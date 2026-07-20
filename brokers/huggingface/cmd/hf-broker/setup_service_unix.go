//go:build linux || darwin

package main

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"strconv"
	"strings"

	"github.com/osolmaz/brokerkit/brokers/huggingface/internal/policypreset"
	bkservice "github.com/osolmaz/brokerkit/internal/host/service"
	bksetup "github.com/osolmaz/brokerkit/internal/host/setup"
)

const (
	hfTokenFileName         = "hf-token"
	telegramTokenFileName   = "telegram-bot-token" // #nosec G101 -- this is a filename, not a credential.
	secretsFileName         = "secrets"
	operatorSecretsFileName = "operator-secrets"
	scopeFileName           = "scope.json"
	policyProfileFileName   = "policy-profile.json"
	policyManifestFileName  = "policy-manifest.json"
	envFileName             = "env"
	unitFileName            = "hf-broker.service"
	maxHFTokenBytes         = 64 * 1024
)

func runSetupSystemd(ctx context.Context, stdout io.Writer, opts setupSystemdOptions) error {
	if err := requireRootForSystemd(opts); err != nil {
		return err
	}
	plan := systemdSetupPlan(opts)
	if err := validateSystemdSetupPlan(plan); err != nil {
		return exitError{code: 64, message: err.Error()}
	}
	if opts.DryRun {
		return printSystemdDryRun(stdout, plan)
	}
	if err := checkPolicyReplacement(stdout, plan); err != nil {
		return err
	}
	installPlan, err := brokerkitSystemdInstallPlan(plan)
	if err != nil {
		return exitError{code: 64, message: err.Error()}
	}
	if err := bkservice.InstallSystemd(ctx, installPlan); err != nil {
		return err
	}
	printSystemdSummary(stdout, opts)
	return nil
}

func requireRootForSystemd(opts setupSystemdOptions) error {
	if runtime.GOOS != "linux" {
		return exitError{code: 64, message: "setup systemd is only supported on Linux"}
	}
	if os.Geteuid() == 0 || opts.AllowNonRoot || opts.DryRun {
		return nil
	}
	return exitError{code: 1, message: "setup systemd must run as root; try sudo hf-broker setup systemd ..."}
}

type systemdPlan struct {
	opts                setupSystemdOptions
	tokenPath           string
	secretsPath         string
	scopePath           string
	policyProfilePath   string
	policyManifestPath  string
	envPath             string
	unitPath            string
	telegramTokenPath   string
	operatorSecretsPath string
}

func systemdSetupPlan(opts setupSystemdOptions) systemdPlan {
	return systemdPlan{
		opts:                opts,
		tokenPath:           filepath.Join(opts.ConfigDir, hfTokenFileName),
		secretsPath:         filepath.Join(opts.ConfigDir, secretsFileName),
		scopePath:           filepath.Join(opts.ConfigDir, scopeFileName),
		policyProfilePath:   filepath.Join(opts.ConfigDir, policyProfileFileName),
		policyManifestPath:  filepath.Join(opts.ConfigDir, policyManifestFileName),
		envPath:             filepath.Join(opts.ConfigDir, envFileName),
		unitPath:            filepath.Join(opts.SystemdDir, unitFileName),
		telegramTokenPath:   filepath.Join(opts.ConfigDir, telegramTokenFileName),
		operatorSecretsPath: filepath.Join(opts.ConfigDir, operatorSecretsFileName),
	}
}

func brokerkitSystemdInstallPlan(plan systemdPlan) (bkservice.SystemdInstallPlan, error) {
	token, err := readHFTokenFile(plan.opts.HFTokenFile)
	if err != nil {
		return bkservice.SystemdInstallPlan{}, err
	}
	activation, err := bksetup.BuildSystemdActivation(plan.opts.SystemdOptions, plan.opts.OperatorEndpoint, unitFileName)
	if err != nil {
		return bkservice.SystemdInstallPlan{}, err
	}
	policyFiles, err := renderSetupPolicy(plan)
	if err != nil {
		return bkservice.SystemdInstallPlan{}, err
	}
	files := []bkservice.ManagedFile{
		{Area: bkservice.ManagedFileConfig, Name: hfTokenFileName, Data: token, Mode: 0o600, Owner: bkservice.ManagedFileOwnerService, CredentialClass: "huggingface-access"},
		{Area: bkservice.ManagedFileConfig, Name: secretsFileName, Data: []byte(plan.opts.ClientName + " = " + plan.opts.SharedSecret + "\n"), Mode: 0o600, Owner: bkservice.ManagedFileOwnerService, CredentialClass: "broker-client"},
		{Area: bkservice.ManagedFileConfig, Name: operatorSecretsFileName, Data: []byte(plan.opts.OperatorName + " = " + plan.opts.OperatorSecret + "\n"), Mode: 0o600, Owner: bkservice.ManagedFileOwnerService, CredentialClass: "broker-operator"},
	}
	var removeFiles []bkservice.ManagedFileRef
	if policyFiles.managedPreset {
		files = append(files,
			bkservice.ManagedFile{Area: bkservice.ManagedFileConfig, Name: policyProfileFileName, Data: policyFiles.profile, Mode: 0o644, Owner: bkservice.ManagedFileOwnerRoot},
			bkservice.ManagedFile{Area: bkservice.ManagedFileConfig, Name: policyManifestFileName, Data: policyFiles.manifest, Mode: 0o644, Owner: bkservice.ManagedFileOwnerRoot},
		)
	} else {
		removeFiles = append(removeFiles,
			bkservice.ManagedFileRef{Area: bkservice.ManagedFileConfig, Name: policyProfileFileName},
			bkservice.ManagedFileRef{Area: bkservice.ManagedFileConfig, Name: policyManifestFileName},
		)
	}
	files = append(files,
		bkservice.ManagedFile{Area: bkservice.ManagedFileConfig, Name: scopeFileName, Data: policyFiles.scope, Mode: 0o644, Owner: bkservice.ManagedFileOwnerRoot},
		bkservice.ManagedFile{Area: bkservice.ManagedFileConfig, Name: envFileName, Data: []byte(renderEnvFile(plan)), Mode: 0o640, Owner: bkservice.ManagedFileOwnerRoot},
	)
	var readyCheck bkservice.ReadinessCheck
	if plan.opts.TelegramBotTokenFile != "" {
		telegramToken, readErr := readSetupTokenFile(plan.opts.TelegramBotTokenFile, "--telegram-bot-token-file")
		if readErr != nil {
			return bkservice.SystemdInstallPlan{}, readErr
		}
		files = append(files, bkservice.ManagedFile{Area: bkservice.ManagedFileConfig, Name: telegramTokenFileName, Data: telegramToken, Mode: 0o600, Owner: bkservice.ManagedFileOwnerService, CredentialClass: "telegram-bot"})
	} else {
		removeFiles = append(removeFiles, bkservice.ManagedFileRef{Area: bkservice.ManagedFileConfig, Name: telegramTokenFileName, CredentialClass: "telegram-bot"})
	}
	if len(removeFiles) > 0 {
		readyCheck = bkservice.EndpointReadyCheck(plan.opts.Endpoint, "/healthz")
	}
	return bkservice.SystemdInstallPlan{
		User:             plan.opts.User,
		Group:            plan.opts.Group,
		AdditionalGroups: activation.Groups,
		GroupMembers:     activation.GroupMembers,
		ConfigDir:        plan.opts.ConfigDir,
		StateDir:         plan.opts.StateDir,
		SystemdDir:       plan.opts.SystemdDir,
		UnitName:         unitFileName,
		Files:            files,
		RemoveFiles:      removeFiles,
		ReadyCheck:       readyCheck,
		Unit:             systemdUnit(plan),
		SocketUnits:      activation.Sockets,
		ActivationUnits:  activation.ActivationUnits,
		NoStart:          plan.opts.NoStart,
		AllowNonRoot:     plan.opts.AllowNonRoot,
		Runner:           plan.opts.CommandRunner,
		Lifecycle:        plan.opts.Lifecycle,
	}, nil
}

type setupPolicyFiles struct {
	scope         []byte
	profile       []byte
	manifest      []byte
	counts        *policypreset.OperationCounts
	policyDigest  string
	managedPreset bool
}

func renderSetupPolicy(plan systemdPlan) (setupPolicyFiles, error) {
	if plan.opts.Repo != "" {
		scope, err := renderScopeJSON(plan.opts.Repo, plan.opts.RepoType)
		return setupPolicyFiles{scope: scope, policyDigest: setupPolicyDigest(scope)}, err
	}
	deniedOperations, err := setupDeniedOperations(plan)
	if err != nil {
		return setupPolicyFiles{}, err
	}
	artifacts, err := policypreset.Render(policypreset.Profile{
		Version: policypreset.ProfileVersion, Preset: plan.opts.PolicyPreset,
		Clients: []string{plan.opts.ClientName}, DeniedOperations: deniedOperations,
	})
	if err != nil {
		return setupPolicyFiles{}, err
	}
	counts := artifacts.Manifest.OperationCounts
	return setupPolicyFiles{
		scope: artifacts.PolicyJSON, profile: artifacts.ProfileJSON,
		manifest: artifacts.ManifestJSON, counts: &counts,
		policyDigest: artifacts.Manifest.PolicyDigest, managedPreset: true,
	}, nil
}

func setupDeniedOperations(plan systemdPlan) ([]string, error) {
	if plan.opts.ResetDeniedOperations {
		return slices.Clone(plan.opts.DeniedOperations), nil
	}
	installed, err := installedPolicyArtifacts(plan)
	if err != nil {
		return nil, err
	}
	if installed == nil {
		return slices.Clone(plan.opts.DeniedOperations), nil
	}
	report := policypreset.Check(installed.profile, installed.manifest, installed.scope)
	if report.Status != policypreset.DriftCurrent && report.Status != policypreset.DriftStale {
		return nil, fmt.Errorf("installed policy artifacts are %s; run hf-broker doctor policy or use --reset-denied-operations", report.Status)
	}
	profile, err := policypreset.ParseInstalledProfile(installed.profile)
	if err != nil {
		return nil, fmt.Errorf("parse installed policy profile: %w", err)
	}
	return mergeDeniedOperations(profile.DeniedOperations, plan.opts.DeniedOperations), nil
}

type installedSetupPolicy struct {
	profile  []byte
	manifest []byte
	scope    []byte
}

func installedPolicyArtifacts(plan systemdPlan) (*installedSetupPolicy, error) {
	profile, manifest, found, err := readInstalledPolicyPair(plan)
	if err != nil || !found {
		return nil, err
	}
	scope, err := os.ReadFile(plan.scopePath) // #nosec G304 -- fixed file beneath the operator-selected config directory.
	if err != nil {
		return nil, fmt.Errorf("read installed policy scope: %w", err)
	}
	return &installedSetupPolicy{profile: profile, manifest: manifest, scope: scope}, nil
}

func readInstalledPolicyPair(plan systemdPlan) ([]byte, []byte, bool, error) {
	profile, profileFound, err := readOptionalSetupPolicyArtifact(plan.policyProfilePath, "profile")
	if err != nil {
		return nil, nil, false, err
	}
	manifest, manifestFound, err := readOptionalSetupPolicyArtifact(plan.policyManifestPath, "manifest")
	if err != nil {
		return nil, nil, false, err
	}
	if !profileFound && !manifestFound {
		return nil, nil, false, nil
	}
	if !profileFound || !manifestFound {
		return nil, nil, false, errors.New("installed managed policy artifacts are incomplete; restore both profile and manifest or use --reset-denied-operations")
	}
	return profile, manifest, true, nil
}

func readOptionalSetupPolicyArtifact(path, name string) ([]byte, bool, error) {
	data, err := os.ReadFile(path) // #nosec G304 -- fixed file beneath the operator-selected config directory.
	if errors.Is(err, os.ErrNotExist) {
		return nil, false, nil
	}
	if err != nil {
		return nil, false, fmt.Errorf("read installed policy %s: %w", name, err)
	}
	return data, true, nil
}

func mergeDeniedOperations(installed, requested []string) []string {
	unique := make(map[string]struct{}, len(installed)+len(requested))
	for _, operation := range append(slices.Clone(installed), requested...) {
		unique[operation] = struct{}{}
	}
	merged := make([]string, 0, len(unique))
	for operation := range unique {
		merged = append(merged, operation)
	}
	slices.Sort(merged)
	return merged
}

func requirePolicyReplacement(plan systemdPlan) error {
	_, err := os.Stat(plan.scopePath)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("inspect existing policy: %w", err)
	}
	if !plan.opts.ReplacePolicy {
		return exitError{code: 64, message: "managed policy already exists; inspect it first or rerun with --replace-policy"}
	}
	return nil
}

func checkPolicyReplacement(stdout io.Writer, plan systemdPlan) error {
	_, err := os.Stat(plan.scopePath)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("inspect existing policy: %w", err)
	}
	if err := printPolicyReplacementPreview(stdout, plan); err != nil {
		return exitError{code: 64, message: err.Error()}
	}
	return requirePolicyReplacement(plan)
}

func readHFTokenFile(path string) ([]byte, error) {
	return readSetupTokenFile(path, "--hf-token-file")
}

func readSetupTokenFile(path string, label string) ([]byte, error) {
	file, err := os.Open(path) // #nosec G304 -- operator-supplied setup path.
	if err != nil {
		return nil, fmt.Errorf("read %s: %w", label, err)
	}
	data, readErr := io.ReadAll(io.LimitReader(file, maxHFTokenBytes+1))
	closeErr := file.Close()
	if readErr != nil {
		return nil, fmt.Errorf("read %s: %w", label, readErr)
	}
	if closeErr != nil {
		return nil, fmt.Errorf("close %s: %w", label, closeErr)
	}
	if len(data) > maxHFTokenBytes {
		return nil, fmt.Errorf("%s exceeds %d bytes", label, maxHFTokenBytes)
	}
	if strings.TrimSpace(string(data)) == "" {
		return nil, fmt.Errorf("%s is empty", label)
	}
	return data, nil
}

func renderScopeJSON(repo, repoType string) ([]byte, error) {
	if !validRepo(repo) {
		return nil, fmt.Errorf("--repo must be owner/name")
	}
	owner, name, ok := strings.Cut(repo, "/")
	if !ok || owner == "" || name == "" {
		return nil, fmt.Errorf("--repo must be owner/name")
	}
	body := map[string]any{
		"rules": []map[string]any{
			{
				"id":         "allow-configured-repo",
				"effect":     "allow",
				"clients":    []string{"*"},
				"operations": []string{"repo.contents.read", "git.fetch", "git.push.append"},
				"targets": []map[string]string{{
					"kind":  "repo",
					"type":  repoType,
					"owner": owner,
					"name":  name,
				}},
			},
		},
	}
	data, err := json.MarshalIndent(body, "", "  ")
	if err != nil {
		return nil, err
	}
	return append(data, '\n'), nil
}

func renderEnvFile(plan systemdPlan) string {
	opts := plan.opts
	body := "HF_BROKER_HF_TOKEN_FILE=" + plan.tokenPath + "\n" +
		"HF_BROKER_SECRETS_FILE=" + plan.secretsPath + "\n" +
		"HF_BROKER_SCOPE_FILE=" + plan.scopePath + "\n" +
		"HF_BROKER_STATE_DIR=" + opts.StateDir + "\n" +
		"HF_BROKER_AGENT_ENDPOINT=activation://agent\n"
	if opts.GitEndpoint != "" {
		body += "HF_BROKER_GIT_ENDPOINT=" + opts.GitEndpoint + "\n"
	}
	body += "HF_BROKER_OPERATOR_SECRETS_FILE=" + plan.operatorSecretsPath + "\n" +
		"HF_BROKER_OPERATOR_ENDPOINT=activation://operator\n"
	if opts.TelegramBotTokenFile != "" {
		body += "HF_BROKER_TELEGRAM_BOT_TOKEN_FILE=" + plan.telegramTokenPath + "\n" +
			"HF_BROKER_TELEGRAM_CHAT_ID=" + strconv.FormatInt(opts.TelegramChatID, 10) + "\n"
	}
	return body
}

func systemdUnit(plan systemdPlan) bkservice.SystemdUnit {
	opts := plan.opts
	return bkservice.SystemdUnit{
		Description:     "hf-broker Hugging Face credential broker",
		User:            opts.User,
		Group:           opts.Group,
		EnvironmentFile: plan.envPath,
		ExecStart:       opts.BinaryPath,
		StateDir:        opts.StateDir,
		ConfigDir:       opts.ConfigDir,
		HomeAccess:      bkservice.HomeAccessDeny,
		PathValidation:  setupPathValidation(opts),
	}
}

func renderSystemdUnit(plan systemdPlan) (string, error) {
	return bkservice.RenderSystemd(systemdUnit(plan))
}

func validateSystemdSetupPlan(plan systemdPlan) error {
	unit := systemdUnit(plan)
	unit.PathValidation = bkservice.PathValidationPreview
	_, err := bkservice.RenderSystemd(unit)
	return err
}

func setupPathValidation(opts setupSystemdOptions) bkservice.PathValidation {
	if opts.DryRun || opts.AllowNonRoot {
		return bkservice.PathValidationPreview
	}
	return bkservice.PathValidationStrict
}

func printSystemdDryRun(stdout io.Writer, plan systemdPlan) error {
	activation, err := bksetup.BuildSystemdActivation(plan.opts.SystemdOptions, plan.opts.OperatorEndpoint, unitFileName)
	if err != nil {
		return err
	}
	sockets, err := bkservice.RenderSystemdSockets(activation.Sockets)
	if err != nil {
		return err
	}
	policyDescription := "preset " + plan.opts.PolicyPreset
	if plan.opts.Repo != "" {
		policyDescription = "restricted repository " + plan.opts.Repo
	}
	_, err = fmt.Fprintf(stdout, `Would configure hf-broker systemd service:
  user:         %s
  group:        %s
  token file:   %s
  secrets file: %s
  operator file:%s
  scope file:   %s
  policy:       %s
  env file:     %s
  state dir:    %s
  unit file:    %s
  broker URL:   %s
  agent access: %s (%s)
  operator access: %s (%s)
%s`, plan.opts.User, plan.opts.Group, plan.tokenPath, plan.secretsPath, plan.operatorSecretsPath, plan.scopePath, policyDescription, plan.envPath, plan.opts.StateDir, plan.unitPath, setupBrokerURL(plan.opts), plan.opts.AgentUser, plan.opts.AgentAccessGroup, plan.opts.OperatorUser, plan.opts.OperatorAccessGroup, sockets)
	if err != nil {
		return err
	}
	return printPolicyReplacementPreview(stdout, plan)
}

func printPolicyReplacementPreview(stdout io.Writer, plan systemdPlan) error {
	preview, err := buildPolicyReplacementPreview(plan)
	if err != nil {
		return err
	}
	_, err = fmt.Fprint(stdout, preview)
	return err
}

func buildPolicyReplacementPreview(plan systemdPlan) (string, error) {
	candidate, err := renderSetupPolicy(plan)
	if err != nil {
		return "", err
	}
	currentDigest, currentCounts, err := currentPolicyPreview(plan)
	if err != nil {
		return "", err
	}
	var output strings.Builder
	output.WriteString("\nPolicy replacement preview:\n")
	fmt.Fprintf(&output, "  current digest:   %s\n", currentDigest)
	fmt.Fprintf(&output, "  candidate digest: %s\n", candidate.policyDigest)
	writeOperationCountPreview(&output, currentCounts, candidate.counts)
	return output.String(), nil
}

func currentPolicyPreview(plan systemdPlan) (string, *policypreset.OperationCounts, error) {
	scope, err := os.ReadFile(plan.scopePath) // #nosec G304 -- fixed file beneath the operator-selected config directory.
	if errors.Is(err, os.ErrNotExist) {
		return "(none)", nil, nil
	}
	if err != nil {
		return "", nil, fmt.Errorf("read installed policy scope: %w", err)
	}
	installed, err := installedPolicyArtifacts(plan)
	if err != nil {
		return "", nil, err
	}
	if installed == nil {
		return setupPolicyDigest(scope), nil, nil
	}
	manifest, err := policypreset.ParseManifest(installed.manifest)
	if err != nil {
		return "", nil, fmt.Errorf("parse installed policy manifest: %w", err)
	}
	counts := manifest.OperationCounts
	return setupPolicyDigest(scope), &counts, nil
}

func writeOperationCountPreview(output *strings.Builder, current, candidate *policypreset.OperationCounts) {
	if candidate == nil {
		output.WriteString("  operation counts: custom policy\n")
		return
	}
	if current == nil {
		fmt.Fprintf(output, "  candidate counts: allow=%d request=%d deny=%d total=%d\n",
			candidate.Allow, candidate.Request, candidate.Deny, candidate.Total)
		return
	}
	fmt.Fprintf(output, "  operation counts: allow %d -> %d; request %d -> %d; deny %d -> %d; total %d -> %d\n",
		current.Allow, candidate.Allow, current.Request, candidate.Request,
		current.Deny, candidate.Deny, current.Total, candidate.Total)
}

func setupPolicyDigest(data []byte) string {
	sum := sha256.Sum256(data)
	return fmt.Sprintf("sha256:%x", sum)
}

func printSystemdSummary(stdout io.Writer, opts setupSystemdOptions) {
	policySummary := "Safe reads and inference run directly; mutations and administration require approval; credential-output operations are denied."
	if opts.Repo != "" {
		policySummary = "Only the configured repository policy is installed."
	}
	_, _ = fmt.Fprintf(stdout, `hf-broker systemd service configured.

Broker endpoint:
  %s

Policy:
  %s

Operator inbox endpoint:
  %s

Operator credential file:
  %s

Git endpoint:
  %s

Configure a client without exposing its secret:
  sudo hf-broker setup client --client %s --endpoint %s --git-endpoint %s --secret-file %s --home-dir '/home/<user>'
`, setupBrokerURL(opts), policySummary, opts.OperatorEndpoint, filepath.Join(opts.ConfigDir, operatorSecretsFileName), configuredGitEndpoint(opts.GitEndpoint), shellQuote(opts.ClientName), shellQuote(opts.Endpoint), shellQuote(opts.GitEndpoint), shellQuote(filepath.Join(opts.ConfigDir, secretsFileName)))
}

func configuredGitEndpoint(value string) string {
	if value == "" {
		return "(not configured)"
	}
	return value
}

func setupBrokerURL(opts setupSystemdOptions) string {
	return opts.Endpoint
}

func shellQuote(value string) string {
	return "'" + strings.ReplaceAll(value, "'", "'\\''") + "'"
}
