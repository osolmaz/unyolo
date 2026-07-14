//go:build linux

package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"

	"github.com/osolmaz/brokerkit/brokers/huggingface/internal/policypreset"
	bkservice "github.com/osolmaz/brokerkit/service"
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
	if err := requirePolicyReplacement(plan); err != nil {
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
	policyFiles, err := renderSetupPolicy(plan)
	if err != nil {
		return bkservice.SystemdInstallPlan{}, err
	}
	files := []bkservice.ManagedFile{
		{Area: bkservice.ManagedFileConfig, Name: hfTokenFileName, Data: token, Mode: 0o600, Owner: bkservice.ManagedFileOwnerService},
		{Area: bkservice.ManagedFileConfig, Name: secretsFileName, Data: []byte(plan.opts.ClientName + " = " + plan.opts.SharedSecret + "\n"), Mode: 0o600, Owner: bkservice.ManagedFileOwnerService},
		{Area: bkservice.ManagedFileConfig, Name: operatorSecretsFileName, Data: []byte(plan.opts.OperatorName + " = " + plan.opts.OperatorSecret + "\n"), Mode: 0o600, Owner: bkservice.ManagedFileOwnerService},
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
		files = append(files, bkservice.ManagedFile{Area: bkservice.ManagedFileConfig, Name: telegramTokenFileName, Data: telegramToken, Mode: 0o600, Owner: bkservice.ManagedFileOwnerService})
	} else {
		removeFiles = append(removeFiles, bkservice.ManagedFileRef{Area: bkservice.ManagedFileConfig, Name: telegramTokenFileName})
	}
	if len(removeFiles) > 0 {
		readyCheck = bkservice.HTTPReadyCheck(brokerBaseURL(plan.opts.BindAddr, plan.opts.Port)+"/healthz", bkservice.LocalHTTPClient())
	}
	return bkservice.SystemdInstallPlan{
		User:         plan.opts.User,
		Group:        plan.opts.Group,
		ConfigDir:    plan.opts.ConfigDir,
		StateDir:     plan.opts.StateDir,
		SystemdDir:   plan.opts.SystemdDir,
		UnitName:     unitFileName,
		Files:        files,
		RemoveFiles:  removeFiles,
		ReadyCheck:   readyCheck,
		Unit:         systemdUnit(plan),
		NoStart:      plan.opts.NoStart,
		AllowNonRoot: plan.opts.AllowNonRoot,
		Runner:       plan.opts.CommandRunner,
	}, nil
}

type setupPolicyFiles struct {
	scope         []byte
	profile       []byte
	manifest      []byte
	managedPreset bool
}

func renderSetupPolicy(plan systemdPlan) (setupPolicyFiles, error) {
	if plan.opts.Repo != "" {
		scope, err := renderScopeJSON(plan.opts.Repo, plan.opts.RepoType)
		return setupPolicyFiles{scope: scope}, err
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
	return setupPolicyFiles{
		scope: artifacts.PolicyJSON, profile: artifacts.ProfileJSON,
		manifest: artifacts.ManifestJSON, managedPreset: true,
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
	profile, err := os.ReadFile(plan.policyProfilePath) // #nosec G304 -- fixed file beneath the operator-selected config directory.
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("read installed policy profile: %w", err)
	}
	manifest, err := os.ReadFile(plan.policyManifestPath) // #nosec G304 -- fixed file beneath the operator-selected config directory.
	if err != nil {
		return nil, fmt.Errorf("read installed policy manifest: %w", err)
	}
	scope, err := os.ReadFile(plan.scopePath) // #nosec G304 -- fixed file beneath the operator-selected config directory.
	if err != nil {
		return nil, fmt.Errorf("read installed policy scope: %w", err)
	}
	return &installedSetupPolicy{profile: profile, manifest: manifest, scope: scope}, nil
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
		"HF_BROKER_BIND_ADDR=" + opts.BindAddr + "\n" +
		"HF_BROKER_PORT=" + strconv.Itoa(opts.Port) + "\n"
	body += "HF_BROKER_OPERATOR_SECRETS_FILE=" + plan.operatorSecretsPath + "\n" +
		"HF_BROKER_OPERATOR_BIND_ADDR=" + opts.OperatorBindAddr + "\n" +
		"HF_BROKER_OPERATOR_PORT=" + strconv.Itoa(opts.OperatorPort) + "\n"
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
	policyDescription := "preset " + plan.opts.PolicyPreset
	if plan.opts.Repo != "" {
		policyDescription = "restricted repository " + plan.opts.Repo
	}
	_, err := fmt.Fprintf(stdout, `Would configure hf-broker systemd service:
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
`, plan.opts.User, plan.opts.Group, plan.tokenPath, plan.secretsPath, plan.operatorSecretsPath, plan.scopePath, policyDescription, plan.envPath, plan.opts.StateDir, plan.unitPath, setupBrokerURL(plan.opts))
	return err
}

func printSystemdSummary(stdout io.Writer, opts setupSystemdOptions) {
	policySummary := "Safe reads and inference run directly; mutations and administration require approval; credential-output operations are denied."
	if opts.Repo != "" {
		policySummary = "Only the configured repository policy is installed."
	}
	_, _ = fmt.Fprintf(stdout, `hf-broker systemd service configured.

Broker URL:
  %s

Policy:
  %s

Operator inbox URL:
  %s

Operator credential file:
  %s

Configure a client without exposing its secret:
  sudo hf-broker setup client --client %s --url %s --secret-file %s --home-dir '/home/<user>'
`, setupBrokerURL(opts), policySummary, brokerBaseURL(opts.OperatorBindAddr, opts.OperatorPort), filepath.Join(opts.ConfigDir, operatorSecretsFileName), shellQuote(opts.ClientName), shellQuote(brokerBaseURL(opts.BindAddr, opts.Port)), shellQuote(filepath.Join(opts.ConfigDir, secretsFileName)))
}

func setupBrokerURL(opts setupSystemdOptions) string {
	if opts.Repo == "" {
		return brokerBaseURL(opts.BindAddr, opts.Port)
	}
	return brokerURL(opts.BindAddr, opts.Port, opts.RepoType, opts.Repo)
}

func shellQuote(value string) string {
	return "'" + strings.ReplaceAll(value, "'", "'\\''") + "'"
}
