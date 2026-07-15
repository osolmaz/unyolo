//go:build linux || darwin

package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"strconv"
	"strings"

	ghpolicy "github.com/osolmaz/brokerkit/brokers/github/internal/policy"
	"github.com/osolmaz/brokerkit/brokers/github/internal/policypreset"
	sharedpreset "github.com/osolmaz/brokerkit/policypreset"
	bkservice "github.com/osolmaz/brokerkit/service"
	bksetup "github.com/osolmaz/brokerkit/setup"
)

const (
	githubTokenFileName           = "github-token"
	githubAppIDFileName           = "github-app-id"
	githubAppPrivateKeyFileName   = "github-app-private-key.pem"
	githubAppClientIDFileName     = "github-app-client-id"
	githubAppClientSecretFileName = "github-app-client-secret" // #nosec G101 -- config filename.
	githubWebhookSecretFileName   = "github-webhook-secret"    // #nosec G101 -- this is a config filename, not a secret value.
	ghTelegramTokenFileName       = "telegram-bot-token"       // #nosec G101 -- this is a config filename, not a secret value.
	ghSecretsFileName             = "secrets"
	ghOperatorSecretsFileName     = "operator-secrets"
	ghScopeFileName               = "scope.json"
	ghPolicyProfileFileName       = "policy-profile.json"
	ghPolicyManifestFileName      = "policy-manifest.json"
	ghEnvFileName                 = "env"
	ghUnitFileName                = "gh-broker.service"
	maxGitHubSetupFileBytes       = 16 * 1024 * 1024
)

type systemdPlan struct {
	opts                setupSystemdOptions
	tokenPath           string
	appIDPath           string
	appPrivateKeyPath   string
	appClientIDPath     string
	appClientSecretPath string
	webhookSecretPath   string
	telegramTokenPath   string
	secretsPath         string
	operatorSecretsPath string
	scopePath           string
	policyProfilePath   string
	policyManifestPath  string
	envPath             string
	unitPath            string
}

type githubCredentialSource struct {
	path  string
	label string
	name  string
	mode  os.FileMode
	owner bkservice.ManagedFileOwner
	class string
}

func runSetupSystemd(ctx context.Context, stdout io.Writer, opts setupSystemdOptions) error {
	if err := requireRootForSystemd(opts); err != nil {
		return err
	}
	plan := systemdSetupPlan(opts)
	if err := validateSystemdSetupPlan(plan); err != nil {
		return err
	}
	if opts.DryRun {
		return printSystemdDryRun(stdout, plan)
	}
	installPlan, err := replacementCheckedSystemdInstallPlan(stdout, plan)
	if err != nil {
		return err
	}
	if err := bkservice.InstallSystemd(ctx, installPlan); err != nil {
		return err
	}
	printSystemdSummary(stdout, plan)
	return nil
}

func replacementCheckedSystemdInstallPlan(stdout io.Writer, plan systemdPlan) (bkservice.SystemdInstallPlan, error) {
	if err := checkGitHubPolicyReplacement(stdout, plan); err != nil {
		return bkservice.SystemdInstallPlan{}, err
	}
	return brokerkitSystemdInstallPlan(plan)
}

func requireRootForSystemd(opts setupSystemdOptions) error {
	if runtime.GOOS != "linux" {
		return errors.New("setup systemd is only supported on Linux")
	}
	if os.Geteuid() == 0 || opts.AllowNonRoot || opts.DryRun {
		return nil
	}
	return errors.New("setup systemd must run as root; try sudo gh-broker setup systemd")
}

func systemdSetupPlan(opts setupSystemdOptions) systemdPlan {
	return systemdPlan{
		opts:                opts,
		tokenPath:           filepath.Join(opts.ConfigDir, githubTokenFileName),
		appIDPath:           filepath.Join(opts.ConfigDir, githubAppIDFileName),
		appPrivateKeyPath:   filepath.Join(opts.ConfigDir, githubAppPrivateKeyFileName),
		appClientIDPath:     filepath.Join(opts.ConfigDir, githubAppClientIDFileName),
		appClientSecretPath: filepath.Join(opts.ConfigDir, githubAppClientSecretFileName),
		webhookSecretPath:   filepath.Join(opts.ConfigDir, githubWebhookSecretFileName),
		telegramTokenPath:   filepath.Join(opts.ConfigDir, ghTelegramTokenFileName),
		secretsPath:         filepath.Join(opts.ConfigDir, ghSecretsFileName),
		operatorSecretsPath: filepath.Join(opts.ConfigDir, ghOperatorSecretsFileName),
		scopePath:           filepath.Join(opts.ConfigDir, ghScopeFileName),
		policyProfilePath:   filepath.Join(opts.ConfigDir, ghPolicyProfileFileName),
		policyManifestPath:  filepath.Join(opts.ConfigDir, ghPolicyManifestFileName),
		envPath:             filepath.Join(opts.ConfigDir, ghEnvFileName),
		unitPath:            filepath.Join(opts.SystemdDir, ghUnitFileName),
	}
}

func brokerkitSystemdInstallPlan(plan systemdPlan) (bkservice.SystemdInstallPlan, error) {
	files, err := githubManagedFiles(plan)
	if err != nil {
		return bkservice.SystemdInstallPlan{}, err
	}
	activation, err := bksetup.BuildSystemdActivation(plan.opts.SystemdOptions, plan.opts.OperatorEndpoint, ghUnitFileName)
	if err != nil {
		return bkservice.SystemdInstallPlan{}, err
	}
	removeFiles := githubRetiredManagedFiles(plan)
	readyCheck := githubInstallReadyCheck(plan)
	return bkservice.SystemdInstallPlan{
		User:             plan.opts.User,
		Group:            plan.opts.Group,
		AdditionalGroups: activation.Groups,
		GroupMembers:     activation.GroupMembers,
		ConfigDir:        plan.opts.ConfigDir,
		StateDir:         plan.opts.StateDir,
		SystemdDir:       plan.opts.SystemdDir,
		UnitName:         ghUnitFileName,
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

func githubRetiredManagedFiles(plan systemdPlan) []bkservice.ManagedFileRef {
	removeFiles := retiredPolicyFiles(plan)
	removeFiles = append(removeFiles, retiredCredentialFiles(plan)...)
	if plan.opts.TelegramBotTokenFile == "" {
		removeFiles = append(removeFiles, bkservice.ManagedFileRef{Area: bkservice.ManagedFileConfig, Name: ghTelegramTokenFileName, CredentialClass: "telegram-bot"})
	}
	return removeFiles
}

func retiredPolicyFiles(plan systemdPlan) []bkservice.ManagedFileRef {
	if plan.opts.ScopeFile == "" {
		return nil
	}
	return []bkservice.ManagedFileRef{
		{Area: bkservice.ManagedFileConfig, Name: ghPolicyProfileFileName},
		{Area: bkservice.ManagedFileConfig, Name: ghPolicyManifestFileName},
	}
}

func retiredCredentialFiles(plan systemdPlan) []bkservice.ManagedFileRef {
	if plan.opts.DevTokenFallback {
		return []bkservice.ManagedFileRef{
			{Area: bkservice.ManagedFileConfig, Name: githubAppIDFileName},
			{Area: bkservice.ManagedFileConfig, Name: githubAppPrivateKeyFileName, CredentialClass: "github-app-private-key"},
			{Area: bkservice.ManagedFileConfig, Name: githubAppClientIDFileName},
			{Area: bkservice.ManagedFileConfig, Name: githubAppClientSecretFileName, CredentialClass: "github-app-client-secret"},
			{Area: bkservice.ManagedFileConfig, Name: githubWebhookSecretFileName, CredentialClass: "github-webhook"},
		}
	}
	removeFiles := []bkservice.ManagedFileRef{{Area: bkservice.ManagedFileConfig, Name: githubTokenFileName, CredentialClass: "github-development"}}
	if plan.opts.GitHubAppClientIDFile == "" {
		removeFiles = append(removeFiles,
			bkservice.ManagedFileRef{Area: bkservice.ManagedFileConfig, Name: githubAppClientIDFileName},
			bkservice.ManagedFileRef{Area: bkservice.ManagedFileConfig, Name: githubAppClientSecretFileName, CredentialClass: "github-app-client-secret"},
		)
	}
	return removeFiles
}

func githubInstallReadyCheck(plan systemdPlan) bkservice.ReadinessCheck {
	if plan.opts.TelegramBotTokenFile != "" {
		return nil
	}
	return bkservice.EndpointReadyCheck(plan.opts.Endpoint, "/healthz")
}

func githubManagedFiles(plan systemdPlan) ([]bkservice.ManagedFile, error) {
	credentials, err := githubCredentialFiles(plan)
	if err != nil {
		return nil, err
	}
	policyFiles, err := renderGitHubSetupPolicy(plan)
	if err != nil {
		return nil, err
	}
	files := append(credentials,
		bkservice.ManagedFile{Area: bkservice.ManagedFileConfig, Name: ghSecretsFileName, Data: []byte(plan.opts.ClientName + " = " + plan.opts.SharedSecret + "\n"), Mode: 0o600, Owner: bkservice.ManagedFileOwnerService, CredentialClass: "broker-client"},
		bkservice.ManagedFile{Area: bkservice.ManagedFileConfig, Name: ghOperatorSecretsFileName, Data: []byte(plan.opts.OperatorID + " = " + plan.opts.OperatorSecret + "\n"), Mode: 0o600, Owner: bkservice.ManagedFileOwnerService, CredentialClass: "broker-operator"},
		bkservice.ManagedFile{Area: bkservice.ManagedFileConfig, Name: ghScopeFileName, Data: policyFiles.scope, Mode: 0o644, Owner: bkservice.ManagedFileOwnerRoot},
		bkservice.ManagedFile{Area: bkservice.ManagedFileConfig, Name: ghEnvFileName, Data: []byte(renderEnvFile(plan)), Mode: 0o640, Owner: bkservice.ManagedFileOwnerRoot},
	)
	if policyFiles.managedPreset {
		files = append(files,
			bkservice.ManagedFile{Area: bkservice.ManagedFileConfig, Name: ghPolicyProfileFileName, Data: policyFiles.profile, Mode: 0o644, Owner: bkservice.ManagedFileOwnerRoot},
			bkservice.ManagedFile{Area: bkservice.ManagedFileConfig, Name: ghPolicyManifestFileName, Data: policyFiles.manifest, Mode: 0o644, Owner: bkservice.ManagedFileOwnerRoot},
		)
	}
	files, err = appendTelegramCredentialFile(files, plan)
	return files, nil
}

func appendTelegramCredentialFile(files []bkservice.ManagedFile, plan systemdPlan) ([]bkservice.ManagedFile, error) {
	if plan.opts.TelegramBotTokenFile == "" {
		return files, nil
	}
	token, err := readRequiredSetupFile(plan.opts.TelegramBotTokenFile, "--telegram-bot-token-file")
	if err != nil {
		return nil, err
	}
	return append(files, bkservice.ManagedFile{Area: bkservice.ManagedFileConfig, Name: ghTelegramTokenFileName, Data: token, Mode: 0o600, Owner: bkservice.ManagedFileOwnerService, CredentialClass: "telegram-bot"}), nil
}

type githubSetupPolicyFiles struct {
	scope         []byte
	profile       []byte
	manifest      []byte
	counts        *policypreset.OperationCounts
	policyDigest  string
	managedPreset bool
}

func renderGitHubSetupPolicy(plan systemdPlan) (githubSetupPolicyFiles, error) {
	if plan.opts.ScopeFile != "" {
		scope, err := readRequiredSetupFile(plan.opts.ScopeFile, "--scope-file")
		if err != nil {
			return githubSetupPolicyFiles{}, err
		}
		if _, err := ghpolicy.Parse(scope); err != nil {
			return githubSetupPolicyFiles{}, err
		}
		return githubSetupPolicyFiles{scope: scope, policyDigest: sharedpreset.Digest(scope)}, nil
	}
	denied, err := githubSetupDeniedOperations(plan)
	if err != nil {
		return githubSetupPolicyFiles{}, err
	}
	artifacts, err := policypreset.Render(policypreset.Profile{
		Version: policypreset.ProfileVersion, Preset: plan.opts.PolicyPreset,
		Clients: []string{plan.opts.ClientName}, DeniedOperations: denied,
	})
	if err != nil {
		return githubSetupPolicyFiles{}, err
	}
	counts := artifacts.Manifest.OperationCounts
	return githubSetupPolicyFiles{
		scope: artifacts.PolicyJSON, profile: artifacts.ProfileJSON, manifest: artifacts.ManifestJSON,
		counts: &counts, policyDigest: artifacts.Manifest.PolicyDigest, managedPreset: true,
	}, nil
}

func githubSetupDeniedOperations(plan systemdPlan) ([]string, error) {
	if plan.opts.ResetDeniedOperations {
		return slices.Clone(plan.opts.DeniedOperations), nil
	}
	installed, err := installedGitHubPolicyArtifacts(plan)
	if err != nil {
		return nil, err
	}
	if installed == nil {
		return slices.Clone(plan.opts.DeniedOperations), nil
	}
	return mergeInstalledGitHubDeniedOperations(installed, plan.opts.DeniedOperations)
}

func mergeInstalledGitHubDeniedOperations(installed *installedGitHubPolicy, requested []string) ([]string, error) {
	report := policypreset.Check(installed.profile, installed.manifest, installed.scope)
	if err := validateInstalledPolicyStatus(report.Status); err != nil {
		return nil, err
	}
	profile, err := policypreset.ParseInstalledProfile(installed.profile)
	if err != nil {
		return nil, fmt.Errorf("parse installed policy profile: %w", err)
	}
	return mergeGitHubDeniedOperations(profile.DeniedOperations, requested), nil
}

func validateInstalledPolicyStatus(status policypreset.DriftStatus) error {
	if status == policypreset.DriftCurrent || status == policypreset.DriftStale {
		return nil
	}
	return fmt.Errorf("installed policy artifacts are %s; run gh-broker doctor policy or use --reset-denied-operations", status)
}

type installedGitHubPolicy struct {
	profile  []byte
	manifest []byte
	scope    []byte
}

func installedGitHubPolicyArtifacts(plan systemdPlan) (*installedGitHubPolicy, error) {
	profile, profileFound, err := readOptionalGitHubPolicyArtifact(plan.policyProfilePath, "profile")
	if err != nil {
		return nil, err
	}
	manifest, manifestFound, err := readOptionalGitHubPolicyArtifact(plan.policyManifestPath, "manifest")
	if err != nil {
		return nil, err
	}
	if !profileFound && !manifestFound {
		return nil, nil
	}
	if err := validateInstalledPolicyArtifactPair(profileFound, manifestFound); err != nil {
		return nil, err
	}
	scope, err := os.ReadFile(plan.scopePath) // #nosec G304 -- fixed file beneath the selected config directory.
	if err != nil {
		return nil, fmt.Errorf("read installed policy scope: %w", err)
	}
	return &installedGitHubPolicy{profile: profile, manifest: manifest, scope: scope}, nil
}

func validateInstalledPolicyArtifactPair(profileFound, manifestFound bool) error {
	if profileFound && manifestFound {
		return nil
	}
	return errors.New("installed managed policy artifacts are incomplete; restore both profile and manifest or use --reset-denied-operations")
}

func readOptionalGitHubPolicyArtifact(path, name string) ([]byte, bool, error) {
	data, err := os.ReadFile(path) // #nosec G304 -- fixed file beneath the selected config directory.
	if errors.Is(err, os.ErrNotExist) {
		return nil, false, nil
	}
	if err != nil {
		return nil, false, fmt.Errorf("read installed policy %s: %w", name, err)
	}
	return data, true, nil
}

func mergeGitHubDeniedOperations(installed, requested []string) []string {
	values := append(slices.Clone(installed), requested...)
	slices.Sort(values)
	return slices.Compact(values)
}

func githubCredentialFiles(plan systemdPlan) ([]bkservice.ManagedFile, error) {
	if plan.opts.DevTokenFallback {
		data, err := readRequiredSetupFile(plan.opts.GitHubTokenFile, "--github-token-file")
		if err != nil {
			return nil, err
		}
		return []bkservice.ManagedFile{{Area: bkservice.ManagedFileConfig, Name: githubTokenFileName, Data: data, Mode: 0o600, Owner: bkservice.ManagedFileOwnerService, CredentialClass: "github-development"}}, nil
	}
	return githubAppCredentialFiles(plan)
}

func githubAppCredentialFiles(plan systemdPlan) ([]bkservice.ManagedFile, error) {
	sources := []githubCredentialSource{
		{path: plan.opts.GitHubAppIDFile, label: "--github-app-id-file", name: githubAppIDFileName, mode: 0o640, owner: bkservice.ManagedFileOwnerRoot},
		{path: plan.opts.GitHubAppPrivateKeyFile, label: "--github-app-private-key-file", name: githubAppPrivateKeyFileName, mode: 0o600, owner: bkservice.ManagedFileOwnerService, class: "github-app-private-key"},
		{path: plan.opts.GitHubWebhookSecretFile, label: "--github-webhook-secret-file", name: githubWebhookSecretFileName, mode: 0o600, owner: bkservice.ManagedFileOwnerService, class: "github-webhook"},
	}
	if plan.opts.GitHubAppClientIDFile != "" {
		sources = append(sources,
			githubCredentialSource{path: plan.opts.GitHubAppClientIDFile, label: "--github-app-client-id-file", name: githubAppClientIDFileName, mode: 0o640, owner: bkservice.ManagedFileOwnerRoot},
			githubCredentialSource{path: plan.opts.GitHubAppClientSecretFile, label: "--github-app-client-secret-file", name: githubAppClientSecretFileName, mode: 0o600, owner: bkservice.ManagedFileOwnerService, class: "github-app-client-secret"},
		)
	}
	files := make([]bkservice.ManagedFile, 0, len(sources))
	for _, source := range sources {
		data, err := readRequiredSetupFile(source.path, source.label)
		if err != nil {
			return nil, err
		}
		files = append(files, bkservice.ManagedFile{Area: bkservice.ManagedFileConfig, Name: source.name, Data: data, Mode: source.mode, Owner: source.owner, CredentialClass: source.class})
	}
	return files, nil
}

func readRequiredSetupFile(path string, label string) ([]byte, error) {
	file, err := os.Open(path) // #nosec G304 -- operator-supplied setup path.
	if err != nil {
		return nil, fmt.Errorf("read %s: %w", label, err)
	}
	data, readErr := io.ReadAll(io.LimitReader(file, maxGitHubSetupFileBytes+1))
	closeErr := file.Close()
	if readErr != nil {
		return nil, fmt.Errorf("read %s: %w", label, readErr)
	}
	if closeErr != nil {
		return nil, fmt.Errorf("close %s: %w", label, closeErr)
	}
	if len(data) > maxGitHubSetupFileBytes {
		return nil, fmt.Errorf("%s exceeds %d bytes", label, maxGitHubSetupFileBytes)
	}
	if len(data) == 0 {
		return nil, fmt.Errorf("%s is empty", label)
	}
	return data, nil
}

func renderEnvFile(plan systemdPlan) string {
	opts := plan.opts
	body := "GH_BROKER_DEVELOPMENT=false\n" +
		"GH_BROKER_AGENT_ENDPOINT=activation://agent\n" +
		"GH_BROKER_CLIENT_ID=" + opts.ClientName + "\n" +
		"GH_BROKER_SECRETS_FILE=" + plan.secretsPath + "\n" +
		"GH_BROKER_SCOPE_FILE=" + plan.scopePath + "\n" +
		"GH_BROKER_STATE_DIR=" + opts.StateDir + "\n" +
		"GH_BROKER_OPERATOR_ID=" + opts.OperatorID + "\n" +
		"GH_BROKER_OPERATOR_SECRETS_FILE=" + plan.operatorSecretsPath + "\n" +
		"GH_BROKER_OPERATOR_ENDPOINT=activation://operator\n" +
		"GH_BROKER_GITHUB_HTTP_TIMEOUT=30\n" +
		"GH_BROKER_GITHUB_STREAM_TIMEOUT=600\n" +
		"GH_BROKER_MAX_RECEIVE_PACK_BYTES=26214400\n"
	if opts.TelegramBotTokenFile != "" {
		body += "GH_BROKER_TELEGRAM_BOT_TOKEN_FILE=" + plan.telegramTokenPath + "\n" +
			"GH_BROKER_TELEGRAM_CHAT_ID=" + strconv.FormatInt(opts.TelegramChatID, 10) + "\n"
	}
	if opts.DevTokenFallback {
		return body + "GH_BROKER_GITHUB_TOKEN_FILE=" + plan.tokenPath + "\n"
	}
	return body +
		"GH_BROKER_GITHUB_APP_ID_FILE=" + plan.appIDPath + "\n" +
		"GH_BROKER_GITHUB_APP_PRIVATE_KEY_FILE=" + plan.appPrivateKeyPath + "\n" +
		optionalAppClientEnv(plan) +
		"GH_BROKER_GITHUB_WEBHOOK_SECRET_FILE=" + plan.webhookSecretPath + "\n"
}

func optionalAppClientEnv(plan systemdPlan) string {
	if plan.opts.GitHubAppClientIDFile == "" {
		return ""
	}
	return "GH_BROKER_GITHUB_USER_ID=" + strconv.FormatInt(plan.opts.GitHubUserID, 10) + "\n" +
		"GH_BROKER_GITHUB_APP_CLIENT_ID_FILE=" + plan.appClientIDPath + "\n" +
		"GH_BROKER_GITHUB_APP_CLIENT_SECRET_FILE=" + plan.appClientSecretPath + "\n"
}

func systemdUnit(plan systemdPlan) bkservice.SystemdUnit {
	return bkservice.SystemdUnit{
		Description:     "gh-broker GitHub credential broker",
		User:            plan.opts.User,
		Group:           plan.opts.Group,
		EnvironmentFile: plan.envPath,
		ExecStart:       plan.opts.BinaryPath,
		StateDir:        plan.opts.StateDir,
		ConfigDir:       plan.opts.ConfigDir,
		HomeAccess:      bkservice.HomeAccessDeny,
		PathValidation:  setupPathValidation(plan.opts),
	}
}

func validateSystemdSetupPlan(plan systemdPlan) error {
	unit := systemdUnit(plan)
	unit.PathValidation = bkservice.PathValidationPreview
	_, err := bkservice.RenderSystemd(unit)
	return err
}

func checkGitHubPolicyReplacement(stdout io.Writer, plan systemdPlan) error {
	exists, err := installedPolicyExists(plan.scopePath)
	if err != nil {
		return err
	}
	if !exists {
		return nil
	}
	if err := printGitHubPolicyReplacementPreview(stdout, plan); err != nil {
		return err
	}
	if !plan.opts.ReplacePolicy {
		return errors.New("managed policy already exists; inspect it first or rerun with --replace-policy")
	}
	return nil
}

func installedPolicyExists(path string) (bool, error) {
	_, err := os.Stat(path)
	if errors.Is(err, os.ErrNotExist) {
		return false, nil
	}
	if err != nil {
		return false, fmt.Errorf("inspect existing policy: %w", err)
	}
	return true, nil
}

func printGitHubPolicyReplacementPreview(stdout io.Writer, plan systemdPlan) error {
	candidate, err := renderGitHubSetupPolicy(plan)
	if err != nil {
		return err
	}
	currentDigest, currentCounts, err := currentGitHubPolicyPreview(plan)
	if err != nil {
		return err
	}
	if _, err := fmt.Fprintf(stdout, "\nPolicy replacement preview:\n  current digest:   %s\n  candidate digest: %s\n", currentDigest, candidate.policyDigest); err != nil {
		return err
	}
	return writeGitHubOperationCountPreview(stdout, currentCounts, candidate.counts)
}

func currentGitHubPolicyPreview(plan systemdPlan) (string, *policypreset.OperationCounts, error) {
	scope, found, err := readCurrentGitHubScope(plan.scopePath)
	if err != nil || !found {
		return scopeDigestResult(scope, nil, found, err)
	}
	counts, err := currentGitHubPolicyCounts(plan)
	return scopeDigestResult(scope, counts, true, err)
}

func readCurrentGitHubScope(path string) ([]byte, bool, error) {
	scope, err := os.ReadFile(path) // #nosec G304 -- fixed file beneath the selected config directory.
	if errors.Is(err, os.ErrNotExist) {
		return nil, false, nil
	}
	if err != nil {
		return nil, false, fmt.Errorf("read installed policy scope: %w", err)
	}
	return scope, true, nil
}

func currentGitHubPolicyCounts(plan systemdPlan) (*policypreset.OperationCounts, error) {
	installed, err := installedGitHubPolicyArtifacts(plan)
	if err != nil || installed == nil {
		return nil, err
	}
	manifest, err := policypreset.ParseManifest(installed.manifest)
	if err != nil {
		return nil, fmt.Errorf("parse installed policy manifest: %w", err)
	}
	counts := manifest.OperationCounts
	return &counts, nil
}

func scopeDigestResult(scope []byte, counts *policypreset.OperationCounts, found bool, err error) (string, *policypreset.OperationCounts, error) {
	if err != nil {
		return "", nil, err
	}
	if !found {
		return "(none)", nil, nil
	}
	return sharedpreset.Digest(scope), counts, nil
}

func writeGitHubOperationCountPreview(stdout io.Writer, current, candidate *policypreset.OperationCounts) error {
	if candidate == nil {
		_, err := fmt.Fprintln(stdout, "  operation counts: custom policy")
		return err
	}
	if current == nil {
		_, err := fmt.Fprintf(stdout, "  candidate counts: allow=%d request=%d deny=%d total=%d\n", candidate.Allow, candidate.Request, candidate.Deny, candidate.Total)
		return err
	}
	_, err := fmt.Fprintf(stdout, "  operation counts: allow %d -> %d; request %d -> %d; deny %d -> %d; total %d -> %d\n",
		current.Allow, candidate.Allow, current.Request, candidate.Request, current.Deny, candidate.Deny, current.Total, candidate.Total)
	return err
}

func setupPathValidation(opts setupSystemdOptions) bkservice.PathValidation {
	if opts.DryRun || opts.AllowNonRoot {
		return bkservice.PathValidationPreview
	}
	return bkservice.PathValidationStrict
}

func printSystemdDryRun(stdout io.Writer, plan systemdPlan) error {
	activation, err := bksetup.BuildSystemdActivation(plan.opts.SystemdOptions, plan.opts.OperatorEndpoint, ghUnitFileName)
	if err != nil {
		return err
	}
	sockets, err := bkservice.RenderSystemdSockets(activation.Sockets)
	if err != nil {
		return err
	}
	_, err = fmt.Fprintf(stdout, `Would configure gh-broker systemd service:
  user:            %s
  group:           %s
  token fallback:  %t
  github token:    %s
  app id file:     %s
  app private key: %s
  webhook secret:  %s
  telegram token:  %s
  secrets file:    %s
  operator file:   %s
  scope file:      %s
  env file:        %s
  state dir:       %s
  unit file:       %s
  broker endpoint: %s
  agent access:    %s (%s)
  operator access: %s (%s)
%s`, plan.opts.User, plan.opts.Group, plan.opts.DevTokenFallback, showPath(plan.opts.DevTokenFallback, plan.tokenPath), showPath(!plan.opts.DevTokenFallback, plan.appIDPath), showPath(!plan.opts.DevTokenFallback, plan.appPrivateKeyPath), showPath(!plan.opts.DevTokenFallback, plan.webhookSecretPath), showPath(plan.opts.TelegramBotTokenFile != "", plan.telegramTokenPath), plan.secretsPath, plan.operatorSecretsPath, plan.scopePath, plan.envPath, plan.opts.StateDir, plan.unitPath, plan.opts.Endpoint, plan.opts.AgentUser, plan.opts.AgentAccessGroup, plan.opts.OperatorUser, plan.opts.OperatorAccessGroup, sockets)
	if err != nil {
		return err
	}
	return printGitHubPolicyReplacementPreview(stdout, plan)
}

func showPath(enabled bool, path string) string {
	if !enabled {
		return "(not configured)"
	}
	return path
}

func printSystemdSummary(stdout io.Writer, plan systemdPlan) {
	_, _ = fmt.Fprintf(stdout, `gh-broker systemd service configured.

Broker endpoint:
  %s

Broker client:
  name: %s
  secret file: %s

Operator inbox:
  endpoint: %s
  credential file: %s

Write the client config with:
  gh-broker setup client --client %s --endpoint %s --secret-file %s --home-dir %s
`, plan.opts.Endpoint, plan.opts.ClientName, plan.secretsPath, plan.opts.OperatorEndpoint, plan.operatorSecretsPath, shellQuote(plan.opts.ClientName), shellQuote(plan.opts.Endpoint), shellQuote(plan.secretsPath), shellQuote(filepath.Join("/home", plan.opts.ClientName)))
}

func shellQuote(value string) string {
	return "'" + strings.ReplaceAll(value, "'", "'\\''") + "'"
}
