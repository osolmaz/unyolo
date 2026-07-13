//go:build linux

package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	ghpolicy "github.com/osolmaz/brokerkit/brokers/github/internal/policy"
	bkservice "github.com/osolmaz/brokerkit/service"
)

const (
	githubTokenFileName         = "github-token"
	githubAppIDFileName         = "github-app-id"
	githubAppPrivateKeyFileName = "github-app-private-key.pem"
	githubWebhookSecretFileName = "github-webhook-secret" // #nosec G101 -- this is a config filename, not a secret value.
	ghTelegramTokenFileName     = "telegram-bot-token"    // #nosec G101 -- this is a config filename, not a secret value.
	ghSecretsFileName           = "secrets"
	ghOperatorSecretsFileName   = "operator-secrets"
	ghScopeFileName             = "scope.json"
	ghEnvFileName               = "env"
	ghUnitFileName              = "gh-broker.service"
	maxGitHubSetupFileBytes     = 16 * 1024 * 1024
)

type systemdPlan struct {
	opts                setupSystemdOptions
	tokenPath           string
	appIDPath           string
	appPrivateKeyPath   string
	webhookSecretPath   string
	telegramTokenPath   string
	secretsPath         string
	operatorSecretsPath string
	scopePath           string
	envPath             string
	unitPath            string
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
	installPlan, err := brokerkitSystemdInstallPlan(plan)
	if err != nil {
		return err
	}
	if err := bkservice.InstallSystemd(ctx, installPlan); err != nil {
		return err
	}
	printSystemdSummary(stdout, plan)
	return nil
}

func requireRootForSystemd(opts setupSystemdOptions) error {
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
		webhookSecretPath:   filepath.Join(opts.ConfigDir, githubWebhookSecretFileName),
		telegramTokenPath:   filepath.Join(opts.ConfigDir, ghTelegramTokenFileName),
		secretsPath:         filepath.Join(opts.ConfigDir, ghSecretsFileName),
		operatorSecretsPath: filepath.Join(opts.ConfigDir, ghOperatorSecretsFileName),
		scopePath:           filepath.Join(opts.ConfigDir, ghScopeFileName),
		envPath:             filepath.Join(opts.ConfigDir, ghEnvFileName),
		unitPath:            filepath.Join(opts.SystemdDir, ghUnitFileName),
	}
}

func brokerkitSystemdInstallPlan(plan systemdPlan) (bkservice.SystemdInstallPlan, error) {
	if _, err := ghpolicy.LoadFile(plan.opts.ScopeFile); err != nil {
		return bkservice.SystemdInstallPlan{}, err
	}
	files, err := githubManagedFiles(plan)
	if err != nil {
		return bkservice.SystemdInstallPlan{}, err
	}
	removeFiles := []bkservice.ManagedFileRef(nil)
	var readyCheck bkservice.ReadinessCheck
	if plan.opts.TelegramBotTokenFile == "" {
		removeFiles = append(removeFiles, bkservice.ManagedFileRef{Area: bkservice.ManagedFileConfig, Name: ghTelegramTokenFileName})
		readyCheck = bkservice.HTTPReadyCheck(brokerURL(plan.opts.BindAddr, plan.opts.Port)+"/healthz", bkservice.LocalHTTPClient())
	}
	return bkservice.SystemdInstallPlan{
		User:         plan.opts.User,
		Group:        plan.opts.Group,
		ConfigDir:    plan.opts.ConfigDir,
		StateDir:     plan.opts.StateDir,
		SystemdDir:   plan.opts.SystemdDir,
		UnitName:     ghUnitFileName,
		Files:        files,
		RemoveFiles:  removeFiles,
		ReadyCheck:   readyCheck,
		Unit:         systemdUnit(plan),
		NoStart:      plan.opts.NoStart,
		AllowNonRoot: plan.opts.AllowNonRoot,
		Runner:       plan.opts.CommandRunner,
	}, nil
}

func githubManagedFiles(plan systemdPlan) ([]bkservice.ManagedFile, error) {
	credentials, err := githubCredentialFiles(plan)
	if err != nil {
		return nil, err
	}
	scope, err := readRequiredSetupFile(plan.opts.ScopeFile, "--scope-file")
	if err != nil {
		return nil, err
	}
	files := append(credentials,
		bkservice.ManagedFile{Area: bkservice.ManagedFileConfig, Name: ghSecretsFileName, Data: []byte(plan.opts.ClientName + " = " + plan.opts.SharedSecret + "\n"), Mode: 0o600, Owner: bkservice.ManagedFileOwnerService},
		bkservice.ManagedFile{Area: bkservice.ManagedFileConfig, Name: ghOperatorSecretsFileName, Data: []byte(plan.opts.OperatorID + " = " + plan.opts.OperatorSecret + "\n"), Mode: 0o600, Owner: bkservice.ManagedFileOwnerService},
		bkservice.ManagedFile{Area: bkservice.ManagedFileConfig, Name: ghScopeFileName, Data: scope, Mode: 0o644, Owner: bkservice.ManagedFileOwnerRoot},
		bkservice.ManagedFile{Area: bkservice.ManagedFileConfig, Name: ghEnvFileName, Data: []byte(renderEnvFile(plan)), Mode: 0o640, Owner: bkservice.ManagedFileOwnerRoot},
	)
	if plan.opts.TelegramBotTokenFile != "" {
		token, readErr := readRequiredSetupFile(plan.opts.TelegramBotTokenFile, "--telegram-bot-token-file")
		if readErr != nil {
			return nil, readErr
		}
		files = append(files, bkservice.ManagedFile{Area: bkservice.ManagedFileConfig, Name: ghTelegramTokenFileName, Data: token, Mode: 0o600, Owner: bkservice.ManagedFileOwnerService})
	}
	return files, nil
}

func githubCredentialFiles(plan systemdPlan) ([]bkservice.ManagedFile, error) {
	if plan.opts.DevTokenFallback {
		data, err := readRequiredSetupFile(plan.opts.GitHubTokenFile, "--github-token-file")
		if err != nil {
			return nil, err
		}
		return []bkservice.ManagedFile{{Area: bkservice.ManagedFileConfig, Name: githubTokenFileName, Data: data, Mode: 0o600, Owner: bkservice.ManagedFileOwnerService}}, nil
	}
	return githubAppCredentialFiles(plan)
}

func githubAppCredentialFiles(plan systemdPlan) ([]bkservice.ManagedFile, error) {
	sources := []struct {
		path  string
		label string
		name  string
		mode  os.FileMode
		owner bkservice.ManagedFileOwner
	}{
		{path: plan.opts.GitHubAppIDFile, label: "--github-app-id-file", name: githubAppIDFileName, mode: 0o640, owner: bkservice.ManagedFileOwnerRoot},
		{path: plan.opts.GitHubAppPrivateKeyFile, label: "--github-app-private-key-file", name: githubAppPrivateKeyFileName, mode: 0o600, owner: bkservice.ManagedFileOwnerService},
		{path: plan.opts.GitHubWebhookSecretFile, label: "--github-webhook-secret-file", name: githubWebhookSecretFileName, mode: 0o600, owner: bkservice.ManagedFileOwnerService},
	}
	files := make([]bkservice.ManagedFile, 0, len(sources))
	for _, source := range sources {
		data, err := readRequiredSetupFile(source.path, source.label)
		if err != nil {
			return nil, err
		}
		files = append(files, bkservice.ManagedFile{Area: bkservice.ManagedFileConfig, Name: source.name, Data: data, Mode: source.mode, Owner: source.owner})
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
	body := "GH_BROKER_ENVIRONMENT=local\n" +
		"GH_BROKER_BIND_ADDR=" + opts.BindAddr + "\n" +
		"GH_BROKER_PORT=" + strconv.Itoa(opts.Port) + "\n" +
		"GH_BROKER_CLIENT_ID=" + opts.ClientName + "\n" +
		"GH_BROKER_SECRETS_FILE=" + plan.secretsPath + "\n" +
		"GH_BROKER_SCOPE_FILE=" + plan.scopePath + "\n" +
		"GH_BROKER_STATE_DIR=" + opts.StateDir + "\n" +
		"GH_BROKER_OPERATOR_ID=" + opts.OperatorID + "\n" +
		"GH_BROKER_OPERATOR_SECRETS_FILE=" + plan.operatorSecretsPath + "\n" +
		"GH_BROKER_OPERATOR_BIND_ADDR=" + opts.OperatorBindAddr + "\n" +
		"GH_BROKER_OPERATOR_PORT=" + strconv.Itoa(opts.OperatorPort) + "\n" +
		"GH_BROKER_GITHUB_HTTP_TIMEOUT=30\n" +
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
		"GH_BROKER_GITHUB_WEBHOOK_SECRET_FILE=" + plan.webhookSecretPath + "\n"
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

func setupPathValidation(opts setupSystemdOptions) bkservice.PathValidation {
	if opts.DryRun || opts.AllowNonRoot {
		return bkservice.PathValidationPreview
	}
	return bkservice.PathValidationStrict
}

func printSystemdDryRun(stdout io.Writer, plan systemdPlan) error {
	_, err := fmt.Fprintf(stdout, `Would configure gh-broker systemd service:
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
  broker URL:      %s
`, plan.opts.User, plan.opts.Group, plan.opts.DevTokenFallback, showPath(plan.opts.DevTokenFallback, plan.tokenPath), showPath(!plan.opts.DevTokenFallback, plan.appIDPath), showPath(!plan.opts.DevTokenFallback, plan.appPrivateKeyPath), showPath(!plan.opts.DevTokenFallback, plan.webhookSecretPath), showPath(plan.opts.TelegramBotTokenFile != "", plan.telegramTokenPath), plan.secretsPath, plan.operatorSecretsPath, plan.scopePath, plan.envPath, plan.opts.StateDir, plan.unitPath, brokerURL(plan.opts.BindAddr, plan.opts.Port))
	return err
}

func showPath(enabled bool, path string) string {
	if !enabled {
		return "(not configured)"
	}
	return path
}

func brokerURL(bindAddr string, port int) string {
	host := bindAddr
	if host == "0.0.0.0" || host == "::" {
		host = "127.0.0.1"
	}
	return "http://" + net.JoinHostPort(host, strconv.Itoa(port))
}

func printSystemdSummary(stdout io.Writer, plan systemdPlan) {
	_, _ = fmt.Fprintf(stdout, `gh-broker systemd service configured.

Broker URL:
  %s

Broker client:
  name: %s
  secret file: %s

Operator inbox:
  url: %s
  credential file: %s

Write the client config with:
  gh-broker setup client --client %s --url %s --secret-file %s --home-dir %s
`, brokerURL(plan.opts.BindAddr, plan.opts.Port), plan.opts.ClientName, plan.secretsPath, brokerURL(plan.opts.OperatorBindAddr, plan.opts.OperatorPort), plan.operatorSecretsPath, shellQuote(plan.opts.ClientName), shellQuote(brokerURL(plan.opts.BindAddr, plan.opts.Port)), shellQuote(plan.secretsPath), shellQuote(filepath.Join("/home", plan.opts.ClientName)))
}

func shellQuote(value string) string {
	return "'" + strings.ReplaceAll(value, "'", "'\\''") + "'"
}
