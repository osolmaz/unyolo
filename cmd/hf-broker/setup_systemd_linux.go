//go:build linux

package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	bkservice "github.com/osolmaz/brokerkit/service"
)

const (
	hfTokenFileName       = "hf-token"
	telegramTokenFileName = "telegram-bot-token"
	secretsFileName       = "secrets"
	scopeFileName         = "scope.json"
	envFileName           = "env"
	unitFileName          = "hf-broker.service"
	maxHFTokenBytes       = 64 * 1024
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
	opts              setupSystemdOptions
	tokenPath         string
	secretsPath       string
	scopePath         string
	envPath           string
	unitPath          string
	telegramTokenPath string
}

func systemdSetupPlan(opts setupSystemdOptions) systemdPlan {
	return systemdPlan{
		opts:              opts,
		tokenPath:         filepath.Join(opts.ConfigDir, hfTokenFileName),
		secretsPath:       filepath.Join(opts.ConfigDir, secretsFileName),
		scopePath:         filepath.Join(opts.ConfigDir, scopeFileName),
		envPath:           filepath.Join(opts.ConfigDir, envFileName),
		unitPath:          filepath.Join(opts.SystemdDir, unitFileName),
		telegramTokenPath: filepath.Join(opts.ConfigDir, telegramTokenFileName),
	}
}

func brokerkitSystemdInstallPlan(plan systemdPlan) (bkservice.SystemdInstallPlan, error) {
	token, err := readHFTokenFile(plan.opts.HFTokenFile)
	if err != nil {
		return bkservice.SystemdInstallPlan{}, err
	}
	scope, err := renderScopeJSON(plan.opts.Repo, plan.opts.RepoType)
	if err != nil {
		return bkservice.SystemdInstallPlan{}, err
	}
	files := []bkservice.ManagedFile{
		{Area: bkservice.ManagedFileConfig, Name: hfTokenFileName, Data: token, Mode: 0o600, Owner: bkservice.ManagedFileOwnerService},
		{Area: bkservice.ManagedFileConfig, Name: secretsFileName, Data: []byte(plan.opts.ClientName + " = " + plan.opts.SharedSecret + "\n"), Mode: 0o600, Owner: bkservice.ManagedFileOwnerService},
		{Area: bkservice.ManagedFileConfig, Name: scopeFileName, Data: scope, Mode: 0o644, Owner: bkservice.ManagedFileOwnerRoot},
		{Area: bkservice.ManagedFileConfig, Name: envFileName, Data: []byte(renderEnvFile(plan)), Mode: 0o640, Owner: bkservice.ManagedFileOwnerRoot},
	}
	var removeFiles []bkservice.ManagedFileRef
	var readyCheck bkservice.ReadinessCheck
	if plan.opts.TelegramBotTokenFile != "" {
		telegramToken, readErr := readSetupTokenFile(plan.opts.TelegramBotTokenFile, "--telegram-bot-token-file")
		if readErr != nil {
			return bkservice.SystemdInstallPlan{}, readErr
		}
		files = append(files, bkservice.ManagedFile{Area: bkservice.ManagedFileConfig, Name: telegramTokenFileName, Data: telegramToken, Mode: 0o600, Owner: bkservice.ManagedFileOwnerService})
	} else {
		removeFiles = []bkservice.ManagedFileRef{{Area: bkservice.ManagedFileConfig, Name: telegramTokenFileName}}
		readyCheck = bkservice.HTTPReadyCheck(brokerBaseURL(plan.opts.BindAddr, plan.opts.Port)+"/healthz", localReadinessHTTPClient())
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

func localReadinessHTTPClient() *http.Client {
	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.Proxy = nil
	return &http.Client{Transport: transport}
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
	_, err := fmt.Fprintf(stdout, `Would configure hf-broker systemd service:
  user:         %s
  group:        %s
  token file:   %s
  secrets file: %s
  scope file:   %s
  env file:     %s
  state dir:    %s
  unit file:    %s
  broker URL:   %s
`, plan.opts.User, plan.opts.Group, plan.tokenPath, plan.secretsPath, plan.scopePath, plan.envPath, plan.opts.StateDir, plan.unitPath, brokerURL(plan.opts.BindAddr, plan.opts.Port, plan.opts.RepoType, plan.opts.Repo))
	return err
}

func printSystemdSummary(stdout io.Writer, opts setupSystemdOptions) {
	_, _ = fmt.Fprintf(stdout, `hf-broker systemd service configured.

Broker URL:
  %s

Configure a client without exposing its secret:
  sudo hf-broker setup client --client %s --url %s --secret-file %s --home-dir '/home/<user>'
`, brokerURL(opts.BindAddr, opts.Port, opts.RepoType, opts.Repo), shellQuote(opts.ClientName), shellQuote(brokerBaseURL(opts.BindAddr, opts.Port)), shellQuote(filepath.Join(opts.ConfigDir, secretsFileName)))
}

func shellQuote(value string) string {
	return "'" + strings.ReplaceAll(value, "'", "'\\''") + "'"
}
