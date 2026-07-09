//go:build linux

package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/user"
	"path/filepath"
	"strconv"
)

const (
	githubTokenFileName         = "github-token"
	githubAppIDFileName         = "github-app-id"
	githubAppPrivateKeyFileName = "github-app-private-key.pem"
	githubWebhookSecretFileName = "github-webhook-secret" // #nosec G101 -- this is a config filename, not a secret value.
	ghSecretsFileName           = "secrets"
	ghScopeFileName             = "scope.json"
	ghEnvFileName               = "env"
	ghUnitFileName              = "gh-broker.service"
)

type systemdPlan struct {
	opts                    setupSystemdOptions
	tokenPath               string
	appIDPath               string
	appPrivateKeyPath       string
	webhookSecretPath       string
	secretsPath             string
	scopePath               string
	envPath                 string
	unitPath                string
	productionAppConfigured bool
}

func runSetupSystemd(ctx context.Context, stdout io.Writer, opts setupSystemdOptions) error {
	if err := requireRootForSystemd(opts); err != nil {
		return err
	}
	plan := systemdSetupPlan(opts)
	if opts.DryRun {
		return printSystemdDryRun(stdout, plan)
	}
	if err := ensureServiceAccount(ctx, opts); err != nil {
		return err
	}
	if err := writeSystemdSetupFiles(plan); err != nil {
		return err
	}
	if err := startSystemdService(ctx, opts); err != nil {
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
		opts:                    opts,
		tokenPath:               filepath.Join(opts.ConfigDir, githubTokenFileName),
		appIDPath:               filepath.Join(opts.ConfigDir, githubAppIDFileName),
		appPrivateKeyPath:       filepath.Join(opts.ConfigDir, githubAppPrivateKeyFileName),
		webhookSecretPath:       filepath.Join(opts.ConfigDir, githubWebhookSecretFileName),
		secretsPath:             filepath.Join(opts.ConfigDir, ghSecretsFileName),
		scopePath:               filepath.Join(opts.ConfigDir, ghScopeFileName),
		envPath:                 filepath.Join(opts.ConfigDir, ghEnvFileName),
		unitPath:                filepath.Join(opts.SystemdDir, ghUnitFileName),
		productionAppConfigured: !opts.DevTokenFallback,
	}
}

func ensureServiceAccount(ctx context.Context, opts setupSystemdOptions) error {
	if err := ensureServiceGroup(ctx, opts); err != nil {
		return err
	}
	return ensureServiceUser(ctx, opts)
}

func ensureServiceGroup(ctx context.Context, opts setupSystemdOptions) error {
	if opts.CommandRunner.Run(ctx, "getent", "group", opts.Group) == nil {
		return nil
	}
	if err := opts.CommandRunner.Run(ctx, "groupadd", "--system", opts.Group); err != nil {
		return fmt.Errorf("create group %q: %w", opts.Group, err)
	}
	return nil
}

func ensureServiceUser(ctx context.Context, opts setupSystemdOptions) error {
	if opts.CommandRunner.Run(ctx, "id", "-u", opts.User) == nil {
		return nil
	}
	if err := opts.CommandRunner.Run(ctx, "useradd", "--system", "--gid", opts.Group, "--home-dir", opts.StateDir, "--shell", "/usr/sbin/nologin", opts.User); err != nil {
		return fmt.Errorf("create user %q: %w", opts.User, err)
	}
	return nil
}

func writeSystemdSetupFiles(plan systemdPlan) error {
	opts := plan.opts
	uid, gid, err := serviceIDs(opts.User, opts.Group)
	if err != nil {
		return err
	}
	if err := writeSystemdPayloads(plan); err != nil {
		return err
	}
	return chownSystemdFiles(plan, configOwnerUID(opts), uid, gid)
}

func configOwnerUID(opts setupSystemdOptions) int {
	if opts.AllowNonRoot {
		return os.Getuid()
	}
	return 0
}

func writeSystemdPayloads(plan systemdPlan) error {
	if err := createSystemdDirs(plan); err != nil {
		return err
	}
	if err := writeCredentialFiles(plan); err != nil {
		return err
	}
	return writeBrokerConfigFiles(plan)
}

func writeCredentialFiles(plan systemdPlan) error {
	if plan.opts.DevTokenFallback {
		return copyRequiredFile(plan.opts.GitHubTokenFile, plan.tokenPath, 0o600, "--github-token-file")
	}
	return writeGitHubAppCredentialFiles(plan)
}

func writeGitHubAppCredentialFiles(plan systemdPlan) error {
	if err := copyRequiredFile(plan.opts.GitHubAppIDFile, plan.appIDPath, 0o640, "--github-app-id-file"); err != nil {
		return err
	}
	if err := copyRequiredFile(plan.opts.GitHubAppPrivateKeyFile, plan.appPrivateKeyPath, 0o600, "--github-app-private-key-file"); err != nil {
		return err
	}
	return copyRequiredFile(plan.opts.GitHubWebhookSecretFile, plan.webhookSecretPath, 0o600, "--github-webhook-secret-file")
}

func writeBrokerConfigFiles(plan systemdPlan) error {
	if err := writeFile(plan.secretsPath, []byte(plan.opts.ClientName+" = "+plan.opts.SharedSecret+"\n"), 0o600); err != nil {
		return err
	}
	if err := copyRequiredFile(plan.opts.ScopeFile, plan.scopePath, 0o644, "--scope-file"); err != nil {
		return err
	}
	if err := writeFile(plan.envPath, []byte(renderEnvFile(plan)), 0o640); err != nil {
		return err
	}
	return writeFile(plan.unitPath, []byte(renderSystemdUnit(plan)), 0o644)
}

func createSystemdDirs(plan systemdPlan) error {
	if err := os.MkdirAll(plan.opts.ConfigDir, 0o750); err != nil {
		return fmt.Errorf("create config dir: %w", err)
	}
	if err := os.MkdirAll(plan.opts.StateDir, 0o750); err != nil {
		return fmt.Errorf("create state dir: %w", err)
	}
	if err := os.MkdirAll(plan.opts.SystemdDir, 0o755); err != nil { // #nosec G301 -- systemd unit directories must be world-readable/traversable.
		return fmt.Errorf("create systemd dir: %w", err)
	}
	return nil
}

func copyRequiredFile(source string, dest string, mode os.FileMode, label string) error {
	data, err := os.ReadFile(source) // #nosec G304 -- operator-supplied setup path.
	if err != nil {
		return fmt.Errorf("read %s: %w", label, err)
	}
	if len(data) == 0 {
		return fmt.Errorf("%s is empty", label)
	}
	return writeFile(dest, data, mode)
}

func writeFile(path string, data []byte, mode os.FileMode) error {
	if err := os.WriteFile(path, data, mode); err != nil { // #nosec G304,G703 -- setup writes operator-configured filesystem paths.
		return fmt.Errorf("write %s: %w", path, err)
	}
	return os.Chmod(path, mode)
}

func chownSystemdFiles(plan systemdPlan, configUID, serviceUID, serviceGID int) error {
	opts := plan.opts
	if err := chownPath(opts.ConfigDir, configUID, serviceGID, "config dir"); err != nil {
		return err
	}
	if err := chownPath(opts.StateDir, serviceUID, serviceGID, "state dir"); err != nil {
		return err
	}
	if err := chownPrivateFiles(plan, serviceUID, serviceGID); err != nil {
		return err
	}
	return chownConfigFiles(plan, configUID, serviceGID)
}

func chownPrivateFiles(plan systemdPlan, uid, gid int) error {
	paths := []string{plan.secretsPath}
	if plan.opts.DevTokenFallback {
		paths = append(paths, plan.tokenPath)
	} else {
		paths = append(paths, plan.appPrivateKeyPath, plan.webhookSecretPath)
	}
	return chownPaths(paths, uid, gid)
}

func chownConfigFiles(plan systemdPlan, uid, gid int) error {
	paths := []string{plan.scopePath, plan.envPath}
	if !plan.opts.DevTokenFallback {
		paths = append(paths, plan.appIDPath)
	}
	return chownPaths(paths, uid, gid)
}

func chownPaths(paths []string, uid, gid int) error {
	for _, path := range paths {
		if err := chownPath(path, uid, gid, path); err != nil {
			return err
		}
	}
	return nil
}

func chownPath(path string, uid, gid int, label string) error {
	if err := os.Chown(path, uid, gid); err != nil {
		return fmt.Errorf("chown %s: %w", label, err)
	}
	return nil
}

func startSystemdService(ctx context.Context, opts setupSystemdOptions) error {
	if opts.NoStart {
		return nil
	}
	if err := opts.CommandRunner.Run(ctx, "systemctl", "daemon-reload"); err != nil {
		return fmt.Errorf("systemctl daemon-reload: %w", err)
	}
	if err := opts.CommandRunner.Run(ctx, "systemctl", "enable", "--now", ghUnitFileName); err != nil {
		return fmt.Errorf("systemctl enable --now %s: %w", ghUnitFileName, err)
	}
	return nil
}

func serviceIDs(userName, groupName string) (int, int, error) {
	account, err := user.Lookup(userName)
	if err != nil {
		return 0, 0, fmt.Errorf("lookup user %q: %w", userName, err)
	}
	group, err := user.LookupGroup(groupName)
	if err != nil {
		return 0, 0, fmt.Errorf("lookup group %q: %w", groupName, err)
	}
	return parseServiceIDs(userName, account.Uid, groupName, group.Gid)
}

func parseServiceIDs(userName, rawUID, groupName, rawGID string) (int, int, error) {
	uid, err := strconv.Atoi(rawUID)
	if err != nil {
		return 0, 0, fmt.Errorf("parse uid for %q: %w", userName, err)
	}
	gid, err := strconv.Atoi(rawGID)
	if err != nil {
		return 0, 0, fmt.Errorf("parse gid for %q: %w", groupName, err)
	}
	return uid, gid, nil
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
		"GH_BROKER_GITHUB_HTTP_TIMEOUT=30\n" +
		"GH_BROKER_MAX_RECEIVE_PACK_BYTES=26214400\n"
	if opts.DevTokenFallback {
		return body + "GH_BROKER_GITHUB_TOKEN_FILE=" + plan.tokenPath + "\n"
	}
	return body +
		"GH_BROKER_GITHUB_APP_ID_FILE=" + plan.appIDPath + "\n" +
		"GH_BROKER_GITHUB_APP_PRIVATE_KEY_FILE=" + plan.appPrivateKeyPath + "\n" +
		"GH_BROKER_GITHUB_WEBHOOK_SECRET_FILE=" + plan.webhookSecretPath + "\n"
}

func renderSystemdUnit(plan systemdPlan) string {
	opts := plan.opts
	return `[Unit]
Description=gh-broker GitHub credential broker
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=` + opts.User + `
Group=` + opts.Group + `
EnvironmentFile=` + plan.envPath + `
ExecStart=` + opts.BinaryPath + `
Restart=on-failure
RestartSec=5
NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=strict
ProtectHome=true
ReadWritePaths=` + opts.StateDir + `
ReadOnlyPaths=` + opts.ConfigDir + `

[Install]
WantedBy=multi-user.target
`
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
  secrets file:    %s
  scope file:      %s
  env file:        %s
  state dir:       %s
  unit file:       %s
  broker URL:      %s
`, plan.opts.User, plan.opts.Group, plan.opts.DevTokenFallback, showPath(plan.opts.DevTokenFallback, plan.tokenPath), showPath(!plan.opts.DevTokenFallback, plan.appIDPath), showPath(!plan.opts.DevTokenFallback, plan.appPrivateKeyPath), showPath(!plan.opts.DevTokenFallback, plan.webhookSecretPath), plan.secretsPath, plan.scopePath, plan.envPath, plan.opts.StateDir, plan.unitPath, brokerURL(plan.opts.BindAddr, plan.opts.Port))
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
	return "http://" + host + ":" + strconv.Itoa(port)
}

func printSystemdSummary(stdout io.Writer, plan systemdPlan) {
	_, _ = fmt.Fprintf(stdout, `gh-broker systemd service configured.

Broker URL:
  %s

Broker client:
  name: %s
  secret file: %s

Write the client config with:
  gh-broker setup client --client %s --url %s --secret-file %s --home-dir /home/%s
`, brokerURL(plan.opts.BindAddr, plan.opts.Port), plan.opts.ClientName, plan.secretsPath, plan.opts.ClientName, brokerURL(plan.opts.BindAddr, plan.opts.Port), plan.secretsPath, plan.opts.ClientName)
}
