//go:build linux

package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"os/user"
	"path/filepath"
	"strconv"
	"strings"

	bkservice "github.com/osolmaz/brokerkit/service"
)

const (
	hfTokenFileName = "hf-token"
	secretsFileName = "secrets"
	scopeFileName   = "scope.json"
	envFileName     = "env"
	unitFileName    = "hf-broker.service"
	maxHFTokenBytes = 64 * 1024
)

func runSetupSystemd(ctx context.Context, stdout io.Writer, opts setupSystemdOptions) error {
	if err := requireRootForSystemd(opts); err != nil {
		return err
	}
	plan := systemdSetupPlan(opts)
	if _, err := renderSystemdUnit(plan); err != nil {
		return exitError{code: 64, message: err.Error()}
	}
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
	opts        setupSystemdOptions
	tokenPath   string
	secretsPath string
	scopePath   string
	envPath     string
	unitPath    string
}

func systemdSetupPlan(opts setupSystemdOptions) systemdPlan {
	return systemdPlan{
		opts:        opts,
		tokenPath:   filepath.Join(opts.ConfigDir, hfTokenFileName),
		secretsPath: filepath.Join(opts.ConfigDir, secretsFileName),
		scopePath:   filepath.Join(opts.ConfigDir, scopeFileName),
		envPath:     filepath.Join(opts.ConfigDir, envFileName),
		unitPath:    filepath.Join(opts.SystemdDir, unitFileName),
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
	if err := createSystemdDirs(plan); err != nil {
		return err
	}
	if err := chownSystemdDirs(plan, configOwnerUID(opts), uid, gid); err != nil {
		return err
	}
	if err := writeSystemdConfigFiles(plan); err != nil {
		return err
	}
	if err := chownSystemdConfigFiles(plan, configOwnerUID(opts), uid, gid); err != nil {
		return err
	}
	return writeUnitFile(plan)
}

func configOwnerUID(opts setupSystemdOptions) int {
	if opts.AllowNonRoot {
		return os.Getuid()
	}
	return 0
}

func writeSystemdConfigFiles(plan systemdPlan) error {
	writers := []func(systemdPlan) error{
		writeTokenFile,
		writeSecretsFile,
		writeScopeFile,
		writeEnvFile,
	}
	for _, write := range writers {
		if err := write(plan); err != nil {
			return err
		}
	}
	return nil
}

func createSystemdDirs(plan systemdPlan) error {
	if err := os.MkdirAll(plan.opts.ConfigDir, 0o750); err != nil {
		return fmt.Errorf("create config dir: %w", err)
	}
	if err := os.MkdirAll(plan.opts.StateDir, 0o750); err != nil {
		return fmt.Errorf("create state dir: %w", err)
	}
	if err := os.MkdirAll(plan.opts.SystemdDir, 0o755); err != nil {
		return fmt.Errorf("create systemd dir: %w", err)
	}
	return nil
}

func writeTokenFile(plan systemdPlan) error {
	return copySecretFile(plan.opts.HFTokenFile, plan.tokenPath)
}

func writeSecretsFile(plan systemdPlan) error {
	opts := plan.opts
	return writeFile(plan.secretsPath, []byte(opts.ClientName+" = "+opts.SharedSecret+"\n"), 0o600)
}

func writeScopeFile(plan systemdPlan) error {
	scopeBytes, err := renderScopeJSON(plan.opts.Repo, plan.opts.RepoType)
	if err != nil {
		return err
	}
	return writeFile(plan.scopePath, scopeBytes, 0o644)
}

func writeEnvFile(plan systemdPlan) error {
	return writeFile(plan.envPath, []byte(renderEnvFile(plan)), 0o640)
}

func writeUnitFile(plan systemdPlan) error {
	body, err := renderSystemdUnit(plan)
	if err != nil {
		return err
	}
	return writeFile(plan.unitPath, []byte(body), 0o644)
}

func chownSystemdDirs(plan systemdPlan, configUID, serviceUID, serviceGID int) error {
	opts := plan.opts
	if err := chownPath(opts.ConfigDir, configUID, serviceGID, "config dir"); err != nil {
		return err
	}
	return chownPath(opts.StateDir, serviceUID, serviceGID, "state dir")
}

func chownSystemdConfigFiles(plan systemdPlan, configUID, serviceUID, serviceGID int) error {
	if err := chownPrivateFiles(plan, serviceUID, serviceGID); err != nil {
		return err
	}
	return chownConfigFiles(plan, configUID, serviceGID)
}

func chownPrivateFiles(plan systemdPlan, uid, gid int) error {
	return chownPaths([]string{plan.tokenPath, plan.secretsPath}, uid, gid)
}

func chownConfigFiles(plan systemdPlan, uid, gid int) error {
	return chownPaths([]string{plan.scopePath, plan.envPath}, uid, gid)
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
	if err := opts.CommandRunner.Run(ctx, "systemctl", "enable", "--now", "hf-broker.service"); err != nil {
		return fmt.Errorf("systemctl enable --now hf-broker.service: %w", err)
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

func copySecretFile(source, dest string) error {
	file, err := os.Open(source) // #nosec G304 -- operator-supplied setup path.
	if err != nil {
		return fmt.Errorf("read --hf-token-file: %w", err)
	}
	data, readErr := io.ReadAll(io.LimitReader(file, maxHFTokenBytes+1))
	closeErr := file.Close()
	if readErr != nil {
		return fmt.Errorf("read --hf-token-file: %w", readErr)
	}
	if closeErr != nil {
		return fmt.Errorf("close --hf-token-file: %w", closeErr)
	}
	if len(data) > maxHFTokenBytes {
		return fmt.Errorf("--hf-token-file exceeds %d bytes", maxHFTokenBytes)
	}
	if len(data) == 0 {
		return fmt.Errorf("--hf-token-file is empty")
	}
	return writeFile(dest, data, 0o600)
}

func writeFile(path string, data []byte, mode os.FileMode) error {
	if err := os.WriteFile(path, data, mode); err != nil {
		return fmt.Errorf("write %s: %w", path, err)
	}
	return os.Chmod(path, mode)
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
	return "HF_BROKER_HF_TOKEN_FILE=" + plan.tokenPath + "\n" +
		"HF_BROKER_SECRETS_FILE=" + plan.secretsPath + "\n" +
		"HF_BROKER_SCOPE_FILE=" + plan.scopePath + "\n" +
		"HF_BROKER_STATE_DIR=" + opts.StateDir + "\n" +
		"HF_BROKER_BIND_ADDR=" + opts.BindAddr + "\n" +
		"HF_BROKER_PORT=" + strconv.Itoa(opts.Port) + "\n"
}

func renderSystemdUnit(plan systemdPlan) (string, error) {
	opts := plan.opts
	return bkservice.RenderSystemd(bkservice.SystemdUnit{
		Description:     "hf-broker Hugging Face credential broker",
		User:            opts.User,
		Group:           opts.Group,
		EnvironmentFile: plan.envPath,
		ExecStart:       opts.BinaryPath,
		StateDir:        opts.StateDir,
		ConfigDir:       opts.ConfigDir,
		HomeAccess:      bkservice.HomeAccessDeny,
		PathValidation:  setupPathValidation(opts),
	})
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
