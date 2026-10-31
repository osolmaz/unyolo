// Package openshell connects broker sandbox listeners to OpenShell sandboxes.
//
// A provider declares its sandbox access: the loopback port of its sandbox
// listener, the variable that carries the client secret, plain environment
// variables, and the binaries that may use it. The adapter turns that into
// OpenShell resources that the gateway owner controls: the listener CA in the
// gateway configuration, one provider profile per provider, one provider per
// connection that holds the client secret, and an environment file for the
// sandbox. The sandbox reaches the listener as [HostName], and OpenShell adds
// the client secret outside the sandbox, so code in the sandbox cannot read it.
package openshell

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/osolmaz/unyolo/deployment/api"
)

// HostName is the name that OpenShell gives sandboxes for services on the
// gateway host.
const HostName = "host.openshell.internal"

// ServerNames are the names that a sandbox listener certificate must carry:
// the name that the sandbox uses and the loopback address that the broker
// listens on.
var ServerNames = []string{HostName, "127.0.0.1"}

const (
	gatewayService = "openshell-gateway"
	caMarker       = "# unYOLO: trust the CA of unYOLO sandbox listeners."
)

// Command is one command that the adapter runs as the gateway owner. Env adds
// variables to the command's environment; a secret travels only there, never
// in the arguments.
type Command struct {
	Name string
	Args []string
	Env  []string
}

// Runner runs commands as the gateway owner.
type Runner interface {
	Run(ctx context.Context, command Command) ([]byte, error)
}

// ExecRunner runs commands as the current account.
type ExecRunner struct{}

// Run runs one command and returns its combined output.
func (ExecRunner) Run(ctx context.Context, command Command) ([]byte, error) {
	process := exec.CommandContext(ctx, command.Name, command.Args...) // #nosec G204 -- the adapter assembles fixed OpenShell and systemd commands.
	process.Env = append(os.Environ(), command.Env...)
	output, err := process.CombinedOutput()
	if err != nil {
		return output, fmt.Errorf("%s %s: %w: %s", command.Name, strings.Join(command.Args, " "), err, strings.TrimSpace(string(output)))
	}
	return output, nil
}

// Access is one provider's sandbox access for one connection.
type Access struct {
	ProviderID string
	Declared   api.RenderSandboxAccess
	// ClientSecret is the connection's client secret for this provider. It is
	// nil when setup kept the secret that the provider already holds.
	ClientSecret []byte
}

// Connection is one sandbox agent connection.
type Connection struct {
	ID       string
	Sandbox  string
	Accesses []Access
}

// Adapter connects sandbox agents to OpenShell as the gateway owner.
type Adapter struct {
	Runner Runner
	// ConfigHome is the gateway owner's configuration directory, such as
	// ~/.config. OpenShell keeps gateway.toml in its openshell folder.
	ConfigHome string
	// GatewayTimeout bounds the wait for the gateway after a restart.
	GatewayTimeout time.Duration
}

// Result describes what Connect changed and what is left to the sandbox owner.
type Result struct {
	// EnvironmentFile holds the sandbox environment, one KEY=VALUE per line.
	EnvironmentFile string
	// Environment is the sandbox environment in file order.
	Environment []api.RenderEnvironment
	// Providers are the OpenShell providers that the sandbox needs.
	Providers []string
	// GatewayRestarted reports that the gateway now trusts a new CA.
	GatewayRestarted bool
	// SandboxMissing reports that the sandbox does not exist yet.
	SandboxMissing bool
	// SandboxRecreate reports that the sandbox exists without the environment
	// and must be created again with it.
	SandboxRecreate bool
}

// VerifyListener calls the provider's sandbox listener on the host with the
// client secret, so a broken listener, certificate, or secret fails before
// OpenShell changes. It waits up to timeout for the broker to restart.
func VerifyListener(ctx context.Context, access Access, caBundle []byte, timeout time.Duration) error {
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(caBundle) {
		return errors.New("the sandbox listener CA is not a PEM certificate")
	}
	client := &http.Client{Timeout: 5 * time.Second, Transport: &http.Transport{
		TLSClientConfig: &tls.Config{RootCAs: roots, ServerName: HostName, MinVersion: tls.VersionTLS12},
	}}
	defer client.CloseIdleConnections()
	address := "https://127.0.0.1:" + strconv.Itoa(access.Declared.Port) + "/.well-known/unyolo-agent"
	deadline := time.Now().Add(timeout)
	for {
		status, err := discover(ctx, client, address, access.ClientSecret)
		if err == nil && status == http.StatusOK {
			return nil
		}
		if time.Now().After(deadline) {
			if err != nil {
				return fmt.Errorf("the %s sandbox listener did not answer: %w", access.ProviderID, err)
			}
			return fmt.Errorf("the %s sandbox listener refused the client secret with status %d", access.ProviderID, status)
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(time.Second):
		}
	}
}

func discover(ctx context.Context, client *http.Client, address string, secret []byte) (int, error) {
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, address, nil)
	if err != nil {
		return 0, err
	}
	request.Header.Set("Authorization", "Bearer "+string(secret))
	response, err := client.Do(request)
	if err != nil {
		return 0, err
	}
	_ = response.Body.Close()
	return response.StatusCode, nil
}

// Check verifies that the local gateway runs as the user service and accepts
// an additional destination CA. It changes nothing.
func (adapter Adapter) Check(ctx context.Context, caCertificate []byte) error {
	if _, err := adapter.Runner.Run(ctx, Command{Name: "systemctl", Args: []string{"--user", "is-active", "--quiet", gatewayService}}); err != nil {
		return fmt.Errorf("the OpenShell gateway must run as the %s user service: %w", gatewayService, err)
	}
	dir, err := os.MkdirTemp("", "unyolo-openshell-check-")
	if err != nil {
		return err
	}
	defer func() { _ = os.RemoveAll(dir) }()
	bundle := filepath.Join(dir, "ca.pem")
	config := filepath.Join(dir, "gateway.toml")
	if err := os.WriteFile(bundle, caCertificate, 0o600); err != nil {
		return err
	}
	if err := os.WriteFile(config, []byte("[openshell]\nversion = 2\n"+caTable(bundle)), 0o600); err != nil {
		return err
	}
	if _, err := adapter.Runner.Run(ctx, preflight(config, filepath.Join(dir, "state"))); err != nil {
		return fmt.Errorf("this OpenShell cannot trust the sandbox listener CA; install OpenShell 0.1.7 or later: %w", err)
	}
	return nil
}

// Connect makes the OpenShell resources for one sandbox connection. caBundle
// is the new listener CA certificate, or nil when the CA did not change.
func (adapter Adapter) Connect(ctx context.Context, connection Connection, caBundle []byte) (Result, error) {
	if len(connection.Accesses) == 0 || connection.Sandbox == "" {
		return Result{}, errors.New("a sandbox connection needs a sandbox and at least one provider")
	}
	result := Result{EnvironmentFile: filepath.Join(adapter.ConfigHome, "unyolo", "sandboxes", connection.Sandbox+".env")}
	restart, err := adapter.trustCA(ctx, caBundle)
	if err != nil {
		return Result{}, err
	}
	for _, access := range connection.Accesses {
		provider, err := adapter.ensureProvider(ctx, connection, access)
		if err != nil {
			return Result{}, err
		}
		result.Providers = append(result.Providers, provider)
		result.Environment = append(result.Environment, environment(access.Declared)...)
	}
	if err := writeEnvironment(result.EnvironmentFile, result.Environment); err != nil {
		return Result{}, err
	}
	if restart {
		if err := adapter.restartGateway(ctx); err != nil {
			return Result{}, err
		}
		result.GatewayRestarted = true
	}
	return adapter.connectSandbox(ctx, connection.Sandbox, result)
}

// trustCA writes the CA bundle and points the gateway at it. It reports
// whether the gateway must restart to read it.
func (adapter Adapter) trustCA(ctx context.Context, caBundle []byte) (bool, error) {
	openshellDir := filepath.Join(adapter.ConfigHome, "openshell")
	bundlePath := filepath.Join(openshellDir, "unyolo-sandbox-ca.pem")
	configPath := filepath.Join(openshellDir, "gateway.toml")
	changedBundle := false
	if caBundle != nil {
		current, err := os.ReadFile(bundlePath) // #nosec G304 -- fixed path in the gateway owner's configuration.
		if err != nil && !errors.Is(err, os.ErrNotExist) {
			return false, err
		}
		if !bytes.Equal(current, caBundle) {
			if err := writeFileAtomic(bundlePath, caBundle, 0o644); err != nil {
				return false, err
			}
			changedBundle = true
		}
	}
	if _, err := os.Stat(bundlePath); err != nil {
		return false, errors.New("the sandbox listener CA is missing; run unyolo setup again to issue a new one")
	}
	changedConfig, err := adapter.ensureCAConfig(ctx, configPath, bundlePath)
	return changedBundle || changedConfig, err
}

// ensureCAConfig adds the CA bundle to gateway.toml. It edits the file only
// when the file has no supervisor network table, and it refuses any other
// state, so it never rewrites the owner's settings.
func (adapter Adapter) ensureCAConfig(ctx context.Context, configPath, bundlePath string) (bool, error) {
	current, err := os.ReadFile(configPath) // #nosec G304 -- fixed path in the gateway owner's configuration.
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return false, err
	}
	block := "\n" + caMarker + "\n" + caTable(bundlePath)
	text := string(current)
	if strings.Contains(text, block) {
		return false, nil
	}
	if hasSupervisorNetwork(text) {
		return false, fmt.Errorf("%s already configures [openshell.supervisor.network]; set additional_ca_bundle = %s there, combined with any CA that it already trusts", configPath, tomlString(bundlePath))
	}
	updated := text
	if updated == "" {
		updated = "[openshell]\nversion = 2\n"
	}
	if !strings.HasSuffix(updated, "\n") {
		updated += "\n"
	}
	updated += block
	if err := writeFileAtomic(configPath, []byte(updated), 0o600); err != nil {
		return false, err
	}
	if _, err := adapter.Runner.Run(ctx, preflight(configPath, "")); err != nil {
		if restoreErr := restore(configPath, current); restoreErr != nil {
			return false, errors.Join(err, restoreErr)
		}
		return false, fmt.Errorf("the OpenShell gateway rejected the sandbox listener CA, and %s was restored: %w", configPath, err)
	}
	return true, nil
}

// restore puts back the previous file, or removes the file when there was none.
func restore(path string, previous []byte) error {
	if previous == nil {
		return os.Remove(path)
	}
	return writeFileAtomic(path, previous, 0o600)
}

func hasSupervisorNetwork(text string) bool {
	for _, line := range strings.Split(text, "\n") {
		trimmed := strings.TrimSpace(line)
		if strings.HasPrefix(trimmed, "#") {
			continue
		}
		if strings.HasPrefix(strings.ReplaceAll(trimmed, " ", ""), "[openshell.supervisor.network]") || strings.Contains(trimmed, "additional_ca_bundle") {
			return true
		}
	}
	return false
}

func caTable(bundlePath string) string {
	return "[openshell.supervisor.network]\nadditional_ca_bundle = " + tomlString(bundlePath) + "\n"
}

func tomlString(value string) string {
	return strconv.Quote(value)
}

func preflight(configPath, stateDir string) Command {
	command := Command{Name: "openshell-gateway", Args: []string{"config", "preflight"}, Env: []string{"OPENSHELL_GATEWAY_CONFIG=" + configPath}}
	if stateDir != "" {
		command.Env = append(command.Env, "XDG_STATE_HOME="+stateDir)
	}
	return command
}

// ensureProvider imports or updates the provider profile and creates or
// updates the connection's provider with the client secret.
func (adapter Adapter) ensureProvider(ctx context.Context, connection Connection, access Access) (string, error) {
	profileID := "unyolo-" + access.ProviderID
	if err := adapter.ensureProfile(ctx, profileID, access); err != nil {
		return "", err
	}
	name := profileID + "-" + connection.ID
	exists := adapter.succeeds(ctx, Command{Name: "openshell", Args: []string{"provider", "get", name}})
	if access.ClientSecret == nil {
		if !exists {
			return "", fmt.Errorf("the OpenShell provider %s is missing; run unyolo setup again to issue a new client secret", name)
		}
		return name, nil
	}
	secret := Command{Env: []string{access.Declared.CredentialEnv + "=" + string(access.ClientSecret)}}
	if exists {
		secret.Name, secret.Args = "openshell", []string{"provider", "update", name, "--credential", access.Declared.CredentialEnv}
	} else {
		secret.Name, secret.Args = "openshell", []string{"provider", "create", "--name", name, "--type", profileID, "--credential", access.Declared.CredentialEnv}
	}
	if _, err := adapter.Runner.Run(ctx, secret); err != nil {
		return "", fmt.Errorf("store the client secret in the OpenShell provider %s: %w", name, errors.New(redact(err.Error(), access.ClientSecret)))
	}
	return name, nil
}

type profileDocument struct {
	ID               string              `json:"id"`
	ResourceVersion  int                 `json:"resource_version,omitempty"`
	DisplayName      string              `json:"display_name"`
	Description      string              `json:"description"`
	Category         string              `json:"category"`
	InferenceCapable bool                `json:"inference_capable"`
	Credentials      []profileCredential `json:"credentials"`
	Endpoints        []profileEndpoint   `json:"endpoints"`
	Binaries         []string            `json:"binaries"`
}

type profileCredential struct {
	Name        string   `json:"name"`
	Description string   `json:"description"`
	EnvVars     []string `json:"env_vars"`
	Required    bool     `json:"required"`
	AuthStyle   string   `json:"auth_style"`
	HeaderName  string   `json:"header_name"`
}

type profileEndpoint struct {
	Host        string `json:"host"`
	Port        int    `json:"port"`
	Protocol    string `json:"protocol"`
	Access      string `json:"access"`
	Enforcement string `json:"enforcement"`
}

func (adapter Adapter) ensureProfile(ctx context.Context, profileID string, access Access) error {
	document := profileDocument{
		ID: profileID, DisplayName: "unYOLO " + access.ProviderID,
		Description: "Stock clients reach the unYOLO " + access.ProviderID + " broker; the broker keeps the provider credential",
		Category:    "other",
		Credentials: []profileCredential{{
			Name: "client_secret", Description: "unYOLO broker client secret", EnvVars: []string{access.Declared.CredentialEnv},
			Required: true, AuthStyle: "bearer", HeaderName: "authorization",
		}},
		Endpoints: []profileEndpoint{{Host: HostName, Port: access.Declared.Port, Protocol: "rest", Access: "full", Enforcement: "enforce"}},
		Binaries:  slices.Clone(access.Declared.Binaries),
	}
	args := []string{"profile", "import", "--file"}
	if exported, err := adapter.Runner.Run(ctx, Command{Name: "openshell", Args: []string{"profile", "export", profileID, "--output", "json"}}); err == nil {
		var current struct {
			ResourceVersion int `json:"resource_version"`
		}
		if err := json.Unmarshal(exported, &current); err != nil || current.ResourceVersion <= 0 {
			return fmt.Errorf("read the OpenShell provider profile %s: the export has no resource version", profileID)
		}
		document.ResourceVersion = current.ResourceVersion
		args = []string{"profile", "update", profileID, "--file"}
	}
	data, err := json.MarshalIndent(document, "", "  ")
	if err != nil {
		return err
	}
	file, err := os.CreateTemp("", profileID+"-*.json")
	if err != nil {
		return err
	}
	defer func() { _ = os.Remove(file.Name()) }()
	if _, err := file.Write(append(data, '\n')); err != nil {
		_ = file.Close()
		return err
	}
	if err := file.Close(); err != nil {
		return err
	}
	_, err = adapter.Runner.Run(ctx, Command{Name: "openshell", Args: append(args, file.Name())})
	return err
}

// environment substitutes the sandbox address into the declared variables.
func environment(access api.RenderSandboxAccess) []api.RenderEnvironment {
	host := HostName + ":" + strconv.Itoa(access.Port)
	replacer := strings.NewReplacer("{host}", host, "{origin}", "https://"+host)
	result := make([]api.RenderEnvironment, 0, len(access.Environment))
	for _, variable := range access.Environment {
		result = append(result, api.RenderEnvironment{Name: variable.Name, Value: replacer.Replace(variable.Value)})
	}
	return result
}

func writeEnvironment(path string, values []api.RenderEnvironment) error {
	var builder strings.Builder
	seen := map[string]bool{}
	for _, value := range values {
		if seen[value.Name] {
			return fmt.Errorf("two providers set the sandbox variable %s", value.Name)
		}
		seen[value.Name] = true
		builder.WriteString(value.Name + "=" + value.Value + "\n")
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	return writeFileAtomic(path, []byte(builder.String()), 0o600)
}

func (adapter Adapter) restartGateway(ctx context.Context) error {
	if _, err := adapter.Runner.Run(ctx, Command{Name: "systemctl", Args: []string{"--user", "restart", gatewayService}}); err != nil {
		return err
	}
	timeout := adapter.GatewayTimeout
	if timeout <= 0 {
		timeout = time.Minute
	}
	deadline := time.Now().Add(timeout)
	for {
		if adapter.succeeds(ctx, Command{Name: "openshell", Args: []string{"sandbox", "list"}}) {
			return nil
		}
		if time.Now().After(deadline) {
			return errors.New("the OpenShell gateway did not answer after its restart")
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(time.Second):
		}
	}
}

// connectSandbox checks the environment of an existing sandbox, attaches the
// providers, and restarts the sandbox when the gateway trusts a new CA. A
// missing sandbox, or one without the environment, is left to its owner, who
// creates it with the providers and the environment file.
func (adapter Adapter) connectSandbox(ctx context.Context, sandbox string, result Result) (Result, error) {
	if !adapter.succeeds(ctx, Command{Name: "openshell", Args: []string{"sandbox", "get", sandbox}}) {
		result.SandboxMissing = true
		return result, nil
	}
	output, err := adapter.Runner.Run(ctx, Command{Name: "openshell", Args: []string{"sandbox", "exec", "--name", sandbox, "--no-tty", "--", "env"}})
	if err != nil {
		return Result{}, fmt.Errorf("read the environment of the sandbox %s: %w", sandbox, err)
	}
	if !hasEnvironment(output, result.Environment) {
		result.SandboxRecreate = true
		return result, nil
	}
	attached, err := adapter.Runner.Run(ctx, Command{Name: "openshell", Args: []string{"sandbox", "provider", "list", sandbox}})
	if err != nil {
		return Result{}, err
	}
	for _, provider := range result.Providers {
		if !tableHasName(attached, provider) {
			if _, err := adapter.Runner.Run(ctx, Command{Name: "openshell", Args: []string{"sandbox", "provider", "attach", sandbox, provider, "--wait"}}); err != nil {
				return Result{}, err
			}
		}
	}
	if result.GatewayRestarted {
		for _, action := range []string{"stop", "start"} {
			if _, err := adapter.Runner.Run(ctx, Command{Name: "openshell", Args: []string{"sandbox", action, sandbox}}); err != nil {
				return Result{}, err
			}
		}
	}
	return result, nil
}

func tableHasName(output []byte, name string) bool {
	for _, line := range strings.Split(string(output), "\n") {
		if fields := strings.Fields(line); len(fields) > 0 && fields[0] == name {
			return true
		}
	}
	return false
}

func hasEnvironment(output []byte, expected []api.RenderEnvironment) bool {
	lines := strings.Split(string(output), "\n")
	for _, variable := range expected {
		if !slices.Contains(lines, variable.Name+"="+variable.Value) {
			return false
		}
	}
	return true
}

func (adapter Adapter) succeeds(ctx context.Context, command Command) bool {
	_, err := adapter.Runner.Run(ctx, command)
	return err == nil
}

func redact(message string, secret []byte) string {
	if len(secret) == 0 {
		return message
	}
	return strings.ReplaceAll(message, string(secret), "[redacted]")
}

func writeFileAtomic(path string, data []byte, mode os.FileMode) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	file, err := os.CreateTemp(filepath.Dir(path), "."+filepath.Base(path)+".*")
	if err != nil {
		return err
	}
	defer func() { _ = os.Remove(file.Name()) }()
	if _, err := file.Write(data); err != nil {
		_ = file.Close()
		return err
	}
	if err := file.Chmod(mode); err != nil {
		_ = file.Close()
		return err
	}
	if err := file.Close(); err != nil {
		return err
	}
	return os.Rename(file.Name(), path)
}
