package openshell

import (
	"context"
	"crypto/tls"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/osolmaz/unyolo/deployment/api"
	"github.com/osolmaz/unyolo/internal/host/pki"
)

const testSecret = "client-secret-with-at-least-32-bytes"

type fakeRunner struct {
	commands []Command
	files    map[string]string
	respond  func(Command) ([]byte, error)
}

func (runner *fakeRunner) Run(_ context.Context, command Command) ([]byte, error) {
	runner.commands = append(runner.commands, command)
	for _, argument := range command.Args {
		if strings.HasSuffix(argument, ".json") {
			data, err := os.ReadFile(argument)
			if err == nil {
				runner.files[argument] = string(data)
			}
		}
	}
	if runner.respond == nil {
		return nil, nil
	}
	return runner.respond(command)
}

func (runner *fakeRunner) ran(prefix string) []Command {
	var result []Command
	for _, command := range runner.commands {
		if strings.HasPrefix(command.Name+" "+strings.Join(command.Args, " "), prefix) {
			result = append(result, command)
		}
	}
	return result
}

func newFakeRunner(respond func(string, Command) ([]byte, error)) *fakeRunner {
	return &fakeRunner{files: map[string]string{}, respond: func(command Command) ([]byte, error) {
		return respond(command.Name+" "+strings.Join(command.Args, " "), command)
	}}
}

var errFailed = errors.New("failed")

func testConnection(secret []byte) Connection {
	return Connection{ID: "bob", Sandbox: "bob", Accesses: []Access{{
		ProviderID: "github", ClientSecret: secret,
		Declared: api.RenderSandboxAccess{
			Port: 38481, CredentialEnv: "GH_ENTERPRISE_TOKEN", Binaries: []string{"/usr/bin/gh", "/usr/bin/git"},
			Environment: []api.RenderEnvironment{{Name: "GH_HOST", Value: "{host}"}, {Name: "GIT_CONFIG_KEY_0", Value: "url.{origin}/.insteadOf"}},
		},
	}}}
}

func testAdapter(t *testing.T, runner Runner, gatewayConfig string) (Adapter, string) {
	t.Helper()
	home := t.TempDir()
	if gatewayConfig != "" {
		if err := os.MkdirAll(filepath.Join(home, "openshell"), 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(home, "openshell", "gateway.toml"), []byte(gatewayConfig), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	return Adapter{Runner: runner, ConfigHome: home, GatewayTimeout: time.Second}, home
}

const baseConfig = "[openshell]\nversion = 2\n\n[openshell.gateway]\ncompute_driver = \"docker\"\n"

func TestCheckNeedsTheUserServiceAndCATrust(t *testing.T) {
	for name, test := range map[string]struct {
		failing string
		message string
	}{
		"inactive gateway": {"systemctl --user is-active", "user service"},
		"old gateway":      {"openshell-gateway config preflight", "0.1.7 or later"},
		"supported":        {"", ""},
	} {
		t.Run(name, func(t *testing.T) {
			runner := newFakeRunner(func(line string, command Command) ([]byte, error) {
				if test.failing != "" && strings.HasPrefix(line, test.failing) {
					return nil, errFailed
				}
				if strings.HasPrefix(line, "openshell-gateway") && !strings.Contains(strings.Join(command.Env, " "), "XDG_STATE_HOME=") {
					t.Fatalf("the check preflight uses the real state directory: %v", command.Env)
				}
				return nil, nil
			})
			err := Adapter{Runner: runner}.Check(t.Context(), []byte("ca"))
			if test.message == "" && err != nil || test.message != "" && (err == nil || !strings.Contains(err.Error(), test.message)) {
				t.Fatalf("Check() error = %v, want %q", err, test.message)
			}
		})
	}
}

func TestConnectCreatesResourcesForAMissingSandbox(t *testing.T) {
	runner := newFakeRunner(func(line string, _ Command) ([]byte, error) {
		switch {
		case strings.HasPrefix(line, "openshell profile export"), strings.HasPrefix(line, "openshell provider get"), strings.HasPrefix(line, "openshell sandbox get"):
			return nil, errFailed
		}
		return nil, nil
	})
	adapter, home := testAdapter(t, runner, baseConfig)
	result, err := adapter.Connect(t.Context(), testConnection([]byte(testSecret)), []byte("CA PEM"))
	if err != nil {
		t.Fatal(err)
	}
	if !result.SandboxMissing || !result.GatewayRestarted || result.SandboxRecreate || strings.Join(result.Providers, ",") != "unyolo-github-bob" {
		t.Fatalf("result = %+v", result)
	}
	config, err := os.ReadFile(filepath.Join(home, "openshell", "gateway.toml"))
	if err != nil {
		t.Fatal(err)
	}
	bundle := filepath.Join(home, "openshell", "unyolo-sandbox-ca.pem")
	if !strings.HasPrefix(string(config), baseConfig) || !strings.Contains(string(config), "[openshell.supervisor.network]\nadditional_ca_bundle = \""+bundle+"\"\n") {
		t.Fatalf("gateway.toml =\n%s", config)
	}
	if data, err := os.ReadFile(bundle); err != nil || string(data) != "CA PEM" {
		t.Fatalf("CA bundle = %q, %v", data, err)
	}
	environment, err := os.ReadFile(result.EnvironmentFile)
	if err != nil || string(environment) != "GH_HOST=host.openshell.internal:38481\nGIT_CONFIG_KEY_0=url.https://host.openshell.internal:38481/.insteadOf\n" {
		t.Fatalf("environment = %q, %v", environment, err)
	}
	created := runner.ran("openshell provider create --name unyolo-github-bob --type unyolo-github --credential GH_ENTERPRISE_TOKEN")
	if len(created) != 1 || strings.Join(created[0].Env, " ") != "GH_ENTERPRISE_TOKEN="+testSecret {
		t.Fatalf("provider create = %+v", created)
	}
	for _, command := range runner.commands {
		if strings.Contains(strings.Join(command.Args, " "), testSecret) {
			t.Fatalf("the secret reached the arguments of %s", command.Name)
		}
	}
	if len(runner.ran("openshell profile import --file")) != 1 || len(runner.ran("systemctl --user restart openshell-gateway")) != 1 {
		t.Fatalf("commands = %+v", runner.commands)
	}
	for path, document := range runner.files {
		if !strings.Contains(document, `"host": "host.openshell.internal"`) || !strings.Contains(document, `"port": 38481`) || !strings.Contains(document, `"GH_ENTERPRISE_TOKEN"`) {
			t.Fatalf("profile %s =\n%s", path, document)
		}
	}
}

func TestConnectUpdatesAnExistingSandbox(t *testing.T) {
	expected := "GH_HOST=host.openshell.internal:38481\nGIT_CONFIG_KEY_0=url.https://host.openshell.internal:38481/.insteadOf\n"
	runner := newFakeRunner(func(line string, _ Command) ([]byte, error) {
		switch {
		case strings.HasPrefix(line, "openshell profile export"):
			return []byte(`{"id":"unyolo-github","resource_version":3}`), nil
		case strings.HasPrefix(line, "openshell sandbox provider list"):
			return []byte("NAME  TYPE\nbob-discord  discord-bot\n"), nil
		case strings.HasPrefix(line, "openshell sandbox get"):
			return []byte(readySandbox), nil
		case strings.HasPrefix(line, "openshell sandbox exec"):
			return []byte("HOME=/home/agent\n" + expected), nil
		}
		return nil, nil
	})
	adapter, _ := testAdapter(t, runner, baseConfig)
	result, err := adapter.Connect(t.Context(), testConnection([]byte(testSecret)), []byte("CA PEM"))
	if err != nil {
		t.Fatal(err)
	}
	if result.SandboxMissing || result.SandboxRecreate || !result.GatewayRestarted {
		t.Fatalf("result = %+v", result)
	}
	updated := runner.ran("openshell profile update unyolo-github --file")
	if len(updated) != 1 || !strings.Contains(runner.files[updated[0].Args[len(updated[0].Args)-1]], `"resource_version": 3`) {
		t.Fatalf("profile update = %+v, files %v", updated, runner.files)
	}
	for _, prefix := range []string{
		"openshell provider update unyolo-github-bob --credential GH_ENTERPRISE_TOKEN",
		"openshell sandbox provider attach bob unyolo-github-bob --wait",
		"openshell sandbox stop bob", "openshell sandbox start bob",
	} {
		if len(runner.ran(prefix)) != 1 {
			t.Fatalf("%q did not run once: %+v", prefix, runner.commands)
		}
	}
}

func TestConnectReportsASandboxWithoutTheEnvironment(t *testing.T) {
	runner := newFakeRunner(func(line string, _ Command) ([]byte, error) {
		switch {
		case strings.HasPrefix(line, "openshell profile export"), strings.HasPrefix(line, "openshell provider get"):
			return nil, errFailed
		case strings.HasPrefix(line, "openshell sandbox provider list"):
			return []byte("NAME  TYPE\nunyolo-github-bob  unyolo-github\n"), nil
		case strings.HasPrefix(line, "openshell sandbox get"):
			return []byte(readySandbox), nil
		case strings.HasPrefix(line, "openshell sandbox exec"):
			return []byte("HOME=/home/agent\n"), nil
		}
		return nil, nil
	})
	adapter, _ := testAdapter(t, runner, baseConfig)
	result, err := adapter.Connect(t.Context(), testConnection([]byte(testSecret)), []byte("CA PEM"))
	if err != nil {
		t.Fatal(err)
	}
	if !result.SandboxRecreate || len(runner.ran("openshell sandbox provider attach")) != 0 || len(runner.ran("openshell sandbox stop")) != 0 {
		t.Fatalf("result = %+v, commands %+v", result, runner.commands)
	}
}

const readySandbox = "Sandbox:\n\n  Id: 1\n  Name: bob\n  Phase: Ready\n"

func TestConnectWaitsForTheSandboxAfterTheGatewayRestart(t *testing.T) {
	gets := 0
	runner := newFakeRunner(func(line string, _ Command) ([]byte, error) {
		switch {
		case strings.HasPrefix(line, "openshell profile export"), strings.HasPrefix(line, "openshell provider get"):
			return nil, errFailed
		case strings.HasPrefix(line, "openshell sandbox get"):
			gets++
			if gets < 3 {
				return []byte("Sandbox:\n\n  Name: bob\n  Phase: Provisioning\n"), nil
			}
			return []byte(readySandbox), nil
		case strings.HasPrefix(line, "openshell sandbox exec"):
			if gets < 3 {
				t.Fatal("the adapter ran a command in the sandbox before it was ready")
			}
			return []byte("HOME=/home/agent\n"), nil
		}
		return nil, nil
	})
	adapter, _ := testAdapter(t, runner, baseConfig)
	adapter.GatewayTimeout = 10 * time.Second
	result, err := adapter.Connect(t.Context(), testConnection([]byte(testSecret)), []byte("CA PEM"))
	if err != nil || !result.SandboxRecreate || gets != 3 {
		t.Fatalf("result = %+v, %v after %d reads", result, err, gets)
	}
}

func TestConnectStopsWhenTheSandboxStaysUnready(t *testing.T) {
	runner := newFakeRunner(func(line string, _ Command) ([]byte, error) {
		switch {
		case strings.HasPrefix(line, "openshell profile export"), strings.HasPrefix(line, "openshell provider get"):
			return nil, errFailed
		case strings.HasPrefix(line, "openshell sandbox get"):
			return []byte("Sandbox:\n\n  Name: bob\n  Phase: Provisioning\n"), nil
		}
		return nil, nil
	})
	adapter, _ := testAdapter(t, runner, baseConfig)
	_, err := adapter.Connect(t.Context(), testConnection([]byte(testSecret)), []byte("CA PEM"))
	if err == nil || !strings.Contains(err.Error(), "the sandbox bob is not ready (phase: Provisioning)") || len(runner.ran("openshell sandbox exec")) != 0 {
		t.Fatalf("Connect() error = %v, commands %+v", err, runner.commands)
	}
}

func TestConnectKeepsAnUnchangedCA(t *testing.T) {
	runner := newFakeRunner(func(line string, _ Command) ([]byte, error) {
		if strings.HasPrefix(line, "openshell profile export") || strings.HasPrefix(line, "openshell sandbox get") {
			return nil, errFailed
		}
		return nil, nil
	})
	adapter, _ := testAdapter(t, runner, baseConfig)
	if _, err := adapter.Connect(t.Context(), testConnection([]byte(testSecret)), []byte("CA PEM")); err != nil {
		t.Fatal(err)
	}
	runner.commands = nil
	result, err := adapter.Connect(t.Context(), testConnection(nil), []byte("CA PEM"))
	if err != nil {
		t.Fatal(err)
	}
	if result.GatewayRestarted || len(runner.ran("systemctl")) != 0 || len(runner.ran("openshell provider create")) != 0 {
		t.Fatalf("result = %+v, commands %+v", result, runner.commands)
	}
	result, err = adapter.Connect(t.Context(), testConnection(nil), nil)
	if err != nil || result.GatewayRestarted {
		t.Fatalf("kept CA connect = %+v, %v", result, err)
	}
}

func TestConnectRefusesAnotherSupervisorNetworkTable(t *testing.T) {
	for name, config := range map[string]string{
		"table":        baseConfig + "\n[openshell.supervisor.network]\nadditional_ca_bundle = \"/etc/ca.pem\"\n",
		"spaced table": baseConfig + "\n[ openshell.supervisor.network ]\n",
		"dotted key":   baseConfig + "supervisor.network.additional_ca_bundle = \"/etc/ca.pem\"\n",
	} {
		t.Run(name, func(t *testing.T) {
			adapter, home := testAdapter(t, newFakeRunner(func(string, Command) ([]byte, error) { return nil, nil }), config)
			if _, err := adapter.Connect(t.Context(), testConnection([]byte(testSecret)), []byte("CA PEM")); err == nil || !strings.Contains(err.Error(), "additional_ca_bundle") {
				t.Fatalf("Connect() error = %v", err)
			}
			if data, _ := os.ReadFile(filepath.Join(home, "openshell", "gateway.toml")); string(data) != config {
				t.Fatalf("gateway.toml changed:\n%s", data)
			}
		})
	}
}

func TestConnectRestoresTheConfigWhenPreflightFails(t *testing.T) {
	for name, config := range map[string]string{"existing file": baseConfig, "no file": ""} {
		t.Run(name, func(t *testing.T) {
			runner := newFakeRunner(func(line string, _ Command) ([]byte, error) {
				if strings.HasPrefix(line, "openshell-gateway config preflight") {
					return nil, errFailed
				}
				return nil, nil
			})
			adapter, home := testAdapter(t, runner, config)
			if _, err := adapter.Connect(t.Context(), testConnection([]byte(testSecret)), []byte("CA PEM")); err == nil || !strings.Contains(err.Error(), "restored") {
				t.Fatalf("Connect() error = %v", err)
			}
			data, err := os.ReadFile(filepath.Join(home, "openshell", "gateway.toml"))
			if config == "" && !errors.Is(err, os.ErrNotExist) || config != "" && string(data) != config {
				t.Fatalf("gateway.toml = %q, %v", data, err)
			}
		})
	}
}

func TestConnectWithoutASecretNeedsTheProvider(t *testing.T) {
	runner := newFakeRunner(func(line string, _ Command) ([]byte, error) {
		if strings.HasPrefix(line, "openshell provider get") || strings.HasPrefix(line, "openshell profile export") {
			return nil, errFailed
		}
		return nil, nil
	})
	adapter, home := testAdapter(t, runner, baseConfig)
	if err := os.WriteFile(filepath.Join(home, "openshell", "unyolo-sandbox-ca.pem"), []byte("CA PEM"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := adapter.Connect(t.Context(), testConnection(nil), nil); err == nil || !strings.Contains(err.Error(), "unyolo-github-bob is missing") {
		t.Fatalf("Connect() error = %v", err)
	}
}

func TestVerifyListenerUsesTheCAAndTheSecret(t *testing.T) {
	now := time.Now()
	ca, err := pki.GenerateConstrainedCA(now, time.Hour, ServerNames)
	if err != nil {
		t.Fatal(err)
	}
	server, err := pki.IssueServer(ca, ServerNames, now, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	pair, err := tls.X509KeyPair(server.Certificate, server.PrivateKey)
	if err != nil {
		t.Fatal(err)
	}
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	broker := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/.well-known/unyolo-agent" || r.Header.Get("Authorization") != "Bearer "+testSecret {
			w.WriteHeader(http.StatusForbidden)
			return
		}
		w.WriteHeader(http.StatusOK)
	}))
	broker.Listener = listener
	broker.TLS = &tls.Config{Certificates: []tls.Certificate{pair}, MinVersion: tls.VersionTLS12}
	broker.StartTLS()
	t.Cleanup(broker.Close)
	port, err := strconv.Atoi(strings.TrimPrefix(listener.Addr().String(), "127.0.0.1:"))
	if err != nil {
		t.Fatal(err)
	}
	access := Access{ProviderID: "github", ClientSecret: []byte(testSecret), Declared: api.RenderSandboxAccess{Port: port}}
	if err := VerifyListener(t.Context(), access, ca.Certificate, time.Second); err != nil {
		t.Fatal(err)
	}
	access.ClientSecret = []byte(strings.Repeat("x", 40))
	if err := VerifyListener(t.Context(), access, ca.Certificate, 0); err == nil || !strings.Contains(err.Error(), "status 403") {
		t.Fatalf("wrong secret error = %v", err)
	}
	other, err := pki.GenerateCA(now, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	access.ClientSecret = []byte(testSecret)
	if err := VerifyListener(t.Context(), access, other.Certificate, 0); err == nil {
		t.Fatal("a listener with another CA was accepted")
	}
}
