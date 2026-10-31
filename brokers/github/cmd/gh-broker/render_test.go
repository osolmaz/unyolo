package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/osolmaz/unyolo/brokers/github/internal/config"
	"github.com/osolmaz/unyolo/deployment/api"
	"github.com/osolmaz/unyolo/deployment/component"
	"github.com/osolmaz/unyolo/internal/host/pki"
)

func githubRenderRequest(t *testing.T, connections ...api.RenderConnection) (api.RenderRequest, map[string][]byte) {
	t.Helper()
	root := filepath.Join("..", "..", "deployment")
	template, err := os.ReadFile(filepath.Join(root, "profile.json"))
	if err != nil {
		t.Fatal(err)
	}
	var profile component.Profile
	if err := json.Unmarshal(template, &profile); err != nil {
		t.Fatal(err)
	}
	request := api.RenderRequest{
		APIVersion: api.RenderAPIVersion, ComponentID: githubComponentID, OperatingSystem: "linux", Architecture: "arm64",
		Approvers: []api.RenderApprover{{ID: "onur", Account: "onur"}}, Connections: connections, Profile: template,
	}
	assets := map[string][]byte{}
	for _, file := range profile.Files {
		data, err := os.ReadFile(filepath.Join(root, file.Source.Path))
		if err != nil {
			t.Fatal(err)
		}
		assets[file.Source.Path] = data
		sum := sha256.Sum256(data)
		request.Files = append(request.Files, api.RenderFile{Path: file.Source.Path, SHA256: "sha256:" + hex.EncodeToString(sum[:]), Data: data})
	}
	return request, assets
}

func TestGitHubRendererAddsTheSandboxListener(t *testing.T) {
	request, assets := githubRenderRequest(t,
		api.RenderConnection{ID: "bob", ClientID: "bob", Providers: []string{"github"}, TargetKind: "sandbox", Isolation: "sandbox", Runtime: "openshell", Sandbox: "bob"},
		api.RenderConnection{ID: "local", ClientID: "local", Providers: []string{"github"}, TargetKind: "local_account", Isolation: "separate", UnixUser: "local", Home: "/home/local"},
	)
	response, err := githubRenderer{}.Render(request, request.Profile, assets)
	if err != nil {
		t.Fatal(err)
	}
	if err := response.Validate(); err != nil {
		t.Fatal(err)
	}
	environment := renderedFile(t, response, environmentAsset)
	for _, line := range []string{
		"GH_BROKER_SANDBOX_ENDPOINT=tls://127.0.0.1:38481\n", "GH_BROKER_SANDBOX_CLIENTS=bob\n",
		"GH_BROKER_TLS_CERT_FILE=" + sandboxCertificateFile + "\n", "GH_BROKER_TLS_KEY_FILE=" + sandboxKeyFile + "\n",
	} {
		if !strings.Contains(environment, line) {
			t.Fatalf("environment lacks %q:\n%s", line, environment)
		}
	}
	var profile component.Profile
	if err := json.Unmarshal(response.Profile, &profile); err != nil {
		t.Fatal(err)
	}
	slots := map[string]component.Credential{}
	for _, credential := range profile.Credentials {
		slots[credential.Slot] = credential
	}
	for slot, destination := range map[string]string{sandboxCertificateSlot: sandboxCertificateFile, sandboxKeySlot: sandboxKeyFile} {
		if credential, found := slots[slot]; !found || credential.Destination != destination || credential.Mode != 0o600 || credential.Owner != "gh-broker" {
			t.Fatalf("credential %s = %+v", slot, credential)
		}
	}
	clients := ""
	for _, store := range profile.SecretStores {
		for _, entry := range store.Entries {
			clients += entry.Identity + "=" + entry.Slot + " "
		}
	}
	if !strings.Contains(clients, "bob=github-client-bob") || !strings.Contains(clients, "local=github-client-local") {
		t.Fatalf("secret stores = %s", clients)
	}
	access := response.SandboxAccess
	if access == nil || access.Port != sandboxListenerPort || access.CredentialEnv != "GH_ENTERPRISE_TOKEN" || len(access.Binaries) != 2 || access.Environment[0].Value != "{host}" {
		t.Fatalf("sandbox access = %+v", access)
	}
}

func TestGitHubRendererWithoutSandboxesKeepsTheStandardRender(t *testing.T) {
	request, assets := githubRenderRequest(t,
		api.RenderConnection{ID: "local", ClientID: "local", Providers: []string{"github"}, TargetKind: "local_account", Isolation: "separate", UnixUser: "local", Home: "/home/local"},
	)
	response, err := githubRenderer{}.Render(request, request.Profile, assets)
	if err != nil {
		t.Fatal(err)
	}
	standard, err := component.StandardRenderer{}.Render(request, request.Profile, assets)
	if err != nil {
		t.Fatal(err)
	}
	if response.SandboxAccess != nil || response.RenderDigest != standard.RenderDigest {
		t.Fatalf("render without sandboxes differs from the standard render: %+v", response.SandboxAccess)
	}
}

func renderedFile(t *testing.T, response api.RenderResponse, path string) string {
	t.Helper()
	for _, file := range response.Files {
		if file.Path == path {
			return string(file.Data)
		}
	}
	t.Fatalf("render response has no %s", path)
	return ""
}

func TestRenderedSandboxEnvironmentLoads(t *testing.T) {
	request, assets := githubRenderRequest(t,
		api.RenderConnection{ID: "bob", ClientID: "bob", Providers: []string{"github"}, TargetKind: "sandbox", Isolation: "sandbox", Runtime: "openshell", Sandbox: "bob"},
	)
	response, err := githubRenderer{}.Render(request, request.Profile, assets)
	if err != nil {
		t.Fatal(err)
	}
	values := map[string]string{}
	for _, line := range strings.Split(renderedFile(t, response, environmentAsset), "\n") {
		if name, value, found := strings.Cut(line, "="); found {
			values[name] = value
		}
	}
	dir := t.TempDir()
	write := func(name, data string) string {
		path := filepath.Join(dir, name)
		if err := os.WriteFile(path, []byte(data), 0o600); err != nil {
			t.Fatal(err)
		}
		return path
	}
	ca, err := pki.GenerateConstrainedCA(time.Now(), time.Hour, []string{"host.openshell.internal", "127.0.0.1"})
	if err != nil {
		t.Fatal(err)
	}
	server, err := pki.IssueServer(ca, []string{"host.openshell.internal", "127.0.0.1"}, time.Now(), time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	appKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	// The rendered paths point at the host; the test keeps every setting and
	// moves only the files into a temporary directory.
	values["GH_BROKER_SECRETS_FILE"] = write("secrets", "bob = "+strings.Repeat("b", 32)+"\n")
	values["GH_BROKER_OPERATOR_SECRETS_FILE"] = write("operator-secrets", "onur = "+strings.Repeat("o", 32)+"\n")
	values["GH_BROKER_SCOPE_FILE"] = write("scope.json", "{}")
	values["GH_BROKER_STATE_DIR"] = dir
	values["GH_BROKER_GITHUB_APP_ID_FILE"] = write("app-id", "12345")
	values["GH_BROKER_GITHUB_APP_PRIVATE_KEY_FILE"] = write("app-key.pem", string(pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(appKey)})))
	values["GH_BROKER_GITHUB_WEBHOOK_SECRET_FILE"] = write("webhook-secret", "webhook")
	values["GH_BROKER_TLS_CERT_FILE"] = write("sandbox-tls.pem", string(server.Certificate))
	values["GH_BROKER_TLS_KEY_FILE"] = write("sandbox-tls-key.pem", string(server.PrivateKey))
	cfg, err := config.LoadFromLookup(func(name string) (string, bool) {
		value, found := values[name]
		return value, found
	})
	if err != nil {
		t.Fatal(err)
	}
	if cfg.SandboxEndpoint == nil || cfg.SandboxEndpoint.String() != "tls://127.0.0.1:38481" || !cfg.IsSandboxClient("bob") {
		t.Fatalf("sandbox listener = %v, clients %v", cfg.SandboxEndpoint, cfg.SandboxClients)
	}
}
