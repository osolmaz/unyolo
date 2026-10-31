package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/osolmaz/unyolo/deployment/api"
	"github.com/osolmaz/unyolo/deployment/component"
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
