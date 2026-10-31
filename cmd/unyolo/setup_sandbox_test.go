package main

import (
	"crypto/x509"
	"encoding/pem"
	"strings"
	"testing"
	"time"

	"github.com/osolmaz/unyolo/deployment/api"
	"github.com/osolmaz/unyolo/deployment/provider"
	"github.com/osolmaz/unyolo/setup/installation"
	setupintent "github.com/osolmaz/unyolo/setup/intent"
	"github.com/osolmaz/unyolo/setup/sandbox/openshell"
)

func TestIssueSandboxTLSSignsListenerCertificatesWithOneConstrainedCA(t *testing.T) {
	now := time.Date(2026, 10, 31, 0, 0, 0, 0, time.UTC)
	values, caPEM, err := issueSandboxTLS([]string{"github-client-bob", "github-sandbox-tls-certificate", "github-sandbox-tls-key"}, now)
	if err != nil {
		t.Fatal(err)
	}
	if len(values) != 2 || len(values["github-sandbox-tls-key"]) == 0 {
		t.Fatalf("values = %v", values)
	}
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(caPEM) {
		t.Fatal("CA certificate was not added")
	}
	block, _ := pem.Decode(values["github-sandbox-tls-certificate"])
	leaf, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := leaf.Verify(x509.VerifyOptions{Roots: roots, DNSName: openshell.HostName, CurrentTime: now.Add(time.Hour)}); err != nil {
		t.Fatal(err)
	}
	if leaf.NotAfter.Sub(now) < sandboxCertificateLifetime-time.Hour {
		t.Fatalf("certificate lifetime ends %s", leaf.NotAfter)
	}
	block, _ = pem.Decode(caPEM)
	ca, err := x509.ParseCertificate(block.Bytes)
	if err != nil || !ca.PermittedDNSDomainsCritical || strings.Join(ca.PermittedDNSDomains, ",") != openshell.HostName {
		t.Fatalf("CA constraints = %v %v, %v", ca.PermittedDNSDomainsCritical, ca.PermittedDNSDomains, err)
	}
	if values, ca, err := issueSandboxTLS([]string{"github-client-bob"}, now); err != nil || values != nil || ca != nil {
		t.Fatalf("plan without sandbox certificates = %v, %v, %v", values, ca, err)
	}
	if _, _, err := issueSandboxTLS([]string{"github-sandbox-tls-certificate"}, now); err == nil {
		t.Fatal("a certificate slot without its key was accepted")
	}
}

func TestSandboxConnectionsUseTheDeclaredAccess(t *testing.T) {
	desired := installation.Installation{Connections: []installation.Connection{
		{ID: "bob", ClientID: "bob", Providers: []string{"github"}, Target: installation.Target{Kind: installation.TargetSandbox, Isolation: "sandbox", Runtime: setupintent.SandboxOpenShell, Sandbox: "bob-box"}},
		{ID: "local", ClientID: "local", Providers: []string{"github", "sudo"}, Target: installation.Target{Kind: installation.TargetLocalAccount}},
	}}
	access := &api.RenderSandboxAccess{Port: 38481, CredentialEnv: "GH_ENTERPRISE_TOKEN", Binaries: []string{"/usr/bin/gh"}}
	connections, err := sandboxConnections(desired, []api.RenderMetadata{{ComponentID: "github", SandboxAccess: access}, {ComponentID: "sudo"}})
	if err != nil {
		t.Fatal(err)
	}
	if len(connections) != 1 || connections[0].ID != "bob" || connections[0].Sandbox != "bob-box" || len(connections[0].Accesses) != 1 || connections[0].Accesses[0].Declared.Port != 38481 {
		t.Fatalf("connections = %+v", connections)
	}
	if _, err := sandboxConnections(desired, []api.RenderMetadata{{ComponentID: "github"}}); err == nil {
		t.Fatal("a provider without sandbox access was accepted")
	}
}

func TestSandboxProvidersKeepOnlyProvidersThatServeSandboxes(t *testing.T) {
	options := []provider.Option{{ID: "github", SandboxAgents: true}, {ID: "huggingface"}, {ID: "sudo"}}
	if got := sandboxProviders([]string{"sudo", "github", "huggingface"}, options); strings.Join(got, ",") != "github" {
		t.Fatalf("sandboxProviders() = %v", got)
	}
}

func TestInstallationFromIntentConnectsAnOpenShellSandbox(t *testing.T) {
	intent := setupintent.Intent{
		APIVersion: setupintent.APIVersion, Goal: setupintent.GoalCompleteLocal,
		CredentialService: &setupintent.CredentialService{Location: setupintent.ServiceNative, Providers: []string{"github", "sudo"}},
		Agent:             &setupintent.Agent{Location: setupintent.AgentSandbox, ConnectionName: "bob", Sandbox: &setupintent.Sandbox{Runtime: setupintent.SandboxOpenShell, Name: "bob"}},
		Connection:        &setupintent.Connection{Transport: setupintent.TransportSandbox},
	}
	result, err := installationFromIntent(intent, "onur", "", []provider.Option{{ID: "github", SandboxAgents: true}, {ID: "sudo"}})
	if err != nil {
		t.Fatal(err)
	}
	if len(result.Connections) != 1 || result.Connections[0].Target.Kind != installation.TargetSandbox || strings.Join(result.Connections[0].Providers, ",") != "github" {
		t.Fatalf("connections = %+v", result.Connections)
	}
	if _, err := installationFromIntent(intent, "onur", "", []provider.Option{{ID: "sudo"}}); err == nil {
		t.Fatal("a sandbox connection without a sandbox provider was accepted")
	}
}

func TestSandboxConnectionNoteListsTheCreateOptions(t *testing.T) {
	note := sandboxConnectionNote("bob", openshell.Result{
		EnvironmentFile: "/home/onur/.config/unyolo/sandboxes/bob.env", Providers: []string{"unyolo-github-bob"}, SandboxMissing: true,
		Environment: []api.RenderEnvironment{{Name: "GIT_CONFIG_VALUE_1", Value: "!gh auth git-credential"}},
	})
	if !strings.Contains(note, "--provider unyolo-github-bob") || !strings.Contains(note, `--env "GIT_CONFIG_VALUE_1=!gh auth git-credential"`) {
		t.Fatalf("note =\n%s", note)
	}
}
