package main

import (
	"errors"
	"fmt"
	"slices"
	"strings"

	"github.com/osolmaz/unyolo/deployment/api"
	"github.com/osolmaz/unyolo/deployment/component"
)

const (
	githubComponentID = "github"
	// sandboxListenerPort is the loopback port of the sandbox listener.
	sandboxListenerPort    = 38481
	sandboxCertificateSlot = "github-sandbox-tls-certificate"
	sandboxKeySlot         = "github-sandbox-tls-key" // #nosec G101 -- public credential slot name, not a credential.
	sandboxCertificateFile = "/etc/gh-broker/sandbox-tls.pem"
	sandboxKeyFile         = "/etc/gh-broker/sandbox-tls-key.pem"
	environmentAsset       = "files/github/env"
)

// githubRenderer renders the GitHub deployment component. When a sandbox
// connection uses the component, it adds the sandbox listener and declares how
// agents in sandboxes reach it.
type githubRenderer struct{}

func (githubRenderer) Render(request api.RenderRequest, template []byte, assets map[string][]byte) (api.RenderResponse, error) {
	profile, rendered, err := component.RenderStandardProfile(request, template, assets)
	if err != nil {
		return api.RenderResponse{}, err
	}
	clients := sandboxClientIDs(request)
	if len(clients) == 0 {
		return component.FinishRender(request, profile, rendered)
	}
	if request.ComponentID != githubComponentID {
		return api.RenderResponse{}, errors.New("the sandbox listener belongs to the github component")
	}
	environment, found := rendered[environmentAsset]
	if !found {
		return api.RenderResponse{}, fmt.Errorf("github component has no %s", environmentAsset)
	}
	rendered[environmentAsset] = append(append([]byte(nil), environment...), sandboxEnvironment(clients)...)
	profile.Credentials = append(profile.Credentials,
		component.Credential{Slot: sandboxCertificateSlot, Destination: sandboxCertificateFile, Mode: 0o600, Owner: "gh-broker", Group: "gh-broker", Encoding: "raw"},
		component.Credential{Slot: sandboxKeySlot, Destination: sandboxKeyFile, Mode: 0o600, Owner: "gh-broker", Group: "gh-broker", Encoding: "raw"},
	)
	return component.FinishSandboxRender(request, profile, rendered, sandboxAccess())
}

// sandboxClientIDs returns the client of every sandbox connection that uses
// the component.
func sandboxClientIDs(request api.RenderRequest) []string {
	var clients []string
	for _, connection := range request.Connections {
		if connection.TargetKind == "sandbox" && slices.Contains(connection.Providers, request.ComponentID) {
			clients = append(clients, connection.ClientID)
		}
	}
	slices.Sort(clients)
	return clients
}

func sandboxEnvironment(clients []string) []byte {
	lines := []string{
		fmt.Sprintf("GH_BROKER_SANDBOX_ENDPOINT=tls://127.0.0.1:%d", sandboxListenerPort),
		"GH_BROKER_SANDBOX_CLIENTS=" + strings.Join(clients, ","),
		"GH_BROKER_TLS_CERT_FILE=" + sandboxCertificateFile,
		"GH_BROKER_TLS_KEY_FILE=" + sandboxKeyFile,
	}
	return []byte(strings.Join(lines, "\n") + "\n")
}

// sandboxAccess tells the runtime adapter what stock gh and git need: the
// client secret as GH_ENTERPRISE_TOKEN, GH_HOST, and Git rules that send
// github.com remotes to the broker with gh as the credential helper.
func sandboxAccess() *api.RenderSandboxAccess {
	return &api.RenderSandboxAccess{
		Port: sandboxListenerPort, CredentialEnv: "GH_ENTERPRISE_TOKEN",
		Environment: []api.RenderEnvironment{
			{Name: "GH_HOST", Value: "{host}"},
			{Name: "GIT_CONFIG_COUNT", Value: "2"},
			{Name: "GIT_CONFIG_KEY_0", Value: "url.{origin}/.insteadOf"},
			{Name: "GIT_CONFIG_VALUE_0", Value: "https://github.com/"},
			{Name: "GIT_CONFIG_KEY_1", Value: "credential.{origin}.helper"},
			{Name: "GIT_CONFIG_VALUE_1", Value: "!gh auth git-credential"},
		},
		Binaries: []string{"/usr/bin/gh", "/usr/bin/git"},
	}
}
