package api

import (
	"strings"
	"testing"
)

func validSandboxAccess() *RenderSandboxAccess {
	return &RenderSandboxAccess{
		Port: 38481, CredentialEnv: "GH_ENTERPRISE_TOKEN", Binaries: []string{"/usr/bin/gh", "/usr/bin/git"},
		Environment: []RenderEnvironment{{Name: "GH_HOST", Value: "{host}"}, {Name: "GIT_CONFIG_VALUE_1", Value: "!gh auth git-credential"}},
	}
}

func TestRenderSandboxAccessValidation(t *testing.T) {
	if err := validSandboxAccess().Validate(); err != nil {
		t.Fatal(err)
	}
	if err := (*RenderSandboxAccess)(nil).Validate(); err != nil {
		t.Fatalf("absent access: %v", err)
	}
	for name, change := range map[string]func(*RenderSandboxAccess){
		"privileged port":    func(a *RenderSandboxAccess) { a.Port = 443 },
		"lowercase variable": func(a *RenderSandboxAccess) { a.CredentialEnv = "gh_token" },
		"no binaries":        func(a *RenderSandboxAccess) { a.Binaries = nil },
		"relative binary":    func(a *RenderSandboxAccess) { a.Binaries = []string{"gh"} },
		"binary wildcard":    func(a *RenderSandboxAccess) { a.Binaries = []string{"/usr/bin/*"} },
		"duplicate variable": func(a *RenderSandboxAccess) {
			a.Environment = append(a.Environment, RenderEnvironment{Name: "GH_HOST", Value: "x"})
		},
		"secret variable": func(a *RenderSandboxAccess) { a.Environment[0].Name = "GH_ENTERPRISE_TOKEN" },
		"multiline value": func(a *RenderSandboxAccess) { a.Environment[0].Value = "a\nb" },
		"empty value":     func(a *RenderSandboxAccess) { a.Environment[0].Value = "" },
	} {
		t.Run(name, func(t *testing.T) {
			access := validSandboxAccess()
			change(access)
			if err := access.Validate(); err == nil {
				t.Fatalf("invalid access passed: %+v", access)
			}
		})
	}
}

func TestRenderMetadataKeepsAndChecksSandboxAccess(t *testing.T) {
	response := RenderResponse{APIVersion: RenderAPIVersion, ComponentID: "github", Profile: []byte(`{}`), SandboxAccess: validSandboxAccess()}
	digest, err := response.CalculateRenderDigest()
	if err != nil {
		t.Fatal(err)
	}
	response.RenderDigest = digest
	if err := response.Validate(); err != nil {
		t.Fatal(err)
	}
	metadata := response.Metadata()
	if err := metadata.Validate(); err != nil || metadata.SandboxAccess.Port != 38481 {
		t.Fatalf("metadata = %+v, %v", metadata.SandboxAccess, err)
	}
	metadata.SandboxAccess.Binaries[0] = "/changed"
	if response.SandboxAccess.Binaries[0] != "/usr/bin/gh" {
		t.Fatal("metadata shares the response's sandbox access")
	}
	response.SandboxAccess.Port = 38482
	if err := response.Validate(); err == nil || !strings.Contains(err.Error(), "digest") {
		t.Fatalf("changed sandbox access kept the digest: %v", err)
	}
}

func TestRenderRequestChecksSandboxConnections(t *testing.T) {
	request := RenderRequest{
		APIVersion: RenderAPIVersion, ComponentID: "github", OperatingSystem: "linux", Architecture: "arm64",
		Approvers: []RenderApprover{{ID: "onur", Account: "onur"}}, Profile: []byte(`{}`),
		Connections: []RenderConnection{{ID: "bob", ClientID: "bob", TargetKind: "sandbox", Isolation: "sandbox", Runtime: "openshell", Sandbox: "bob"}},
	}
	if err := request.Validate(); err != nil {
		t.Fatal(err)
	}
	request.Connections[0].Runtime = "docker"
	if err := request.Validate(); err == nil {
		t.Fatal("an unsupported sandbox runtime passed")
	}
	request.Connections[0] = RenderConnection{ID: "bob", ClientID: "bob", TargetKind: "remote", RemoteName: "bob", Sandbox: "bob"}
	if err := request.Validate(); err == nil {
		t.Fatal("a remote connection with a sandbox passed")
	}
}
