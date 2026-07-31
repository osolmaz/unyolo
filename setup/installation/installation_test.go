package installation

import (
	"encoding/json"
	"testing"

	setupintent "github.com/osolmaz/unyolo/setup/intent"
)

func validInstallation() Installation {
	return Installation{
		APIVersion: APIVersion,
		Name:       DefaultName,
		CredentialService: setupintent.CredentialService{
			Location:  setupintent.ServiceNative,
			Providers: []string{"github", "huggingface"},
		},
		Approvers: []Approver{{ID: "onur", Account: "onur"}},
		Connections: []Connection{{
			ID: "bob", ClientID: "bob",
			Target:    Target{Kind: TargetLocalAccount, Isolation: "separate", AccountMode: setupintent.AccountExisting, Account: "bob", Home: "/home/bob", Shell: "/bin/bash", UID: 1000, GID: 1000},
			Providers: []string{"github"}, Integrations: []string{"openclaw"},
		}},
	}
}

func TestInstallationCanonicalAndDigest(t *testing.T) {
	t.Parallel()
	value := validInstallation()
	if err := value.Validate(); err != nil {
		t.Fatal(err)
	}
	first, err := value.Canonical()
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := Decode(first)
	if err != nil {
		t.Fatal(err)
	}
	second, err := decoded.Canonical()
	if err != nil {
		t.Fatal(err)
	}
	if string(first) != string(second) {
		t.Fatal("canonical installation output changed after round trip")
	}
	firstDigest, _ := value.Digest()
	secondDigest, _ := decoded.Digest()
	if firstDigest != secondDigest {
		t.Fatal("installation digest is not deterministic")
	}
}

func TestInstallationAllowsZeroConnections(t *testing.T) {
	t.Parallel()
	value := validInstallation()
	value.Connections = nil
	if err := value.Validate(); err != nil {
		t.Fatal(err)
	}
}

func TestInstallationRejectsInvalidConnections(t *testing.T) {
	t.Parallel()
	cases := map[string]func(*Installation){
		"unknown provider":  func(value *Installation) { value.Connections[0].Providers = []string{"sudo"} },
		"duplicate client":  func(value *Installation) { value.Connections = append(value.Connections, value.Connections[0]) },
		"missing approver":  func(value *Installation) { value.Approvers = nil },
		"local target path": func(value *Installation) { value.Connections[0].Target.ProjectDirectory = "/tmp" },
	}
	for name, mutate := range cases {
		mutate := mutate
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			value := validInstallation()
			mutate(&value)
			if err := value.Validate(); err == nil {
				t.Fatal("expected validation error")
			}
		})
	}
}

func TestInstallationDecodeRejectsUnknownFields(t *testing.T) {
	t.Parallel()
	value := validInstallation()
	data, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	data = append(data[:len(data)-1], []byte(`,"token":"forbidden"}`)...)
	if _, err := Decode(data); err == nil {
		t.Fatal("expected unknown secret field rejection")
	}
}
