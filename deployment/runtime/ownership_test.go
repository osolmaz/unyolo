package runtime

import (
	"testing"

	"github.com/osolmaz/unyolo/deployment/api"
	"github.com/osolmaz/unyolo/internal/host/bundle"
)

func TestValidateOwnershipAcceptsGeneratedClientPath(t *testing.T) {
	t.Parallel()
	component := bundle.Component{Setup: &bundle.SetupAdapter{Ownership: bundle.OwnershipEnvelope{Paths: []string{"/etc/gh-broker"}}}}
	response := api.Response{Actions: []api.PlannedAction{{Resource: api.Resource{Kind: "client", ID: "bob", Path: "/home/bob/.config/gh-broker/client.json"}}}}
	if err := ValidateOwnershipWithPaths(response, component, []string{"/home/bob/.config/gh-broker/client.json"}); err != nil {
		t.Fatal(err)
	}
	if err := ValidateOwnershipWithPaths(response, component, []string{"/home/alice/.config/gh-broker/client.json"}); err == nil {
		t.Fatal("client path for another identity was accepted")
	}
}

func TestValidateOwnershipAcceptsNamedSecretStore(t *testing.T) {
	t.Parallel()
	component := bundle.Component{Setup: &bundle.SetupAdapter{Ownership: bundle.OwnershipEnvelope{Paths: []string{"/etc/gh-broker"}}}}
	response := api.Response{Actions: []api.PlannedAction{{Resource: api.Resource{Kind: "secret_store", ID: "clients", Path: "/etc/gh-broker/secrets"}}}}
	if err := ValidateOwnership(response, component); err != nil {
		t.Fatal(err)
	}
	response.Actions[0].Resource.Path = "/etc/shadow"
	if err := ValidateOwnership(response, component); err == nil {
		t.Fatal("secret store outside ownership was accepted")
	}
}
