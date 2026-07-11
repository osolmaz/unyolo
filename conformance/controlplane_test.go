package conformance

import (
	"path/filepath"
	"testing"

	"github.com/osolmaz/brokerkit/controlplane"
	"github.com/osolmaz/brokerkit/grants"
	"github.com/osolmaz/brokerkit/policy"
)

func TestRunControlPlane(t *testing.T) {
	clientToken := "client-secret-abcdefghijklmnopqrstuvwxyz"
	operatorToken := "operator-secret-abcdefghijklmnopqrstuvwxyz"
	store := grants.New(filepath.Join(t.TempDir(), "grants.json"), grants.Options{})
	runtime, err := controlplane.New(controlplane.Options{
		Broker: "test-broker", Store: store,
		ClientSecrets: map[string]string{"bob": clientToken}, OperatorSecrets: map[string]string{"onur": operatorToken},
	})
	if err != nil {
		t.Fatal(err)
	}
	RunControlPlane(t, Fixture{
		Runtime: runtime, ClientToken: clientToken, OperatorToken: operatorToken,
		Request: grants.Request{Client: "bob", Operation: "repo.read", Target: policy.Target{Kind: "repo", Fields: map[string][]string{"name": {"owner/repo"}}}, Reason: "conformance"},
	})
}
