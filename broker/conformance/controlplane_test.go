package conformance

import (
	"io"
	"net"
	"net/http"
	"path/filepath"
	"testing"
	"time"

	"github.com/osolmaz/unyolo/authorization/grants"
	"github.com/osolmaz/unyolo/authorization/policy"
	"github.com/osolmaz/unyolo/broker/controlplane"
	"github.com/osolmaz/unyolo/operator/client"
	"github.com/osolmaz/unyolo/operator/v1"
	"github.com/osolmaz/unyolo/telemetry/audit"
)

func TestRunOperatorV1(t *testing.T) {
	clientToken := "client-secret-abcdefghijklmnopqrstuvwxyz"
	operatorToken := "operator-secret-abcdefghijklmnopqrstuvwxyz"
	store := grants.New(filepath.Join(t.TempDir(), "grants.json"), grants.Options{})
	runtime, err := controlplane.New(controlplane.Options{
		Broker: "test-broker", Store: store,
		ClientSecrets: map[string]string{"bob": clientToken}, OperatorSecrets: map[string]string{"onur": operatorToken},
		Audit: audit.New(io.Discard),
	})
	if err != nil {
		t.Fatal(err)
	}
	RunOperatorV1(t, Fixture{
		Runtime: runtime, ClientToken: clientToken, OperatorToken: operatorToken,
		Request: grants.Request{Client: "bob", Operation: "repo.read", Target: policy.Target{Kind: "repo", Fields: map[string][]string{"name": {"owner/repo"}}}, Reason: "conformance"},
	})
}

func TestOperatorV1MountsOnUnixSocket(t *testing.T) {
	t.Parallel()
	operatorToken := "operator-secret-abcdefghijklmnopqrstuvwxyz"
	store := grants.New(filepath.Join(t.TempDir(), "grants.json"), grants.Options{})
	runtime, err := controlplane.New(controlplane.Options{
		Broker: "unix-test", Store: store,
		ClientSecrets:   map[string]string{"bob": "client-secret-abcdefghijklmnopqrstuvwxyz"},
		OperatorSecrets: map[string]string{"onur": operatorToken},
		Audit:           audit.New(io.Discard),
	})
	if err != nil {
		t.Fatal(err)
	}
	socketPath := filepath.Join(t.TempDir(), "operator.sock")
	listener, err := net.Listen("unix", socketPath)
	if err != nil {
		t.Fatal(err)
	}
	server := &http.Server{Handler: runtime.OperatorHandler, ReadHeaderTimeout: 5 * time.Second}
	t.Cleanup(func() {
		_ = server.Close()
		_ = listener.Close()
	})
	go func() { _ = server.Serve(listener) }()
	client, err := operatorclient.New("unix://"+socketPath, operatorToken, nil)
	if err != nil {
		t.Fatal(err)
	}
	descriptor, err := client.Discover(t.Context())
	if err != nil || descriptor.APIVersion != operatorv1.APIVersion {
		t.Fatalf("Discover() = %+v, %v", descriptor, err)
	}
}

func TestRunControlPlaneRejectsUnknownClientCredential(t *testing.T) {
	store := grants.New(filepath.Join(t.TempDir(), "grants.json"), grants.Options{})
	runtime, err := controlplane.New(controlplane.Options{
		Broker: "test-broker", Store: store,
		ClientSecrets:   map[string]string{"bob": "client-secret-abcdefghijklmnopqrstuvwxyz"},
		OperatorSecrets: map[string]string{"onur": "operator-secret-abcdefghijklmnopqrstuvwxyz"},
		Audit:           audit.New(io.Discard),
	})
	if err != nil {
		t.Fatal(err)
	}
	fixture := Fixture{
		Runtime: runtime, ClientToken: "unknown-client-secret-abcdefghijklmnopqrstuvwxyz",
		OperatorToken: "operator-secret-abcdefghijklmnopqrstuvwxyz",
		Request:       grants.Request{Client: "bob", Operation: "repo.read", Target: policy.Target{Kind: "repo"}, Reason: "test"},
	}
	if err := validateFixture(fixture); err == nil {
		t.Fatal("validateFixture() accepted an unknown client credential")
	}
}
