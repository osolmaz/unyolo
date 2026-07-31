package control

import (
	"context"
	"net"
	"net/http"
	"path/filepath"
	"strings"
	"testing"
	"time"

	pairingservice "github.com/osolmaz/unyolo/internal/pairing"
	pairingv1 "github.com/osolmaz/unyolo/protocol/pairing"
)

func TestClientLifecycle(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	socket := filepath.Join(dir, "control.sock")
	store := &pairingservice.Store{Directory: filepath.Join(dir, "state")}
	listener, err := net.Listen("unix", socket)
	if err != nil {
		t.Fatal(err)
	}
	server := &http.Server{Handler: pairingservice.ControlHandler(store), ReadHeaderTimeout: time.Second}
	go func() { _ = server.Serve(listener) }()
	t.Cleanup(func() { _ = server.Close() })

	client, err := New("unix://" + socket)
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	invitation, err := client.Create(ctx, InvitationOptions{
		ID: "pair-a", Endpoint: "https://pair.example:443", CACertificate: []byte("public-ca"),
		ServerName: "pair.example", ExpiresAt: time.Now().Add(10 * time.Minute),
		Bundle: pairingv1.Bundle{Connections: []pairingv1.BrokerConnection{{
			BrokerName: "gh-broker", ClientID: "bob", Endpoint: "tls://broker.example:443",
			Secret: strings.Repeat("s", 32), ServerName: "broker.example",
		}}},
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := pairingv1.DecodeInvitation(invitation); err != nil {
		t.Fatalf("returned invitation is invalid: %v", err)
	}
	state, err := client.State(ctx, "pair-a")
	if err != nil || state.State != pairingservice.StateOffered {
		t.Fatalf("State() = %+v, %v", state, err)
	}
	if err := client.Revoke(ctx, "pair-a"); err != nil {
		t.Fatal(err)
	}
	// After revoke, activate must fail.
	if _, err := client.Activate(ctx, "pair-a"); err == nil {
		t.Fatal("Activate() after revoke unexpectedly succeeded")
	}
}

func TestClientRejectsNetworkEndpoint(t *testing.T) {
	t.Parallel()
	if _, err := New("https://pair.example:443"); err == nil {
		t.Fatal("network endpoint accepted")
	}
	if _, err := New("tls://pair.example:443"); err == nil {
		t.Fatal("tls endpoint accepted")
	}
}
