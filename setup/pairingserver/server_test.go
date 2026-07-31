package pairingserver

import (
	"context"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/osolmaz/unyolo/internal/host/pki"
	pairingservice "github.com/osolmaz/unyolo/internal/pairing"
	pairingcontrol "github.com/osolmaz/unyolo/internal/pairing/control"
	pairingv1 "github.com/osolmaz/unyolo/protocol/pairing"
	"github.com/osolmaz/unyolo/setup/pairingclient"
)

func TestServerDrivesReadyActivateVerified(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	stateDir := filepath.Join(dir, "state")
	store := &pairingservice.Store{Directory: stateDir}

	socket := filepath.Join(dir, "control.sock")
	controlListener, err := net.Listen("unix", socket)
	if err != nil {
		t.Fatal(err)
	}
	controlServer := &http.Server{Handler: pairingservice.ControlHandler(store), ReadHeaderTimeout: time.Second}
	go func() { _ = controlServer.Serve(controlListener) }()
	t.Cleanup(func() { _ = controlServer.Close() })

	ca, err := pki.GenerateCA(time.Now(), 0)
	if err != nil {
		t.Fatal(err)
	}
	serverMaterial, err := pki.IssueServer(ca, []string{"127.0.0.1"}, time.Now(), 0)
	if err != nil {
		t.Fatal(err)
	}
	certificate, err := tls.X509KeyPair(serverMaterial.Certificate, serverMaterial.PrivateKey)
	if err != nil {
		t.Fatal(err)
	}
	publicServer := httptest.NewUnstartedServer(pairingservice.PublicHandler(store))
	publicServer.TLS = &tls.Config{MinVersion: tls.VersionTLS13, Certificates: []tls.Certificate{certificate}}
	publicServer.StartTLS()
	t.Cleanup(publicServer.Close)

	var expectedSecret string
	agentServer := httptest.NewUnstartedServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		if expectedSecret == "" || request.Header.Get("Authorization") != "Bearer "+expectedSecret {
			http.Error(writer, "unauthorized", http.StatusUnauthorized)
			return
		}
		writer.Header().Set("Content-Type", "application/json")
		_, _ = writer.Write([]byte(`{"api_version":"unyolo.io/agent/v1","build_id":"test","contract_digest":"sha256:bdc7fc2230ea7db9ede54305f2adcb3e3c21451056e58f9467fd5dbcc4a3ddc7","credential":{"credential_kind":"test","generation":1,"provider":"github","ready":true,"verification_state":"verified"},"operations":[]}`))
	}))
	agentServer.TLS = &tls.Config{MinVersion: tls.VersionTLS13, Certificates: []tls.Certificate{certificate}}
	agentServer.StartTLS()
	t.Cleanup(agentServer.Close)
	brokerURL := strings.Replace(agentServer.URL, "https://", "tls://", 1)

	control, err := pairingcontrol.New("unix://" + socket)
	if err != nil {
		t.Fatal(err)
	}
	server := &Server{Control: control}
	ctx := context.Background()
	invitation, err := server.Create(ctx, InvitationRequest{
		ID: "pair-a", PublicEndpoint: publicServer.URL, PublicServerName: "127.0.0.1",
		CACertificate: ca.Certificate, Bindings: []BrokerBinding{{
			BrokerName: "gh-broker", ClientID: "bob", Endpoint: brokerURL, ServerName: "127.0.0.1",
		}},
	})
	if err != nil {
		t.Fatal(err)
	}
	expectedSecret = readBundleSecret(t, stateDir, "pair-a", "gh-broker")

	clientHome := t.TempDir()
	clientErr := make(chan error, 1)
	go func() {
		result, err := pairingclient.Claim(ctx, invitation.Encoded, clientHome)
		if err != nil {
			clientErr <- err
			return
		}
		if err := pairingclient.WaitForActive(ctx, result); err != nil {
			clientErr <- err
			return
		}
		if err := pairingclient.VerifyConnections(ctx, result); err != nil {
			clientErr <- err
			return
		}
		clientErr <- pairingclient.MarkVerified(ctx, result)
	}()

	waitCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	if err := server.WaitForReady(waitCtx, "pair-a", 50*time.Millisecond); err != nil {
		t.Fatal(err)
	}
	if err := server.Activate(ctx, "pair-a"); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-clientErr:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("client goroutine timed out")
	}

	state, err := control.State(ctx, "pair-a")
	if err != nil || state.State != pairingservice.StateVerified {
		t.Fatalf("final state = %+v, %v", state, err)
	}
}

func TestServerRevokePendingInvitation(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	stateDir := filepath.Join(dir, "state")
	store := &pairingservice.Store{Directory: stateDir}
	socket := filepath.Join(dir, "control.sock")
	listener, err := net.Listen("unix", socket)
	if err != nil {
		t.Fatal(err)
	}
	controlServer := &http.Server{Handler: pairingservice.ControlHandler(store), ReadHeaderTimeout: time.Second}
	go func() { _ = controlServer.Serve(listener) }()
	t.Cleanup(func() { _ = controlServer.Close() })

	control, err := pairingcontrol.New("unix://" + socket)
	if err != nil {
		t.Fatal(err)
	}
	server := &Server{Control: control}
	ctx := context.Background()
	invitation, err := server.Create(ctx, InvitationRequest{
		ID: "pair-a", PublicEndpoint: "https://pair.example:443", PublicServerName: "pair.example",
		CACertificate: []byte("public-ca"), Bindings: []BrokerBinding{{
			BrokerName: "gh-broker", ClientID: "bob", Endpoint: "tls://broker.example:443", ServerName: "broker.example",
		}},
	})
	if err != nil {
		t.Fatal(err)
	}
	_ = invitation
	if err := server.Revoke(ctx, "pair-a"); err != nil {
		t.Fatal(err)
	}
	state, err := control.State(ctx, "pair-a")
	if err != nil || state.State != pairingservice.StateRevoked {
		t.Fatalf("state after revoke = %+v, %v", state, err)
	}
}

// keep base64 wired so the import is retained for future CA fingerprint helpers.
var _ = base64.RawStdEncoding

// keep pairingv1 wired for future evolutions of the invitation schema surface.
var _ = pairingv1.APIVersion

func readBundleSecret(t *testing.T, stateDir, id, brokerName string) string {
	t.Helper()
	data, err := os.ReadFile(filepath.Join(stateDir, id+".json"))
	if err != nil {
		t.Fatal(err)
	}
	var record struct {
		Bundle pairingv1.Bundle `json:"bundle"`
	}
	if err := json.Unmarshal(data, &record); err != nil {
		t.Fatal(err)
	}
	for _, connection := range record.Bundle.Connections {
		if connection.BrokerName == brokerName {
			return connection.Secret
		}
	}
	t.Fatalf("broker %q not found in bundle", brokerName)
	return ""
}
