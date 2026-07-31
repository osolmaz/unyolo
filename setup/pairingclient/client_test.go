package pairingclient

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	clientconfig "github.com/osolmaz/unyolo/internal/config/client"
	"github.com/osolmaz/unyolo/internal/host/pki"
	pairingstore "github.com/osolmaz/unyolo/internal/pairing"
	pairingv1 "github.com/osolmaz/unyolo/protocol/pairing"
)

func TestClaimPublishActivateAndVerify(t *testing.T) {
	t.Parallel()
	now := time.Now()
	ca, err := pki.GenerateCA(now, 0)
	if err != nil {
		t.Fatal(err)
	}
	serverMaterial, err := pki.IssueServer(ca, []string{"127.0.0.1"}, now, 0)
	if err != nil {
		t.Fatal(err)
	}
	certificate, err := tls.X509KeyPair(serverMaterial.Certificate, serverMaterial.PrivateKey)
	if err != nil {
		t.Fatal(err)
	}
	store := &pairingstore.Store{Directory: filepath.Join(t.TempDir(), "state")}
	server := httptest.NewUnstartedServer(pairingstore.PublicHandler(store))
	server.TLS = &tls.Config{MinVersion: tls.VersionTLS13, Certificates: []tls.Certificate{certificate}}
	server.StartTLS()
	t.Cleanup(server.Close)

	agentServer := httptest.NewUnstartedServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		if request.Header.Get("Authorization") != "Bearer "+strings.Repeat("s", 32) {
			http.Error(writer, "unauthorized", http.StatusUnauthorized)
			return
		}
		_ = json.NewEncoder(writer).Encode(map[string]any{
			"api_version": "unyolo.io/agent/v1", "build_id": "test", "contract_digest": "sha256:bdc7fc2230ea7db9ede54305f2adcb3e3c21451056e58f9467fd5dbcc4a3ddc7",
			"credential": map[string]any{"credential_kind": "test", "generation": 1, "provider": "github", "ready": true, "verification_state": "verified"}, "operations": []string{},
		})
	}))
	agentServer.TLS = &tls.Config{MinVersion: tls.VersionTLS13, Certificates: []tls.Certificate{certificate}}
	agentServer.StartTLS()
	t.Cleanup(agentServer.Close)

	invitation, err := store.Create(pairingstore.InvitationOptions{
		ID: "pair-a", Endpoint: server.URL, CACertificate: ca.Certificate, ServerName: "127.0.0.1", ExpiresAt: now.Add(10 * time.Minute),
		Bundle: pairingv1.Bundle{Connections: []pairingv1.BrokerConnection{{
			BrokerName: "gh-broker", ClientID: "bob", Endpoint: strings.Replace(agentServer.URL, "https://", "tls://", 1), Secret: strings.Repeat("s", 32), ServerName: "127.0.0.1",
		}}},
	})
	if err != nil {
		t.Fatal(err)
	}
	home := t.TempDir()
	result, err := Claim(context.Background(), invitation, home)
	if err != nil {
		t.Fatal(err)
	}
	if record, err := store.LocalStatus("pair-a"); err != nil || record.State != pairingstore.StateReady {
		t.Fatalf("ready record = %+v, %v", record, err)
	}
	if _, err := store.Activate("pair-a"); err != nil {
		t.Fatal(err)
	}
	if err := WaitForActive(context.Background(), result); err != nil {
		t.Fatal(err)
	}
	if err := VerifyConnections(context.Background(), result); err != nil {
		t.Fatal(err)
	}
	if err := MarkVerified(context.Background(), result); err != nil {
		t.Fatal(err)
	}
	path, _ := clientconfig.Path(home, "gh-broker")
	if info, err := os.Stat(path); err != nil || info.Mode().Perm() != 0o600 {
		t.Fatalf("client config mode = %v, %v", info, err)
	}
	loaded, err := clientconfig.ReadPath(path, home)
	if err != nil || loaded.ClientID != "bob" || loaded.CAFile != result.CAPath {
		t.Fatalf("client config = %+v, %v", loaded, err)
	}
}
