package pairingclient

import (
	"context"
	"crypto/tls"
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

	invitation, err := store.Create(pairingstore.InvitationOptions{
		ID: "pair-a", Endpoint: server.URL, CACertificate: ca.Certificate, ServerName: "127.0.0.1", ExpiresAt: now.Add(10 * time.Minute),
		Bundle: pairingv1.Bundle{Connections: []pairingv1.BrokerConnection{{
			BrokerName: "gh-broker", ClientID: "bob", Endpoint: "tls://broker.example:443", Secret: strings.Repeat("s", 32), ServerName: "broker.example",
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
