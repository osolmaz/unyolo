package pairingclient

import (
	"context"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"errors"
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

func TestClaimRejectsWrongServerName(t *testing.T) {
	t.Parallel()
	env := newPairingTestEnv(t)
	invitation, err := env.store.Create(pairingstore.InvitationOptions{
		ID: "pair-a", Endpoint: env.pairingURL, CACertificate: env.caCert, ServerName: "not-the-server",
		ExpiresAt: env.now.Add(10 * time.Minute),
		Bundle:    env.bundleTemplate(),
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Claim(context.Background(), invitation, t.TempDir()); err == nil {
		t.Fatal("wrong server name accepted")
	}
	assertHomeUntouched(t, env.home)
}

func TestClaimRejectsWrongCA(t *testing.T) {
	t.Parallel()
	env := newPairingTestEnv(t)
	otherCA, err := pki.GenerateCA(env.now, 0)
	if err != nil {
		t.Fatal(err)
	}
	invitation, err := env.store.Create(pairingstore.InvitationOptions{
		ID: "pair-a", Endpoint: env.pairingURL, CACertificate: otherCA.Certificate, ServerName: "127.0.0.1",
		ExpiresAt: env.now.Add(10 * time.Minute),
		Bundle:    env.bundleTemplate(),
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Claim(context.Background(), invitation, t.TempDir()); err == nil {
		t.Fatal("wrong CA accepted")
	}
	assertHomeUntouched(t, env.home)
}

func TestClaimExpiredInvitationIsRejected(t *testing.T) {
	t.Parallel()
	env := newPairingTestEnv(t)
	invitation, err := env.store.Create(pairingstore.InvitationOptions{
		ID: "pair-a", Endpoint: env.pairingURL, CACertificate: env.caCert, ServerName: "127.0.0.1",
		ExpiresAt: env.now.Add(10 * time.Minute),
		Bundle:    env.bundleTemplate(),
	})
	if err != nil {
		t.Fatal(err)
	}
	env.setNow(env.now.Add(20 * time.Minute))
	if _, err := Claim(context.Background(), invitation, t.TempDir()); err == nil {
		t.Fatal("expired invitation accepted")
	}
}

func TestClaimReplayRejected(t *testing.T) {
	t.Parallel()
	env := newPairingTestEnv(t)
	invitation, err := env.store.Create(pairingstore.InvitationOptions{
		ID: "pair-a", Endpoint: env.pairingURL, CACertificate: env.caCert, ServerName: "127.0.0.1",
		ExpiresAt: env.now.Add(10 * time.Minute),
		Bundle:    env.bundleTemplate(),
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Claim(context.Background(), invitation, t.TempDir()); err != nil {
		t.Fatal(err)
	}
	replayHome := t.TempDir()
	if _, err := Claim(context.Background(), invitation, replayHome); err == nil {
		t.Fatal("replayed invitation accepted")
	}
	assertHomeUntouched(t, replayHome)
}

func TestWaitForActiveReportsRevocation(t *testing.T) {
	t.Parallel()
	env := newPairingTestEnv(t)
	invitation, err := env.store.Create(pairingstore.InvitationOptions{
		ID: "pair-a", Endpoint: env.pairingURL, CACertificate: env.caCert, ServerName: "127.0.0.1",
		ExpiresAt: env.now.Add(10 * time.Minute),
		Bundle:    env.bundleTemplate(),
	})
	if err != nil {
		t.Fatal(err)
	}
	result, err := Claim(context.Background(), invitation, env.home)
	if err != nil {
		t.Fatal(err)
	}
	if err := env.store.Revoke("pair-a"); err != nil {
		t.Fatalf("revoke of ready pairing = %v", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	err = WaitForActive(ctx, result)
	if !errors.Is(err, ErrCancelled) {
		t.Fatalf("WaitForActive after revoke = %v", err)
	}
}

func TestClaimRestoresPreexistingClientFilesOnFailure(t *testing.T) {
	t.Parallel()
	env := newPairingTestEnv(t)
	invitation, err := env.store.Create(pairingstore.InvitationOptions{
		ID: "pair-a", Endpoint: env.pairingURL, CACertificate: env.caCert, ServerName: "127.0.0.1",
		ExpiresAt: env.now.Add(10 * time.Minute),
		Bundle:    env.bundleTemplate(),
	})
	if err != nil {
		t.Fatal(err)
	}
	existingPath, err := clientconfig.Path(env.home, "gh-broker")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Dir(existingPath), 0o700); err != nil {
		t.Fatal(err)
	}
	previous := []byte("previous config content")
	if err := os.WriteFile(existingPath, previous, 0o600); err != nil {
		t.Fatal(err)
	}
	env.stopPairing()
	if _, err := Claim(context.Background(), invitation, env.home); err == nil {
		t.Fatal("expected claim to fail without a live pairing server")
	}
	restored, err := os.ReadFile(existingPath)
	if err != nil {
		t.Fatal(err)
	}
	if string(restored) != string(previous) {
		t.Fatalf("preexisting file was mutated: got %q want %q", restored, previous)
	}
}

type pairingTestEnv struct {
	now         time.Time
	clock       *time.Time
	store       *pairingstore.Store
	pairingURL  string
	pairing     *httptest.Server
	agent       *httptest.Server
	caCert      []byte
	certificate tls.Certificate
	home        string
	brokerURL   string
	brokerName  string
	clientID    string
	brokerSec   string
}

func newPairingTestEnv(t *testing.T) *pairingTestEnv {
	t.Helper()
	now := time.Now().UTC()
	env := &pairingTestEnv{now: now, brokerName: "gh-broker", clientID: "bob", brokerSec: strings.Repeat("s", 32)}
	ca, err := pki.GenerateCA(now, 0)
	if err != nil {
		t.Fatal(err)
	}
	env.caCert = ca.Certificate
	serverMaterial, err := pki.IssueServer(ca, []string{"127.0.0.1"}, now, 0)
	if err != nil {
		t.Fatal(err)
	}
	env.certificate, err = tls.X509KeyPair(serverMaterial.Certificate, serverMaterial.PrivateKey)
	if err != nil {
		t.Fatal(err)
	}
	stateDir := filepath.Join(t.TempDir(), "state")
	nowRef := env.now
	env.clock = &nowRef
	env.store = &pairingstore.Store{Directory: stateDir, Now: func() time.Time { return *env.clock }}

	env.pairing = httptest.NewUnstartedServer(pairingstore.PublicHandler(env.store))
	env.pairing.TLS = &tls.Config{MinVersion: tls.VersionTLS13, Certificates: []tls.Certificate{env.certificate}}
	env.pairing.StartTLS()
	env.pairingURL = env.pairing.URL
	t.Cleanup(func() { env.pairing.Close() })

	env.agent = httptest.NewUnstartedServer(http.HandlerFunc(env.serveAgent))
	env.agent.TLS = &tls.Config{MinVersion: tls.VersionTLS13, Certificates: []tls.Certificate{env.certificate}}
	env.agent.StartTLS()
	env.brokerURL = strings.Replace(env.agent.URL, "https://", "tls://", 1)
	t.Cleanup(func() { env.agent.Close() })

	env.home = t.TempDir()
	return env
}

func (env *pairingTestEnv) serveAgent(writer http.ResponseWriter, request *http.Request) {
	if request.Header.Get("Authorization") != "Bearer "+env.brokerSec {
		http.Error(writer, "unauthorized", http.StatusUnauthorized)
		return
	}
	_ = json.NewEncoder(writer).Encode(map[string]any{
		"api_version": "unyolo.io/agent/v1", "build_id": "test", "contract_digest": "sha256:bdc7fc2230ea7db9ede54305f2adcb3e3c21451056e58f9467fd5dbcc4a3ddc7",
		"credential": map[string]any{"credential_kind": "test", "generation": 1, "provider": "github", "ready": true, "verification_state": "verified"}, "operations": []string{},
	})
}

func (env *pairingTestEnv) setNow(value time.Time) {
	*env.clock = value
}

func (env *pairingTestEnv) stopPairing() {
	env.pairing.Close()
}

func (env *pairingTestEnv) bundleTemplate() pairingv1.Bundle {
	return pairingv1.Bundle{Connections: []pairingv1.BrokerConnection{{
		BrokerName: env.brokerName, ClientID: env.clientID, Endpoint: env.brokerURL, Secret: env.brokerSec, ServerName: "127.0.0.1",
	}}}
}

// assertHomeUntouched verifies that Claim never persisted files under the given home directory.
func assertHomeUntouched(t *testing.T, home string) {
	t.Helper()
	configRoot := filepath.Join(home, ".config", "unyolo")
	if _, err := os.Stat(configRoot); err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return
		}
		t.Fatal(err)
	}
	entries, err := os.ReadDir(configRoot)
	if err != nil {
		t.Fatal(err)
	}
	for _, entry := range entries {
		if entry.Name() != "" {
			t.Fatalf("home directory was touched: %s", entry.Name())
		}
	}
}

// ensure base64 is retained so the import stays wired for future CA fingerprint tests.
var _ = base64.RawStdEncoding
