package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/osolmaz/unyolo/brokers/github/internal/config"
	"github.com/osolmaz/unyolo/internal/host/pki"
	"github.com/osolmaz/unyolo/transport/endpoint"
)

func TestSandboxListenerServesOnlySandboxClients(t *testing.T) {
	cfg := configForBuildTest(t)
	hostSecret, sandboxSecret := strings.Repeat("a", 32), strings.Repeat("b", 32)
	cfg.ClientID, cfg.SharedSecret = "", ""
	cfg.ClientSecrets = map[string]string{"bob": hostSecret, "sandbox-a": sandboxSecret}
	cfg.SandboxClients = []string{"sandbox-a"}
	roots := writeSandboxTLS(t, &cfg)
	address := freeLoopbackAddress(t)
	sandbox, err := endpoint.Parse("tls://"+address, endpoint.ParseOptions{})
	if err != nil {
		t.Fatal(err)
	}
	cfg.SandboxEndpoint = &sandbox
	servers, err := buildServers(t.Context(), cfg)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(t.Context())
	done := make(chan error, 1)
	go func() { done <- serveServers(ctx, servers) }()
	t.Cleanup(func() {
		cancel()
		<-done
	})

	sandboxClient := &http.Client{Timeout: 5 * time.Second, Transport: &http.Transport{TLSClientConfig: &tls.Config{RootCAs: roots, ServerName: "host.openshell.internal", MinVersion: tls.VersionTLS12}}}
	agentSocket := strings.TrimPrefix(cfg.AgentEndpoint.String(), "unix://")
	hostClient := &http.Client{Timeout: 5 * time.Second, Transport: &http.Transport{DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, "unix", agentSocket)
	}}}
	for name, test := range map[string]struct {
		client *http.Client
		url    string
		secret string
		status int
	}{
		"sandbox client on the sandbox listener": {sandboxClient, "https://" + address + "/api/grants", sandboxSecret, http.StatusOK},
		"host client on the sandbox listener":    {sandboxClient, "https://" + address + "/api/grants", hostSecret, http.StatusForbidden},
		"sandbox client on the agent socket":     {hostClient, "http://agent/api/grants", sandboxSecret, http.StatusForbidden},
		"host client on the agent socket":        {hostClient, "http://agent/api/grants", hostSecret, http.StatusOK},
	} {
		t.Run(name, func(t *testing.T) {
			request, err := http.NewRequestWithContext(t.Context(), http.MethodGet, test.url, nil)
			if err != nil {
				t.Fatal(err)
			}
			request.Header.Set("Authorization", "Bearer "+test.secret)
			response, err := test.client.Do(request)
			if err != nil {
				t.Fatal(err)
			}
			_ = response.Body.Close()
			if response.StatusCode != test.status {
				t.Fatalf("status = %d, want %d", response.StatusCode, test.status)
			}
		})
	}
}

func writeSandboxTLS(t *testing.T, cfg *config.Config) *x509.CertPool {
	t.Helper()
	now := time.Now()
	ca, err := pki.GenerateCA(now, 0)
	if err != nil {
		t.Fatal(err)
	}
	server, err := pki.IssueServer(ca, []string{"host.openshell.internal", "127.0.0.1"}, now, 0)
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	cfg.TLSCertificateFile, cfg.TLSPrivateKeyFile = filepath.Join(dir, "tls.pem"), filepath.Join(dir, "tls-key.pem")
	for path, data := range map[string][]byte{cfg.TLSCertificateFile: server.Certificate, cfg.TLSPrivateKeyFile: server.PrivateKey} {
		if err := os.WriteFile(path, data, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(ca.Certificate) {
		t.Fatal("CA certificate was not added")
	}
	return roots
}

func freeLoopbackAddress(t *testing.T) string {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	address := listener.Addr().String()
	if err := listener.Close(); err != nil {
		t.Fatal(err)
	}
	return address
}
