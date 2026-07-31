package endpoint

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io"
	"net"
	"net/http"
	"testing"
	"time"

	"github.com/osolmaz/unyolo/internal/host/pki"
)

func TestTLSListenerAndPinnedTransport(t *testing.T) {
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
	configured, err := Parse("tls://127.0.0.1:1", ParseOptions{})
	if err != nil {
		t.Fatal(err)
	}
	configured.port = 0
	listener, err := Listen(configured, ListenOptions{TLSConfig: &tls.Config{MinVersion: tls.VersionTLS13, Certificates: []tls.Certificate{certificate}}})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = listener.Close() })
	server := &http.Server{ReadHeaderTimeout: time.Second, Handler: http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
		_, _ = io.WriteString(writer, "ok")
	})}
	go func() { _ = server.Serve(listener) }()
	t.Cleanup(func() { _ = server.Shutdown(context.Background()) })

	address := listener.Addr().(*net.TCPAddr)
	resolved, err := Parse("tls://127.0.0.1:"+fmt.Sprint(address.Port), ParseOptions{})
	if err != nil {
		t.Fatal(err)
	}
	transport, err := HTTPTransportWithOptions(resolved, TransportOptions{TLSConfig: pinnedTLSConfig(t, ca.Certificate, "127.0.0.1")})
	if err != nil {
		t.Fatal(err)
	}
	client := &http.Client{Transport: transport}
	response, err := client.Get("https://" + resolved.Address())
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = response.Body.Close() }()
	body, _ := io.ReadAll(response.Body)
	if string(body) != "ok" || response.TLS == nil || response.TLS.Version != tls.VersionTLS13 {
		t.Fatalf("TLS response = %q, %#v", body, response.TLS)
	}
}

func TestParseTLSRequiresExplicitNetworkApproval(t *testing.T) {
	t.Parallel()
	if _, err := Parse("tls://broker.example:443", ParseOptions{}); err == nil {
		t.Fatal("network TLS endpoint accepted without approval")
	}
	value, err := Parse("tls://broker.example:443", ParseOptions{AllowNetworkTLS: true})
	if err != nil || value.Scheme() != SchemeTLS || value.Exposure() != ExposureNetwork {
		t.Fatalf("Parse() = %+v, %v", value, err)
	}
}

func pinnedTLSConfig(t *testing.T, ca []byte, serverName string) *tls.Config {
	t.Helper()
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(ca) {
		t.Fatal("append root CA")
	}
	return &tls.Config{MinVersion: tls.VersionTLS13, RootCAs: roots, ServerName: serverName}
}
