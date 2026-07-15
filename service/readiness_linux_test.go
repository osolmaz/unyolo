//go:build linux

package service

import (
	"context"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestLocalHTTPClientDisablesProxy(t *testing.T) {
	client := LocalHTTPClient()
	transport, ok := client.Transport.(*http.Transport)
	if !ok {
		t.Fatalf("transport type = %T, want *http.Transport", client.Transport)
	}
	if transport.Proxy != nil {
		t.Fatal("local HTTP client retained a proxy callback")
	}
	defaultTransport := http.DefaultTransport.(*http.Transport)
	if transport == defaultTransport {
		t.Fatal("local HTTP client mutated the default transport")
	}
}

func TestEndpointReadyCheckOverUnixSocket(t *testing.T) {
	directory := t.TempDir()
	if err := os.Chmod(directory, 0o700); err != nil {
		t.Fatal(err)
	}
	listener, err := net.Listen("unix", filepath.Join(directory, "broker.sock"))
	if err != nil {
		t.Fatal(err)
	}
	server := &http.Server{Handler: http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		writer.WriteHeader(http.StatusNoContent)
	})}
	go func() { _ = server.Serve(listener) }()
	t.Cleanup(func() { _ = server.Close() })
	if err := EndpointReadyCheck("unix://"+filepath.Join(directory, "broker.sock"), "/readyz")(t.Context()); err != nil {
		t.Fatal(err)
	}
}

func TestHTTPReadyCheck(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		writer.WriteHeader(http.StatusNoContent)
	}))
	t.Cleanup(server.Close)
	if err := HTTPReadyCheck(server.URL, server.Client())(context.Background()); err != nil {
		t.Fatal(err)
	}
}

func TestHTTPReadyCheckRejectsFailureWithoutResponseBody(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		http.Error(writer, "sensitive provider response", http.StatusServiceUnavailable)
	}))
	t.Cleanup(server.Close)
	err := HTTPReadyCheck(server.URL, server.Client())(context.Background())
	if err == nil || !strings.Contains(err.Error(), "503") || strings.Contains(err.Error(), "sensitive") {
		t.Fatalf("HTTPReadyCheck() error = %v", err)
	}
}

func TestHTTPReadyCheckRejectsRedirect(t *testing.T) {
	redirected := false
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		if request.URL.Path == "/healthy" {
			redirected = true
			writer.WriteHeader(http.StatusNoContent)
			return
		}
		http.Redirect(writer, request, "/healthy", http.StatusTemporaryRedirect)
	}))
	t.Cleanup(server.Close)
	err := HTTPReadyCheck(server.URL, server.Client())(context.Background())
	if err == nil || !strings.Contains(err.Error(), "307") {
		t.Fatalf("HTTPReadyCheck(redirect) error = %v", err)
	}
	if redirected {
		t.Fatal("HTTPReadyCheck followed a readiness redirect")
	}
}

func TestHTTPReadyCheckRedactsInvalidURL(t *testing.T) {
	err := HTTPReadyCheck("http://secret.example/%zz", nil)(context.Background())
	if err == nil || strings.Contains(err.Error(), "secret.example") {
		t.Fatalf("HTTPReadyCheck(invalid URL) error = %v", err)
	}
}
