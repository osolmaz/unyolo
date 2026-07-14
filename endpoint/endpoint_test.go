package endpoint

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func TestParseCanonicalEndpoints(t *testing.T) {
	tests := []struct {
		value string
		opts  ParseOptions
		want  string
		class Exposure
	}{
		{"unix:///run/brokerkit/github/agent.sock", ParseOptions{}, "unix:///run/brokerkit/github/agent.sock", ExposureLocal},
		{"tcp://127.0.0.1:52147", ParseOptions{}, "tcp://127.0.0.1:52147", ExposureLoopback},
		{"tcp://[::1]:52147", ParseOptions{}, "tcp://[::1]:52147", ExposureLoopback},
		{"tcp://192.0.2.4:443", ParseOptions{AllowNetworkTCP: true}, "tcp://192.0.2.4:443", ExposureNetwork},
		{"activation://operator", ParseOptions{}, "activation://operator", ExposureLocal},
		{"fd://3", ParseOptions{}, "fd://3", ExposureLocal},
	}
	for _, test := range tests {
		t.Run(test.value, func(t *testing.T) {
			value, err := Parse(test.value, test.opts)
			if err != nil || value.String() != test.want || value.Exposure() != test.class {
				t.Fatalf("Parse() = %q, %q, %v", value.String(), value.Exposure(), err)
			}
		})
	}
}

func TestParseRejectsUnsafeEndpoints(t *testing.T) {
	values := []string{
		"", " unix:///run/x.sock", "http://127.0.0.1:1", "unix://relative.sock", "unix:///run/../tmp/x.sock",
		"tcp://localhost:1", "tcp://127.0.0.1", "tcp://127.0.0.1:0", "tcp://0.0.0.0:1", "tcp://user@127.0.0.1:1",
		"tcp://127.0.0.1:1/path", "activation://bad/name", "activation://agent?x=1", "fd://2", "fd://abc",
	}
	for _, value := range values {
		if parsed, err := Parse(value, ParseOptions{}); err == nil {
			t.Errorf("Parse(%q) = %#v, want error", value, parsed)
		}
	}
}

func TestEphemeralTCPRequiresDevelopmentOption(t *testing.T) {
	value, err := Parse("tcp://127.0.0.1:0", ParseOptions{AllowEphemeralTCP: true})
	if err != nil || value.Address() != "127.0.0.1:0" {
		t.Fatalf("Parse() = %#v, %v", value, err)
	}
}

func TestUnixListenerAndTransport(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Unix sockets are unavailable")
	}
	directory := t.TempDir()
	if err := os.Chmod(directory, 0o700); err != nil {
		t.Fatal(err)
	}
	value, err := Parse("unix://"+filepath.Join(directory, "agent.sock"), ParseOptions{})
	if err != nil {
		t.Fatal(err)
	}
	listener, err := Listen(value, ListenOptions{Development: true, SocketMode: 0o600})
	if err != nil {
		t.Fatal(err)
	}
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) { _, _ = io.WriteString(writer, "ok") }))
	server.Listener = listener
	server.Start()
	transport, err := HTTPTransport(value, nil)
	if err != nil {
		t.Fatal(err)
	}
	baseURL, _ := HTTPBaseURL(value)
	request, _ := http.NewRequestWithContext(context.Background(), http.MethodGet, baseURL, http.NoBody)
	response, err := (&http.Client{Transport: transport}).Do(request)
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(response.Body)
	_ = response.Body.Close()
	if string(body) != "ok" {
		t.Fatalf("body = %q", body)
	}
	server.Close()
	if _, err := os.Lstat(value.Path()); !os.IsNotExist(err) {
		t.Fatalf("socket survived close: %v", err)
	}
}

func TestExistingNonSocketFailsClosed(t *testing.T) {
	directory := t.TempDir()
	_ = os.Chmod(directory, 0o700)
	path := filepath.Join(directory, "agent.sock")
	if err := os.WriteFile(path, []byte("not a socket"), 0o600); err != nil {
		t.Fatal(err)
	}
	value, _ := Parse("unix://"+path, ParseOptions{})
	if _, err := Listen(value, ListenOptions{Development: true}); err == nil || !strings.Contains(err.Error(), "owned socket") {
		t.Fatalf("Listen() error = %v", err)
	}
}
