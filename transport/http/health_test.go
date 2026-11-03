package httpx

import (
	"crypto/tls"
	"crypto/x509"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func TestEnableHTTP2HealthChecksConfiguresTheDefaultTransport(t *testing.T) {
	transport, ok := http.DefaultTransport.(*http.Transport)
	if !ok {
		t.Fatalf("default transport is %T", http.DefaultTransport)
	}
	previous := transport.HTTP2
	t.Cleanup(func() { transport.HTTP2 = previous })

	EnableHTTP2HealthChecks()

	if transport.HTTP2 == nil || transport.HTTP2.SendPingTimeout != http2PingAfterIdle ||
		transport.HTTP2.PingTimeout != http2PingTimeout {
		t.Fatalf("HTTP/2 config = %+v", transport.HTTP2)
	}
	if clone := transport.Clone(); clone.HTTP2 == nil || clone.HTTP2.SendPingTimeout != http2PingAfterIdle {
		t.Fatalf("cloned HTTP/2 config = %+v", clone.HTTP2)
	}
}

func TestDeadHTTP2ConnectionStaysInUseWithoutHealthChecks(t *testing.T) {
	t.Parallel()
	server, path := newSilencingHTTP2Server(t)
	client := server.client(t, nil)

	server.get(t, client)
	path.silenceOpenConnections()
	if _, err := client.Get(server.url); err == nil {
		t.Fatal("request over the silenced connection succeeded")
	}
	if dials := path.dials.Load(); dials != 1 {
		t.Fatalf("dials = %d, want the old connection to stay in use", dials)
	}
}

func TestHTTP2HealthChecksReplaceADeadConnection(t *testing.T) {
	t.Parallel()
	server, path := newSilencingHTTP2Server(t)
	client := server.client(t, func(transport *http.Transport) {
		configureHTTP2HealthChecks(transport, 100*time.Millisecond, 100*time.Millisecond)
	})

	server.get(t, client)
	path.silenceOpenConnections()
	deadline := time.Now().Add(10 * time.Second)
	for {
		response, err := client.Get(server.url)
		if err == nil {
			_ = response.Body.Close()
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("no request succeeded after the connection went silent: %v", err)
		}
	}
	if dials := path.dials.Load(); dials != 2 {
		t.Fatalf("dials = %d, want one new connection", dials)
	}
}

type silencingHTTP2Server struct {
	url  string
	cert *x509.Certificate
}

func newSilencingHTTP2Server(t *testing.T) (silencingHTTP2Server, *silencingPath) {
	t.Helper()
	upstream := httptest.NewUnstartedServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		_, _ = io.WriteString(writer, request.Proto)
	}))
	upstream.EnableHTTP2 = true
	upstream.StartTLS()
	t.Cleanup(upstream.Close)
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	path := &silencingPath{listener: listener, silenced: map[net.Conn]bool{}}
	t.Cleanup(path.close)
	go path.serve(upstream.Listener.Addr().String())
	return silencingHTTP2Server{url: "https://" + listener.Addr().String() + "/", cert: upstream.Certificate()}, path
}

func (s silencingHTTP2Server) client(t *testing.T, configure func(*http.Transport)) *http.Client {
	t.Helper()
	roots := x509.NewCertPool()
	roots.AddCert(s.cert)
	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.HTTP2 = nil
	transport.TLSClientConfig = &tls.Config{RootCAs: roots, ServerName: "example.com", MinVersion: tls.VersionTLS12}
	if configure != nil {
		configure(transport)
	}
	t.Cleanup(transport.CloseIdleConnections)
	return &http.Client{Transport: transport, Timeout: time.Second}
}

func (s silencingHTTP2Server) get(t *testing.T, client *http.Client) {
	t.Helper()
	response, err := client.Get(s.url)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = response.Body.Close() }()
	body, err := io.ReadAll(response.Body)
	if err != nil || string(body) != "HTTP/2.0" {
		t.Fatalf("response = %q, %v; want HTTP/2.0", body, err)
	}
}

// silencingPath forwards TCP connections. A silenced connection stays open but
// drops every byte, like a route that a network change took away.
type silencingPath struct {
	listener net.Listener
	dials    atomic.Int32
	mu       sync.Mutex
	conns    []net.Conn
	silenced map[net.Conn]bool
}

func (p *silencingPath) serve(target string) {
	for {
		conn, err := p.listener.Accept()
		if err != nil {
			return
		}
		p.dials.Add(1)
		upstream, err := net.Dial("tcp", target)
		if err != nil {
			_ = conn.Close()
			continue
		}
		p.mu.Lock()
		p.conns = append(p.conns, conn, upstream)
		p.mu.Unlock()
		go p.forward(upstream, conn, conn)
		go p.forward(conn, upstream, conn)
	}
}

func (p *silencingPath) forward(destination, source, client net.Conn) {
	buffer := make([]byte, 32*1024)
	for {
		count, err := source.Read(buffer)
		if err != nil {
			return
		}
		if p.isSilenced(client) {
			continue
		}
		if _, err := destination.Write(buffer[:count]); err != nil {
			return
		}
	}
}

func (p *silencingPath) isSilenced(conn net.Conn) bool {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.silenced[conn]
}

func (p *silencingPath) silenceOpenConnections() {
	p.mu.Lock()
	defer p.mu.Unlock()
	for _, conn := range p.conns {
		p.silenced[conn] = true
	}
}

func (p *silencingPath) close() {
	_ = p.listener.Close()
	p.mu.Lock()
	defer p.mu.Unlock()
	for _, conn := range p.conns {
		_ = conn.Close()
	}
}
