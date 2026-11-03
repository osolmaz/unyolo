package httpx

import (
	"net/http"
	"time"
)

const (
	// http2PingAfterIdle is how long an HTTP/2 connection can stay silent
	// before the client sends a ping to check it.
	http2PingAfterIdle = 30 * time.Second
	// http2PingTimeout is how long the client waits for the ping reply before
	// it closes the connection.
	http2PingTimeout = 15 * time.Second
)

// EnableHTTP2HealthChecks makes the process-wide default transport close an
// HTTP/2 connection that stops answering. Without it, Go sends each new
// request over a dead connection, for example after a network change, until
// the kernel gives up on it, which takes about 15 minutes on Linux. Services
// call it once at startup, before their first request. Clients that use or
// clone the default transport keep the setting.
func EnableHTTP2HealthChecks() {
	if transport, ok := http.DefaultTransport.(*http.Transport); ok {
		configureHTTP2HealthChecks(transport, http2PingAfterIdle, http2PingTimeout)
	}
}

func configureHTTP2HealthChecks(transport *http.Transport, pingAfterIdle, pingTimeout time.Duration) {
	if transport.HTTP2 == nil {
		transport.HTTP2 = &http.HTTP2Config{}
	}
	transport.HTTP2.SendPingTimeout = pingAfterIdle
	transport.HTTP2.PingTimeout = pingTimeout
}
