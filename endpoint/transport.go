package endpoint

import (
	"context"
	"errors"
	"net"
	"net/http"
	"time"
)

const staleProbeTimeout = 200 * time.Millisecond

// HTTPBaseURL returns the bounded synthetic HTTP origin used with an endpoint-aware transport.
func HTTPBaseURL(value Endpoint) (string, error) {
	switch value.scheme {
	case SchemeUnix:
		return "http://brokerkit.local", nil
	case SchemeTCP:
		return "http://" + value.Address(), nil
	default:
		return "", errors.New("endpoint cannot be dialed by a client")
	}
}

// HTTPTransport returns a cloned transport that dials only value.
func HTTPTransport(value Endpoint, base *http.Transport) (*http.Transport, error) {
	if !value.ClientCapable() {
		return nil, errors.New("endpoint cannot be dialed by a client")
	}
	if base == nil {
		base = http.DefaultTransport.(*http.Transport)
	}
	transport := base.Clone()
	dialer := &net.Dialer{Timeout: 10 * time.Second, KeepAlive: 30 * time.Second}
	transport.DialContext = func(ctx context.Context, _, _ string) (net.Conn, error) {
		switch value.scheme {
		case SchemeUnix:
			return dialer.DialContext(ctx, "unix", value.path)
		case SchemeTCP:
			return dialer.DialContext(ctx, "tcp", value.Address())
		default:
			return nil, errors.New("endpoint cannot be dialed by a client")
		}
	}
	transport.DialTLSContext = nil
	return transport, nil
}
