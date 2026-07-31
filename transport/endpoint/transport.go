package endpoint

import (
	"context"
	"crypto/tls"
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
		return "http://unyolo.local", nil
	case SchemeTCP:
		if value.exposure != ExposureLoopback {
			return "", errors.New("direct TCP clients require a loopback endpoint")
		}
		return "http://" + value.Address(), nil
	case SchemeTLS:
		return "https://" + value.Address(), nil
	default:
		return "", errors.New("endpoint cannot be dialed by a client")
	}
}

// TransportOptions contains the pinned TLS client settings for a network endpoint.
type TransportOptions struct {
	Base      *http.Transport
	TLSConfig *tls.Config
}

// HTTPTransport returns a cloned transport that dials only value.
func HTTPTransport(value Endpoint, base *http.Transport) (*http.Transport, error) {
	return HTTPTransportWithOptions(value, TransportOptions{Base: base})
}

// HTTPTransportWithOptions returns a transport with explicit TLS trust when required.
func HTTPTransportWithOptions(value Endpoint, options TransportOptions) (*http.Transport, error) {
	if !value.ClientCapable() {
		return nil, errors.New("endpoint cannot be dialed by a client")
	}
	if value.scheme == SchemeTCP && value.exposure != ExposureLoopback {
		return nil, errors.New("direct TCP clients require a loopback endpoint")
	}
	if value.scheme == SchemeTLS && (options.TLSConfig == nil || options.TLSConfig.MinVersion < tls.VersionTLS13 || options.TLSConfig.RootCAs == nil || options.TLSConfig.ServerName == "") {
		return nil, errors.New("tls client requires a pinned CA, server name, and TLS 1.3")
	}
	base := options.Base
	if base == nil {
		base = http.DefaultTransport.(*http.Transport)
	}
	transport := base.Clone()
	dialer := &net.Dialer{Timeout: 10 * time.Second, KeepAlive: 30 * time.Second}
	transport.DialContext = func(ctx context.Context, _, _ string) (net.Conn, error) {
		switch value.scheme {
		case SchemeUnix:
			return dialer.DialContext(ctx, "unix", value.path)
		case SchemeTCP, SchemeTLS:
			return dialer.DialContext(ctx, "tcp", value.Address())
		default:
			return nil, errors.New("endpoint cannot be dialed by a client")
		}
	}
	transport.DialTLSContext = nil
	if value.scheme == SchemeTLS {
		transport.TLSClientConfig = options.TLSConfig.Clone()
	} else {
		transport.TLSClientConfig = nil
	}
	return transport, nil
}
