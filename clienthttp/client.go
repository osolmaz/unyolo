// Package clienthttp contains shared safety defaults for broker HTTP clients.
package clienthttp

import (
	"errors"
	"net"
	"net/http"
	"net/url"
	"time"

	"github.com/osolmaz/brokerkit/endpoint"
)

// ParseBaseURL accepts only absolute HTTP(S) origins with an optional path.
func ParseBaseURL(value string) (*url.URL, error) {
	parsed, err := url.Parse(value)
	if err != nil || !validBaseURL(parsed) {
		return nil, errors.New("client base URL is invalid")
	}
	if parsed.Scheme == "http" {
		host := net.ParseIP(parsed.Hostname())
		if host == nil || !host.IsLoopback() {
			return nil, errors.New("plaintext client base URL must use a literal loopback address")
		}
	}
	return parsed, nil
}

func validBaseURL(parsed *url.URL) bool {
	return (parsed.Scheme == "http" || parsed.Scheme == "https") && parsed.Host != "" &&
		parsed.User == nil && parsed.RawQuery == "" && parsed.Fragment == ""
}

// ForEndpoint constructs a secure HTTP client and synthetic base URL for one endpoint URI.
func ForEndpoint(value string, client *http.Client) (string, *http.Client, error) {
	parsed, err := endpoint.Parse(value, endpoint.ParseOptions{})
	if err != nil {
		return "", nil, err
	}
	baseURL, err := endpoint.HTTPBaseURL(parsed)
	if err != nil {
		return "", nil, err
	}
	var transport *http.Transport
	if client != nil {
		configured, ok := client.Transport.(*http.Transport)
		if client.Transport != nil && !ok {
			return "", nil, errors.New("endpoint client requires an HTTP transport")
		}
		transport = configured
	}
	transport, err = endpoint.HTTPTransport(parsed, transport)
	if err != nil {
		return "", nil, err
	}
	secure := Secure(client)
	secure.Transport = transport
	return baseURL, secure, nil
}

// Secure clones client and disables redirects that could forward credentials.
func Secure(client *http.Client) *http.Client {
	if client == nil {
		return &http.Client{Timeout: 35 * time.Second, CheckRedirect: rejectRedirect}
	}
	secure := *client
	secure.CheckRedirect = rejectRedirect
	if secure.Timeout <= 0 {
		secure.Timeout = 35 * time.Second
	}
	return &secure
}

func rejectRedirect(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
