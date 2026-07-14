package endpoint

import (
	"errors"
	"net"
	"net/url"
	"path"
	"strings"
)

// ValidateHTTPOrigin validates an upstream HTTP base URL. Production requires
// HTTPS. Development may use plaintext only with a literal loopback address.
func ValidateHTTPOrigin(raw string, development bool) error {
	value, err := url.Parse(raw)
	if err != nil || value.Scheme == "" || value.Host == "" || value.User != nil || value.RawQuery != "" || value.Fragment != "" || value.Opaque != "" {
		return errors.New("upstream URL must be an absolute credential-free HTTP origin")
	}
	normalizedPath := strings.TrimSuffix(value.Path, "/")
	if normalizedPath == "" && value.Path != "" {
		normalizedPath = "/"
	}
	if value.Path != "" && path.Clean(value.Path) != normalizedPath {
		return errors.New("upstream URL path must be normalized")
	}
	switch value.Scheme {
	case "https":
		return nil
	case "http":
		if development && literalLoopbackHost(value.Hostname()) {
			return nil
		}
		return errors.New("plaintext upstream URL requires development mode and a literal loopback host")
	default:
		return errors.New("upstream URL scheme must be https")
	}
}

func literalLoopbackHost(host string) bool {
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}
