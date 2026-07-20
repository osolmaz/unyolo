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
	if err != nil || !validHTTPOriginShape(value) {
		return errors.New("upstream URL must be an absolute credential-free HTTP origin")
	}
	if err := validateHTTPOriginPath(value.Path); err != nil {
		return err
	}
	return validateHTTPOriginScheme(value, development)
}

func validHTTPOriginShape(value *url.URL) bool {
	return value.Scheme != "" && value.Host != "" && value.User == nil && value.RawQuery == "" && value.Fragment == "" && value.Opaque == ""
}

func validateHTTPOriginPath(value string) error {
	normalizedPath := strings.TrimSuffix(value, "/")
	if normalizedPath == "" && value != "" {
		normalizedPath = "/"
	}
	if value != "" && path.Clean(value) != normalizedPath {
		return errors.New("upstream URL path must be normalized")
	}
	return nil
}

func validateHTTPOriginScheme(value *url.URL, development bool) error {
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
