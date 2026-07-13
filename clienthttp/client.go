// Package clienthttp contains shared safety defaults for broker HTTP clients.
package clienthttp

import (
	"errors"
	"net/http"
	"net/url"
	"time"
)

// ParseBaseURL accepts only absolute HTTP(S) origins with an optional path.
func ParseBaseURL(value string) (*url.URL, error) {
	parsed, err := url.Parse(value)
	if err != nil || (parsed.Scheme != "http" && parsed.Scheme != "https") || parsed.Host == "" ||
		parsed.User != nil || parsed.RawQuery != "" || parsed.Fragment != "" {
		return nil, errors.New("client base URL is invalid")
	}
	return parsed, nil
}

// Secure clones client and disables redirects that could forward credentials.
func Secure(client *http.Client) *http.Client {
	if client == nil {
		return &http.Client{Timeout: 35 * time.Second, CheckRedirect: rejectRedirect}
	}
	secure := *client
	secure.CheckRedirect = rejectRedirect
	return &secure
}

func rejectRedirect(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
