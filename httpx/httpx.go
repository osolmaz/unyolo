// Package httpx contains small HTTP safety helpers for broker proxies.
package httpx

import (
	"errors"
	"io"
	"math"
	"net/http"
	"strings"
)

// ErrBodyTooLarge is returned when ReadLimited sees more bytes than allowed.
var ErrBodyTooLarge = errors.New("body too large")

var (
	hopByHopHeaders = map[string]struct{}{
		"connection":          {},
		"keep-alive":          {},
		"proxy-authenticate":  {},
		"proxy-authorization": {},
		"proxy-connection":    {},
		"te":                  {},
		"trailer":             {},
		"transfer-encoding":   {},
		"upgrade":             {},
	}
	requestCredentialHeaders = map[string]struct{}{
		"authorization":       {},
		"cookie":              {},
		"proxy-authorization": {},
	}
	responseCredentialHeaders = map[string]struct{}{
		"authentication-info": {},
		"set-cookie":          {},
		"set-cookie2":         {},
		"www-authenticate":    {},
	}
	rewrittenBodyHeaders = map[string]struct{}{
		"content-encoding": {},
		"content-length":   {},
		"etag":             {},
		"link":             {},
	}
)

// HeaderDropper reports whether a header should be omitted when copied.
type HeaderDropper func(string) bool

// ReadLimited reads reader up to limit bytes and fails if one more byte exists.
func ReadLimited(reader io.Reader, limit int64) ([]byte, error) {
	if limit < 0 {
		return nil, errors.New("body limit must be non-negative")
	}
	if limit == math.MaxInt64 {
		return io.ReadAll(reader)
	}
	body, err := io.ReadAll(io.LimitReader(reader, limit+1))
	if err != nil {
		return nil, err
	}
	if int64(len(body)) > limit {
		return nil, ErrBodyTooLarge
	}
	return body, nil
}

// CopyHeaders copies src into dst unless drop returns true for the header name.
func CopyHeaders(dst http.Header, src http.Header, drop HeaderDropper) {
	if dst == nil {
		return
	}
	connectionNominated := connectionNominatedHeaders(src, drop)
	for key, values := range src {
		if shouldDropHeader(key, drop, connectionNominated) {
			continue
		}
		for _, value := range values {
			dst.Add(key, value)
		}
	}
}

// DropAny combines multiple header drop predicates.
func DropAny(droppers ...HeaderDropper) HeaderDropper {
	return func(key string) bool {
		for _, drop := range droppers {
			if drop != nil && drop(key) {
				return true
			}
		}
		return false
	}
}

// HopByHopHeader reports whether key is unsafe to forward through a proxy.
func HopByHopHeader(key string) bool {
	return headerIn(key, hopByHopHeaders)
}

// RequestCredentialHeader reports whether key carries client credentials.
func RequestCredentialHeader(key string) bool {
	return headerIn(key, requestCredentialHeaders)
}

// ResponseCredentialHeader reports whether key may expose upstream auth state.
func ResponseCredentialHeader(key string) bool {
	return headerIn(key, responseCredentialHeaders)
}

// ProxyRequestHeader reports whether key should be dropped before upstreaming.
func ProxyRequestHeader(key string) bool {
	return HopByHopHeader(key) || RequestCredentialHeader(key)
}

// ProxyResponseHeader reports whether key should be dropped before responding.
func ProxyResponseHeader(key string) bool {
	return HopByHopHeader(key) || ResponseCredentialHeader(key)
}

// RewrittenBodyHeader reports whether key is invalid after rewriting a body.
func RewrittenBodyHeader(key string) bool {
	return headerIn(key, rewrittenBodyHeaders)
}

// NoStore sets response headers for broker responses that must not be cached.
func NoStore(header http.Header) {
	header.Set("Cache-Control", "no-store")
	header.Set("Pragma", "no-cache")
	header.Set("X-Content-Type-Options", "nosniff")
}

func headerIn(key string, values map[string]struct{}) bool {
	_, ok := values[strings.ToLower(key)]
	return ok
}

func shouldDropHeader(key string, drop HeaderDropper, connectionNominated map[string]struct{}) bool {
	if drop != nil && drop(key) {
		return true
	}
	_, ok := connectionNominated[strings.ToLower(key)]
	return ok
}

func connectionNominatedHeaders(src http.Header, drop HeaderDropper) map[string]struct{} {
	if drop == nil || !drop("Connection") {
		return nil
	}
	out := map[string]struct{}{}
	for key, values := range src {
		if !strings.EqualFold(key, "Connection") {
			continue
		}
		for _, value := range values {
			addConnectionTokens(out, value)
		}
	}
	return out
}

func addConnectionTokens(out map[string]struct{}, value string) {
	for _, token := range strings.Split(value, ",") {
		token = strings.TrimSpace(token)
		if token != "" {
			out[strings.ToLower(token)] = struct{}{}
		}
	}
}
