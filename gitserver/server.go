// Package gitserver restricts a broker listener to authenticated Git data-plane traffic.
package gitserver

import (
	"encoding/json"
	"errors"
	"net/http"
	"path"
	"strings"

	"github.com/osolmaz/brokerkit/auth"
)

const IdentityPath = "/_brokerkit/git/v1"

// AllowRoute classifies one provider-owned Git, LFS, or Xet route.
type AllowRoute func(method, requestPath string) bool

// DelegateAuthentication identifies routes whose provider handler validates a
// broker-issued, one-time capability instead of the shared client credential.
type DelegateAuthentication func(*http.Request) bool

// New returns a handler that exposes only the provider's Git data plane.
func New(provider string, authenticator *auth.Authenticator, next http.Handler, allow AllowRoute, delegate DelegateAuthentication) (http.Handler, error) {
	if provider == "" || authenticator == nil || next == nil || allow == nil {
		return nil, errors.New("complete Git listener configuration is required")
	}
	return gitHandler{provider: provider, authenticator: authenticator, next: next, allow: allow, delegate: delegate}, nil
}

type gitHandler struct {
	provider      string
	authenticator *auth.Authenticator
	next          http.Handler
	allow         AllowRoute
	delegate      DelegateAuthentication
}

func (h gitHandler) ServeHTTP(response http.ResponseWriter, request *http.Request) {
	if !normalizedPath(request) {
		http.Error(response, "invalid Git route", http.StatusBadRequest)
		return
	}
	if request.Method == http.MethodGet && request.URL.Path == IdentityPath {
		h.serveIdentity(response, request)
		return
	}
	if !h.allow(request.Method, request.URL.Path) {
		http.NotFound(response, request)
		return
	}
	if (h.delegate == nil || !h.delegate(request)) && !h.authenticate(response, request) {
		return
	}
	h.next.ServeHTTP(response, request)
}

func (h gitHandler) serveIdentity(response http.ResponseWriter, request *http.Request) {
	if !h.authenticate(response, request) {
		return
	}
	response.Header().Set("Cache-Control", "no-store")
	response.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(response).Encode(map[string]string{"provider": h.provider})
}

func (h gitHandler) authenticate(response http.ResponseWriter, request *http.Request) bool {
	_, err := h.authenticator.AuthenticateRequest(request)
	if err == nil {
		return true
	}
	if errors.Is(err, auth.ErrMissing) {
		response.Header().Set("WWW-Authenticate", `Basic realm="brokerkit-git"`)
		http.Error(response, "authentication required", http.StatusUnauthorized)
		return false
	}
	http.Error(response, "authentication failed", http.StatusForbidden)
	return false
}

func normalizedPath(request *http.Request) bool {
	value := request.URL.EscapedPath()
	if strings.Contains(strings.ToLower(value), "%2f") || strings.Contains(strings.ToLower(value), "%5c") {
		return false
	}
	return request.URL.RawPath == "" && request.URL.Path != "" && path.Clean(request.URL.Path) == request.URL.Path
}
