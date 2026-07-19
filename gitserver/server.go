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

// New returns a handler that exposes only the provider's Git data plane.
func New(provider string, authenticator *auth.Authenticator, next http.Handler, allow AllowRoute) (http.Handler, error) {
	if provider == "" || authenticator == nil || next == nil || allow == nil {
		return nil, errors.New("complete Git listener configuration is required")
	}
	return http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		if !normalizedPath(request) {
			http.Error(response, "invalid Git route", http.StatusBadRequest)
			return
		}
		if request.Method == http.MethodGet && request.URL.Path == IdentityPath {
			if _, err := authenticator.AuthenticateRequest(request); err != nil {
				response.Header().Set("WWW-Authenticate", `Basic realm="brokerkit-git"`)
				http.Error(response, "authentication required", http.StatusUnauthorized)
				return
			}
			response.Header().Set("Cache-Control", "no-store")
			response.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(response).Encode(map[string]string{"provider": provider})
			return
		}
		if !allow(request.Method, request.URL.Path) {
			http.NotFound(response, request)
			return
		}
		next.ServeHTTP(response, request)
	}), nil
}

func normalizedPath(request *http.Request) bool {
	value := request.URL.EscapedPath()
	if strings.Contains(strings.ToLower(value), "%2f") || strings.Contains(strings.ToLower(value), "%5c") {
		return false
	}
	return request.URL.RawPath == "" && request.URL.Path != "" && path.Clean(request.URL.Path) == request.URL.Path
}
