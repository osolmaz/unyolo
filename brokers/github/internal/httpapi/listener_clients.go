package httpapi

import (
	"net/http"
	"slices"
	"strings"
)

// Listener names the kind of listener that serves a handler.
type Listener int

const (
	// HostListener is the local Unix socket or the loopback Git listener.
	HostListener Listener = iota
	// SandboxListener is the TLS listener for agents in sandboxes.
	SandboxListener
)

// BindClients returns handler for one listener. The sandbox listener serves
// only sandbox clients, and every other listener refuses them, so a secret
// that a sandbox holds works on no other listener. A request without a valid
// credential passes through, and the handler answers it as before.
func (s *Server) BindClients(handler http.Handler, listener Listener) http.Handler {
	if len(s.sandboxClients) == 0 {
		return handler
	}
	return clientBinding{next: handler, server: s, sandbox: listener == SandboxListener}
}

type clientBinding struct {
	next    http.Handler
	server  *Server
	sandbox bool
}

func (b clientBinding) ServeHTTP(response http.ResponseWriter, request *http.Request) {
	client, err := b.server.control.Clients.AuthenticateHeader(bearerFromTokenScheme(request.Header.Get("Authorization")))
	if err == nil && slices.Contains(b.server.sandboxClients, client) != b.sandbox {
		http.Error(response, "this client cannot use this listener", http.StatusForbidden)
		return
	}
	b.next.ServeHTTP(response, request)
}

// bearerFromTokenScheme reads GitHub's "token" scheme, which the GitHub CLI
// sends to Enterprise hosts, as a bearer credential.
func bearerFromTokenScheme(header string) string {
	if scheme, value, found := strings.Cut(strings.TrimSpace(header), " "); found && strings.EqualFold(scheme, "token") {
		return "Bearer " + strings.TrimSpace(value)
	}
	return header
}
