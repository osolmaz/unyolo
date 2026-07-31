// Package pairingserver assembles server-side pairing invitations and drives
// the ready → activate → verified transitions through the local control API.
//
// This package is intentionally minimal and free of terminal or session
// coupling so it can be exercised in unit tests and wired into the wizard
// coordinator once the pairing service has a signed release component.
package pairingserver

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"time"

	pairingcontrol "github.com/osolmaz/unyolo/internal/pairing/control"
	pairingv1 "github.com/osolmaz/unyolo/protocol/pairing"
)

// DefaultInvitationLifetime is the recommended maximum invitation lifetime.
const DefaultInvitationLifetime = 10 * time.Minute

// BrokerBinding describes one broker connection the invitation will ship. It
// is populated from an installation snapshot before the invitation is
// created.
type BrokerBinding struct {
	BrokerName  string
	ClientID    string
	Endpoint    string
	GitEndpoint string
	ServerName  string
}

// InvitationRequest describes one reviewed remote connection.
type InvitationRequest struct {
	ID                 string
	PublicEndpoint     string
	PublicServerName   string
	CACertificate      []byte
	InvitationLifetime time.Duration
	Bindings           []BrokerBinding
}

// Invitation represents the material produced for the client.
type Invitation struct {
	Encoded   string
	PairingID string
	ExpiresAt time.Time
}

// Server drives one remote pairing exchange.
type Server struct {
	Control *pairingcontrol.Client
	Now     func() time.Time
}

// Create composes a fresh invitation. Every broker binding must be present
// in the reviewed installation. The bundle is populated with generated
// per-connection secrets; provider credentials never enter the bundle.
func (server *Server) Create(ctx context.Context, request InvitationRequest) (Invitation, error) {
	if server == nil || server.Control == nil {
		return Invitation{}, errors.New("pairing server is not configured")
	}
	if request.ID == "" || len(request.Bindings) == 0 || len(request.CACertificate) == 0 {
		return Invitation{}, errors.New("invitation request is invalid")
	}
	connections := make([]pairingv1.BrokerConnection, 0, len(request.Bindings))
	for _, binding := range request.Bindings {
		secret, err := randomSecret()
		if err != nil {
			return Invitation{}, err
		}
		connections = append(connections, pairingv1.BrokerConnection{
			BrokerName: binding.BrokerName, ClientID: binding.ClientID, Endpoint: binding.Endpoint,
			GitEndpoint: binding.GitEndpoint, Secret: secret, ServerName: binding.ServerName,
		})
	}
	lifetime := request.InvitationLifetime
	if lifetime <= 0 || lifetime > DefaultInvitationLifetime {
		lifetime = DefaultInvitationLifetime
	}
	expires := server.now().Add(lifetime)
	encoded, err := server.Control.Create(ctx, pairingcontrol.InvitationOptions{
		ID: request.ID, Endpoint: request.PublicEndpoint, CACertificate: request.CACertificate,
		ServerName: request.PublicServerName, ExpiresAt: expires,
		Bundle: pairingv1.Bundle{Connections: connections},
	})
	if err != nil {
		return Invitation{}, err
	}
	return Invitation{Encoded: encoded, PairingID: request.ID, ExpiresAt: expires.UTC()}, nil
}

// WaitForReady polls the local control endpoint until the remote client
// reports ready or the context ends. It returns cancelled when the invitation
// expires or is revoked.
func (server *Server) WaitForReady(ctx context.Context, id string, poll time.Duration) error {
	if poll <= 0 {
		poll = 500 * time.Millisecond
	}
	ticker := time.NewTicker(poll)
	defer ticker.Stop()
	for {
		state, err := server.Control.State(ctx, id)
		if err == nil && state.State == "ready" {
			return nil
		}
		if err == nil && (state.State == "expired" || state.State == "revoked") {
			return fmt.Errorf("pairing was cancelled before ready (state=%s)", state.State)
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-ticker.C:
		}
	}
}

// Activate authorizes the reviewed connection. It must be called only after
// the server-side apply plan installs the broker client entries and restarts
// the affected brokers.
func (server *Server) Activate(ctx context.Context, id string) error {
	_, err := server.Control.Activate(ctx, id)
	return err
}

// Revoke cancels a pending invitation. It refuses to touch an activated
// pairing; a connection-removal plan is required in that case.
func (server *Server) Revoke(ctx context.Context, id string) error {
	return server.Control.Revoke(ctx, id)
}

func (server *Server) now() time.Time {
	if server.Now != nil {
		return server.Now().UTC()
	}
	return time.Now().UTC()
}

func randomSecret() (string, error) {
	value := make([]byte, 32)
	if _, err := rand.Read(value); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(value), nil
}
