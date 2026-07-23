// Package mcpgrant owns the provider-neutral, transcript-safe MCP grant
// projection layered over BrokerKit grant APIs.
package mcpgrant

import (
	"encoding/json"
	"errors"
	"strings"

	usebudget "github.com/osolmaz/brokerkit/authorization/budget"
)

const APIVersion = "brokerkit.io/mcp-grant/v1"

// Grant is the closed grant lifecycle document returned to MCP clients. Target
// and attribute values contain only the provider scope accepted at the public
// grant boundary; requester identity and approval authority are omitted.
type Grant struct {
	APIVersion    string          `json:"api_version"`
	ID            string          `json:"id"`
	RequestID     string          `json:"request_id,omitempty"`
	Status        string          `json:"status"`
	Operation     string          `json:"operation"`
	Target        json.RawMessage `json:"target"`
	Attrs         json.RawMessage `json:"attrs"`
	Mode          string          `json:"mode"`
	Minutes       int             `json:"minutes"`
	MaxUses       usebudget.Limit `json:"max_uses"`
	UsesRemaining int             `json:"uses_remaining"`
	UsedCount     int             `json:"used_count"`
	PendingUntil  *string         `json:"pending_until"`
	ExpiresAt     *string         `json:"expires_at"`
}

// Input supplies one provider grant projection.
type Input struct {
	ID            string
	RequestID     string
	Status        string
	Operation     string
	Target        any
	Attrs         any
	Mode          string
	Minutes       int
	MaxUses       usebudget.Limit
	UsesRemaining int
	UsedCount     int
	PendingUntil  *string
	ExpiresAt     *string
}

// Project validates and converts provider grant data to the closed MCP shape.
func Project(input Input) (Grant, error) {
	target, err := json.Marshal(input.Target)
	if err != nil {
		return Grant{}, errors.New("grant target is invalid")
	}
	attrs, err := json.Marshal(input.Attrs)
	if err != nil {
		return Grant{}, errors.New("grant attrs are invalid")
	}
	grant := Grant{
		APIVersion: APIVersion, ID: strings.TrimSpace(input.ID), RequestID: strings.TrimSpace(input.RequestID),
		Status: input.Status, Operation: strings.TrimSpace(input.Operation), Target: target, Attrs: attrs,
		Mode: input.Mode, Minutes: input.Minutes, MaxUses: input.MaxUses, UsesRemaining: input.UsesRemaining,
		UsedCount: input.UsedCount, PendingUntil: input.PendingUntil, ExpiresAt: input.ExpiresAt,
	}
	if err := validate(grant); err != nil {
		return Grant{}, err
	}
	return grant, nil
}

func validate(grant Grant) error {
	if !validGrantProjection(grant) {
		return errors.New("grant projection is invalid")
	}
	if grant.Mode != "window" && grant.Mode != "execution" {
		return errors.New("grant mode is invalid")
	}
	if !validStatus(grant.Status) {
		return errors.New("grant status is invalid")
	}
	if !validGrantScope(grant) {
		return errors.New("grant scope is invalid")
	}
	return nil
}

func validGrantProjection(grant Grant) bool {
	return grant.ID != "" && grant.Operation != "" && grant.Minutes >= 1 && grant.UsedCount >= 0 && grant.UsesRemaining >= -1
}

func validGrantScope(grant Grant) bool {
	return len(grant.Target) > 0 && string(grant.Target) != "null" && len(grant.Attrs) > 0 && string(grant.Attrs) != "null"
}

func validStatus(status string) bool {
	switch status {
	case "pending", "active", "denied", "expired", "consumed", "revoked", "canceled", "retained":
		return true
	default:
		return false
	}
}
