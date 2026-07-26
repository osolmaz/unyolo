// Package api defines the closed setup-component V1 protocol.
package api

import (
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"slices"
	"strings"
)

const (
	APIVersion         = "brokerkit.io/setup-component/v1"
	MaxFiles           = 256
	MaxActions         = 1024
	MaxCredentialSlots = 64
	MaxMessageBytes    = 16 * 1024 * 1024
)

var identifierPattern = regexp.MustCompile(`^[a-z0-9](?:[a-z0-9._-]{0,126}[a-z0-9])?$`)

// Action selects one fixed adapter operation.
type Action string

const (
	ActionValidate Action = "validate"
	ActionPlan     Action = "plan"
	ActionApply    Action = "apply"
	ActionVerify   Action = "verify"
	ActionRollback Action = "rollback"
)

// File is one nonsecret digest-bound profile file.
type File struct {
	Path   string `json:"path"`
	SHA256 string `json:"sha256"`
	Data   []byte `json:"data"`
}

// SecretDescriptor binds a logical slot to an inherited read-only descriptor.
type SecretDescriptor struct {
	Name   string `json:"name"`
	FD     int    `json:"fd"`
	Rotate bool   `json:"rotate,omitempty"`
}

// AgentBinding is one validated deployment agent available to a component.
type AgentBinding struct {
	ID       string `json:"id"`
	ClientID string `json:"client_id"`
	UnixUser string `json:"unix_user"`
	Home     string `json:"home"`
}

// Request is one bounded adapter request.
type Request struct {
	APIVersion       string             `json:"api_version"`
	Action           Action             `json:"action"`
	DeploymentDigest string             `json:"deployment_digest"`
	PlanDigest       string             `json:"plan_digest,omitempty"`
	ComponentID      string             `json:"component_id"`
	Profile          json.RawMessage    `json:"profile"`
	Files            []File             `json:"files"`
	Agents           []AgentBinding     `json:"agents,omitempty"`
	Secrets          []SecretDescriptor `json:"secrets,omitempty"`
	RollbackHandle   string             `json:"rollback_handle,omitempty"`
}

// Resource identifies one adapter-owned host resource.
type Resource struct {
	Kind string `json:"kind"`
	ID   string `json:"id"`
	Path string `json:"path,omitempty"`
}

// PlannedAction is one secret-safe component change.
type PlannedAction struct {
	ID            string   `json:"id"`
	Type          string   `json:"type"`
	Risk          string   `json:"risk"`
	Resource      Resource `json:"resource"`
	CurrentDigest string   `json:"current_digest,omitempty"`
	DesiredDigest string   `json:"desired_digest,omitempty"`
	Restart       bool     `json:"restart,omitempty"`
	DependsOn     []string `json:"depends_on,omitempty"`
}

// CredentialAction reports intent without credential metadata.
type CredentialAction struct {
	Slot   string `json:"slot"`
	Action string `json:"action"`
}

// Response is one closed redacted adapter result.
type Response struct {
	APIVersion     string             `json:"api_version"`
	ComponentID    string             `json:"component_id"`
	Status         string             `json:"status"`
	PlanDigest     string             `json:"plan_digest,omitempty"`
	Actions        []PlannedAction    `json:"actions,omitempty"`
	Credentials    []CredentialAction `json:"credentials,omitempty"`
	RollbackHandle string             `json:"rollback_handle,omitempty"`
	Verification   []string           `json:"verification,omitempty"`
	ProviderFacts  json.RawMessage    `json:"provider_facts,omitempty"`
	BlockedReason  string             `json:"blocked_reason,omitempty"`
}

// Validate checks request bounds and protocol invariants.
//
//nolint:cyclop // The closed wire request is validated field by field at its trust boundary.
func (request Request) Validate() error {
	if request.APIVersion != APIVersion || !identifierPattern.MatchString(request.ComponentID) {
		return errors.New("setup-component request identity is invalid")
	}
	if !slices.Contains([]Action{ActionValidate, ActionPlan, ActionApply, ActionVerify, ActionRollback}, request.Action) {
		return errors.New("setup-component action is invalid")
	}
	if !validDigest(request.DeploymentDigest) || (request.PlanDigest != "" && !validDigest(request.PlanDigest)) {
		return errors.New("setup-component request digest is invalid")
	}
	if slices.Contains([]Action{ActionApply, ActionRollback}, request.Action) && request.PlanDigest == "" {
		return errors.New("setup-component mutation requires a plan digest")
	}
	if request.Action == ActionRollback && !validHandle(request.RollbackHandle) {
		return errors.New("setup-component rollback requires a valid handle")
	}
	if request.Action != ActionApply && len(request.Secrets) != 0 {
		return errors.New("setup-component secrets are accepted only during apply")
	}
	if len(request.Profile) == 0 || len(request.Profile) > MaxMessageBytes || len(request.Files) > MaxFiles || len(request.Secrets) > MaxCredentialSlots || len(request.Agents) > 32 {
		return errors.New("setup-component request exceeds size limits")
	}
	seenFiles, seenSlots, seenFDs, seenAgents := map[string]bool{}, map[string]bool{}, map[int]bool{}, map[string]bool{}
	for _, file := range request.Files {
		if strings.TrimSpace(file.Path) == "" || !validDigest(file.SHA256) || file.SHA256 != digest(file.Data) || len(file.Data) > MaxMessageBytes || seenFiles[file.Path] {
			return errors.New("setup-component file is invalid or duplicated")
		}
		seenFiles[file.Path] = true
	}
	for _, agent := range request.Agents {
		if !identifierPattern.MatchString(agent.ID) || !identifierPattern.MatchString(agent.ClientID) || strings.TrimSpace(agent.UnixUser) == "" ||
			!strings.HasPrefix(agent.Home, "/") || seenAgents[agent.ID] {
			return errors.New("setup-component agent binding is invalid or duplicated")
		}
		seenAgents[agent.ID] = true
	}
	for _, secret := range request.Secrets {
		if !identifierPattern.MatchString(secret.Name) || secret.FD < 3 || seenSlots[secret.Name] || seenFDs[secret.FD] {
			return errors.New("setup-component secret descriptor is invalid or duplicated")
		}
		seenSlots[secret.Name], seenFDs[secret.FD] = true, true
	}
	return nil
}

// Validate checks response bounds and redacted structure.
//
//nolint:cyclop // The closed wire response is validated field by field at its trust boundary.
func (response Response) Validate() error {
	if response.APIVersion != APIVersion || !identifierPattern.MatchString(response.ComponentID) {
		return errors.New("setup-component response identity is invalid")
	}
	if !slices.Contains([]string{"valid", "planned", "applied", "verified", "rolled_back", "blocked"}, response.Status) {
		return errors.New("setup-component response status is invalid")
	}
	if len(response.Actions) > MaxActions || len(response.Credentials) > MaxCredentialSlots || len(response.Verification) > MaxActions ||
		len(response.ProviderFacts) > MaxMessageBytes || len(response.BlockedReason) > 4096 {
		return errors.New("setup-component response exceeds size limits")
	}
	if response.PlanDigest != "" && !validDigest(response.PlanDigest) {
		return errors.New("setup-component plan digest is invalid")
	}
	if slices.Contains([]string{"planned", "applied", "blocked", "rolled_back"}, response.Status) && response.PlanDigest == "" {
		return errors.New("setup-component response requires a plan digest")
	}
	seen := map[string]bool{}
	for _, action := range response.Actions {
		if !identifierPattern.MatchString(action.ID) || seen[action.ID] || !validRisk(action.Risk) || strings.TrimSpace(action.Type) == "" ||
			strings.TrimSpace(action.Resource.Kind) == "" || strings.TrimSpace(action.Resource.ID) == "" ||
			!validOptionalDigest(action.CurrentDigest) || !validOptionalDigest(action.DesiredDigest) {
			return errors.New("setup-component planned action is invalid or duplicated")
		}
		seen[action.ID] = true
	}
	if response.RollbackHandle != "" && !validHandle(response.RollbackHandle) {
		return errors.New("setup-component rollback handle is invalid")
	}
	for _, evidence := range response.Verification {
		if strings.TrimSpace(evidence) == "" || len(evidence) > 4096 {
			return errors.New("setup-component verification evidence is invalid")
		}
	}
	if len(response.ProviderFacts) != 0 && !json.Valid(response.ProviderFacts) {
		return errors.New("setup-component provider facts are invalid")
	}
	for _, credential := range response.Credentials {
		if !identifierPattern.MatchString(credential.Slot) || !slices.Contains([]string{"install", "retain", "rotate", "remove"}, credential.Action) {
			return fmt.Errorf("setup-component credential action for %q is invalid", credential.Slot)
		}
	}
	return nil
}

func digest(value []byte) string {
	return fmt.Sprintf("sha256:%x", sha256.Sum256(value))
}

func validOptionalDigest(value string) bool {
	return value == "" || validDigest(value)
}

func validHandle(value string) bool {
	return identifierPattern.MatchString(value) && len(value) <= 128
}

func validRisk(value string) bool {
	return slices.Contains([]string{"low", "medium", "high", "critical"}, value)
}

func validDigest(value string) bool {
	return len(value) == 71 && strings.HasPrefix(value, "sha256:") && isLowerHex(value[7:])
}

func isLowerHex(value string) bool {
	for _, char := range value {
		if (char < '0' || char > '9') && (char < 'a' || char > 'f') {
			return false
		}
	}
	return true
}
