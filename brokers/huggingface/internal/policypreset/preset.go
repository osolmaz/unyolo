// Package policypreset renders provider-owned Hugging Face policy presets.
package policypreset

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"slices"
	"strings"

	"github.com/osolmaz/brokerkit/brokers/huggingface/internal/opcatalog"
	"github.com/osolmaz/brokerkit/brokers/huggingface/internal/policy"
)

const (
	RequestAllAgentOperations = "request-all-agent-operations"
	ProfileVersion            = 1
	ManifestVersion           = 1
)

// Profile is the small, operator-editable input used to render a concrete
// broker policy. DeniedOperations is an exact override list.
type Profile struct {
	Version          int      `json:"version"`
	Preset           string   `json:"preset"`
	Clients          []string `json:"clients"`
	DeniedOperations []string `json:"denied_operations"`
}

// Manifest binds one generated policy to its profile and operation catalog.
type Manifest struct {
	Version         int                    `json:"version"`
	Preset          string                 `json:"preset"`
	CatalogDigest   string                 `json:"catalog_digest"`
	ProfileDigest   string                 `json:"profile_digest"`
	PolicyDigest    string                 `json:"policy_digest"`
	OperationCounts OperationCounts        `json:"operation_counts"`
	Operations      []OperationFingerprint `json:"operations"`
}

type OperationCounts struct {
	Total   int `json:"total"`
	Allow   int `json:"allow"`
	Request int `json:"request"`
	Deny    int `json:"deny"`
}

type OperationFingerprint struct {
	Name               string                        `json:"name"`
	OperationRevision  int                           `json:"operation_revision"`
	Effect             opcatalog.DefaultPolicyEffect `json:"effect"`
	Risk               opcatalog.Risk                `json:"risk"`
	AuthorizationMode  opcatalog.AuthorizationMode   `json:"authorization_mode"`
	MaxUses            int                           `json:"max_uses"`
	RequestTTLSeconds  int                           `json:"request_ttl_seconds"`
	ApprovalTTLSeconds int                           `json:"approval_ttl_seconds"`
}

type Artifacts struct {
	Profile      Profile
	Manifest     Manifest
	ProfileJSON  []byte
	PolicyJSON   []byte
	ManifestJSON []byte
}

type policyDocument struct {
	Rules []policyRule `json:"rules"`
}

type policyRule struct {
	ID          string           `json:"id"`
	Effect      string           `json:"effect"`
	Clients     []string         `json:"clients"`
	Operations  []string         `json:"operations"`
	Targets     []map[string]any `json:"targets"`
	GrantPolicy *ruleGrantPolicy `json:"grant_policy,omitempty"`
	Description string           `json:"description"`
}

type ruleGrantPolicy struct {
	Mode              string `json:"mode"`
	DefaultMinutes    int    `json:"default_minutes"`
	MaxMinutes        int    `json:"max_minutes"`
	RequestTTLMinutes int    `json:"request_ttl_minutes"`
	DefaultMaxUses    int    `json:"default_max_uses"`
	MaxUses           int    `json:"max_uses"`
}

// NewProfile creates the default profile for one or more broker clients.
func NewProfile(clients, deniedOperations []string) Profile {
	return Profile{
		Version: ProfileVersion, Preset: RequestAllAgentOperations,
		Clients: clients, DeniedOperations: deniedOperations,
	}
}

// ParseProfile strictly decodes and normalizes one profile.
func ParseProfile(data []byte) (Profile, error) {
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	var profile Profile
	if err := decoder.Decode(&profile); err != nil {
		return Profile{}, fmt.Errorf("parse policy profile: %w", err)
	}
	var trailing struct{}
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		return Profile{}, errors.New("parse policy profile: trailing content")
	}
	return normalizeProfile(profile)
}

// Render materializes a validated profile into deterministic policy artifacts.
func Render(input Profile) (Artifacts, error) {
	profile, err := normalizeProfile(input)
	if err != nil {
		return Artifacts{}, err
	}
	descriptors := opcatalog.MustAll()
	denied := make(map[string]bool, len(profile.DeniedOperations))
	for _, operation := range profile.DeniedOperations {
		denied[operation] = true
	}

	document := policyDocument{Rules: make([]policyRule, 0, len(descriptors))}
	manifest := Manifest{
		Version: ManifestVersion, Preset: profile.Preset,
		Operations: make([]OperationFingerprint, 0, len(descriptors)),
	}
	for _, descriptor := range descriptors {
		effect := descriptor.DefaultPolicyEffect
		if denied[descriptor.Name] {
			effect = opcatalog.DefaultEffectDeny
		}
		document.Rules = append(document.Rules, renderRule(profile.Clients, descriptor, effect))
		manifest.Operations = append(manifest.Operations, fingerprint(descriptor, effect))
		manifest.OperationCounts.add(effect)
	}
	manifest.OperationCounts.Total = len(descriptors)

	profileJSON, err := marshalCanonical(profile)
	if err != nil {
		return Artifacts{}, err
	}
	policyJSON, err := marshalCanonical(document)
	if err != nil {
		return Artifacts{}, err
	}
	if _, err := policy.Parse(policyJSON); err != nil {
		return Artifacts{}, fmt.Errorf("validate rendered policy: %w", err)
	}
	catalogJSON, err := json.Marshal(descriptors)
	if err != nil {
		return Artifacts{}, fmt.Errorf("encode catalog digest input: %w", err)
	}
	manifest.CatalogDigest = digest(catalogJSON)
	manifest.ProfileDigest = digest(profileJSON)
	manifest.PolicyDigest = digest(policyJSON)
	manifestJSON, err := marshalCanonical(manifest)
	if err != nil {
		return Artifacts{}, err
	}
	return Artifacts{
		Profile: profile, Manifest: manifest, ProfileJSON: profileJSON,
		PolicyJSON: policyJSON, ManifestJSON: manifestJSON,
	}, nil
}

func normalizeProfile(profile Profile) (Profile, error) {
	if profile.Version != ProfileVersion {
		return Profile{}, fmt.Errorf("policy profile version must be %d", ProfileVersion)
	}
	if profile.Preset != RequestAllAgentOperations {
		return Profile{}, fmt.Errorf("unknown Hugging Face policy preset %q", profile.Preset)
	}
	clients, err := normalizeExactValues("clients", profile.Clients)
	if err != nil {
		return Profile{}, err
	}
	denied, err := normalizeExactValues("denied_operations", profile.DeniedOperations)
	if err != nil && len(profile.DeniedOperations) > 0 {
		return Profile{}, err
	}
	for _, operation := range denied {
		if _, found := opcatalog.ByName(operation); !found {
			return Profile{}, fmt.Errorf("denied_operations contains unknown operation %q", operation)
		}
	}
	profile.Clients = clients
	profile.DeniedOperations = denied
	return profile, nil
}

func normalizeExactValues(field string, values []string) ([]string, error) {
	if len(values) == 0 {
		return nil, fmt.Errorf("%s must not be empty", field)
	}
	normalized := slices.Clone(values)
	for _, value := range normalized {
		if value == "" || strings.TrimSpace(value) != value {
			return nil, fmt.Errorf("%s contains an empty or whitespace-padded value", field)
		}
	}
	slices.Sort(normalized)
	for index := 1; index < len(normalized); index++ {
		if normalized[index] == normalized[index-1] {
			return nil, fmt.Errorf("%s contains duplicate values", field)
		}
	}
	return normalized, nil
}

func renderRule(clients []string, descriptor opcatalog.Descriptor, effect opcatalog.DefaultPolicyEffect) policyRule {
	target := map[string]any{"kind": descriptor.TargetKind, "owner": "*", "name": "*"}
	if descriptor.TargetKind == string(policy.KindRepo) {
		target["type"] = "*"
	}
	rule := policyRule{
		ID:     "preset-" + strings.ReplaceAll(descriptor.Name, ".", "-"),
		Effect: string(effect), Clients: clients, Operations: []string{descriptor.Name},
		Targets:     []map[string]any{target},
		Description: "Generated by Hugging Face policy preset " + RequestAllAgentOperations + ".",
	}
	if effect == opcatalog.DefaultEffectRequest {
		rule.GrantPolicy = grantPolicy(descriptor)
	}
	return rule
}

func grantPolicy(descriptor opcatalog.Descriptor) *ruleGrantPolicy {
	mode := string(policy.GrantModeWindow)
	if descriptor.AuthorizationMode == opcatalog.ModeExecution {
		mode = string(policy.GrantModeExecution)
	}
	maxMinutes := descriptor.ApprovalTTLSeconds / 60
	defaultMinutes := min(policy.DefaultGrantMinutes, maxMinutes)
	maxUses := descriptor.MaxUses
	if descriptor.AuthorizationMode == opcatalog.ModeExecution {
		maxUses = 1
	}
	return &ruleGrantPolicy{
		Mode: mode, DefaultMinutes: defaultMinutes, MaxMinutes: maxMinutes,
		RequestTTLMinutes: descriptor.RequestTTLSeconds / 60,
		DefaultMaxUses:    1, MaxUses: maxUses,
	}
}

func fingerprint(descriptor opcatalog.Descriptor, effect opcatalog.DefaultPolicyEffect) OperationFingerprint {
	return OperationFingerprint{
		Name: descriptor.Name, OperationRevision: descriptor.OperationRevision,
		Effect: effect, Risk: descriptor.Risk, AuthorizationMode: descriptor.AuthorizationMode,
		MaxUses: descriptor.MaxUses, RequestTTLSeconds: descriptor.RequestTTLSeconds,
		ApprovalTTLSeconds: descriptor.ApprovalTTLSeconds,
	}
}

func (counts *OperationCounts) add(effect opcatalog.DefaultPolicyEffect) {
	switch effect {
	case opcatalog.DefaultEffectAllow:
		counts.Allow++
	case opcatalog.DefaultEffectRequest:
		counts.Request++
	case opcatalog.DefaultEffectDeny:
		counts.Deny++
	}
}

func marshalCanonical(value any) ([]byte, error) {
	data, err := json.MarshalIndent(value, "", "  ")
	if err != nil {
		return nil, fmt.Errorf("encode policy artifact: %w", err)
	}
	return append(data, '\n'), nil
}

func digest(data []byte) string {
	sum := sha256.Sum256(data)
	return "sha256:" + hex.EncodeToString(sum[:])
}
