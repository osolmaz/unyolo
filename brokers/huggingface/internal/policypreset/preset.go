// Package policypreset adapts Hugging Face policy semantics to the shared
// managed policy artifact lifecycle.
package policypreset

import (
	"fmt"
	"strings"

	corepolicy "github.com/osolmaz/unyolo/authorization/policy"
	shared "github.com/osolmaz/unyolo/authorization/preset"
	"github.com/osolmaz/unyolo/brokers/huggingface/internal/opcatalog"
	"github.com/osolmaz/unyolo/brokers/huggingface/internal/policy"
)

const RequestAllAgentOperations = "request-all-agent-operations"

const (
	ProfileVersion  = shared.ProfileVersion
	ManifestVersion = shared.ManifestVersion
)

type Profile = shared.Profile
type ProtectedTarget = shared.ProtectedTarget
type Manifest = shared.Manifest
type OperationCounts = shared.OperationCounts
type OperationFingerprint = shared.OperationFingerprint
type Artifacts = shared.Artifacts
type DriftStatus = shared.DriftStatus
type DriftReport = shared.DriftReport

const (
	DriftCurrent  = shared.DriftCurrent
	DriftStale    = shared.DriftStale
	DriftModified = shared.DriftModified
	DriftInvalid  = shared.DriftInvalid
)

type renderer struct{}

type policyDocument struct {
	Rules []policyRule `json:"rules"`
}

type policyRule struct {
	ID             string                     `json:"id"`
	Effect         string                     `json:"effect"`
	Clients        []string                   `json:"clients"`
	Operations     []string                   `json:"operations"`
	Targets        []map[string]any           `json:"targets"`
	CredentialUses []corepolicy.CredentialUse `json:"credential_use,omitempty"`
	GrantPolicy    *ruleGrantPolicy           `json:"grant_policy,omitempty"`
	Description    string                     `json:"description"`
}

type ruleGrantPolicy struct {
	Mode              string `json:"mode"`
	DefaultMinutes    int    `json:"default_minutes"`
	MaxMinutes        int    `json:"max_minutes"`
	RequestTTLMinutes int    `json:"request_ttl_minutes"`
	DefaultMaxUses    int    `json:"default_max_uses"`
	MaxUses           int    `json:"max_uses"`
}

type authorizationMetadata struct {
	Risk                     opcatalog.Risk                `json:"risk"`
	DefaultAuthorizationMode opcatalog.AuthorizationMode   `json:"default_authorization_mode"`
	AuthorizationModes       []opcatalog.AuthorizationMode `json:"authorization_modes"`
	ExplicitOnly             bool                          `json:"explicit_only"`
	Sealed                   bool                          `json:"sealed"`
	Internal                 bool                          `json:"internal"`
	AgentFacing              bool                          `json:"agent_facing"`
	CredentialOutput         *string                       `json:"credential_output_kind,omitempty"`
	TargetKind               string                        `json:"target_kind"`
	TargetSchema             string                        `json:"target_schema,omitempty"`
	MaxUses                  int                           `json:"max_uses"`
	RequestTTLSeconds        int                           `json:"request_ttl_seconds"`
	ApprovalTTLSeconds       int                           `json:"approval_ttl_seconds"`
}

func (renderer) ProviderID() string { return "huggingface" }
func (renderer) PresetName() string { return RequestAllAgentOperations }

func (renderer) ValidateProfile(profile shared.Profile) error {
	for _, target := range profile.ProtectedTargets {
		if err := validateProtectedTarget(target); err != nil {
			return err
		}
	}
	return nil
}

func validateProtectedTarget(target shared.ProtectedTarget) error {
	switch target.Kind {
	case string(policy.KindRepo):
		if !validProtectedRepoType(target.Type) {
			return fmt.Errorf("protected repository %s/%s requires an exact type", target.Owner, target.Name)
		}
	case string(policy.KindBucket):
		if target.Type != "" {
			return fmt.Errorf("protected bucket %s/%s must not set type", target.Owner, target.Name)
		}
	default:
		return fmt.Errorf("protected target kind %q is unsupported", target.Kind)
	}
	return nil
}

func validProtectedRepoType(value string) bool {
	return value == "model" || value == "dataset" || value == "space" || value == "kernel"
}

func (renderer) Operations() ([]shared.Operation, error) {
	descriptors, err := opcatalog.All()
	if err != nil {
		return nil, err
	}
	operations := make([]shared.Operation, 0, len(descriptors))
	for _, descriptor := range descriptors {
		digest, err := shared.AuthorizationDigest(authorizationMetadata{
			Risk: descriptor.Risk, DefaultAuthorizationMode: descriptor.DefaultAuthorizationMode,
			AuthorizationModes: descriptor.AuthorizationModes,
			ExplicitOnly:       descriptor.ExplicitOnly, Sealed: descriptor.Sealed, Internal: descriptor.Internal,
			AgentFacing: descriptor.AgentFacing, CredentialOutput: descriptor.CredentialOutputKind,
			TargetKind: descriptor.TargetKind, TargetSchema: descriptor.TargetSchema, MaxUses: descriptor.MaxUses,
			RequestTTLSeconds: descriptor.RequestTTLSeconds, ApprovalTTLSeconds: descriptor.ApprovalTTLSeconds,
		})
		if err != nil {
			return nil, fmt.Errorf("fingerprint operation %s: %w", descriptor.Name, err)
		}
		defaultEffect := descriptor.DefaultPolicyEffect
		if descriptor.Implementation == opcatalog.StatusBlockedUpstream {
			defaultEffect = opcatalog.DefaultEffectDeny
		}
		operations = append(operations, shared.Operation{
			Name: descriptor.Name, OperationRevision: descriptor.OperationRevision,
			DefaultEffect: defaultEffect, AuthorizationDigest: digest,
		})
	}
	return operations, nil
}

func (renderer) RenderPolicy(profile shared.Profile, operations []shared.EffectiveOperation) ([]byte, error) {
	document := policyDocument{Rules: make([]policyRule, 0, len(operations)*(len(profile.ProtectedTargets)+1))}
	for index, target := range profile.ProtectedTargets {
		for _, operation := range operations {
			descriptor, found := opcatalog.ByName(operation.Name)
			if found && descriptor.TargetKind == target.Kind {
				document.Rules = append(document.Rules, renderProtectedRule(profile.Clients, index, target, descriptor))
			}
		}
	}
	for _, operation := range operations {
		descriptor, found := opcatalog.ByName(operation.Name)
		if !found {
			return nil, fmt.Errorf("operation %q disappeared during policy render", operation.Name)
		}
		if descriptor.Name == string(policy.OpGitFetch) {
			document.Rules = append(document.Rules, renderAnonymousFetchRule(profile.Clients, descriptor))
		}
		document.Rules = append(document.Rules, renderRule(profile.Clients, descriptor, operation.Effect))
	}
	return shared.MarshalCanonical(document)
}

func (renderer) ValidatePolicy(data []byte) error {
	_, err := policy.Parse(data)
	return err
}

func NewProfile(clients, deniedOperations []string) Profile {
	return shared.NewProfile(renderer{}, clients, deniedOperations)
}

func ParseProfile(data []byte) (Profile, error) { return shared.ParseProfile(renderer{}, data) }

func ParseManifest(data []byte) (Manifest, error) { return shared.ParseManifest(renderer{}, data) }

func ParseInstalledProfile(data []byte) (Profile, error) {
	return shared.ParseInstalledProfile(renderer{}, data)
}

func Render(profile Profile) (Artifacts, error) { return shared.Render(renderer{}, profile) }

func Check(profileData, manifestData, policyData []byte) DriftReport {
	return shared.Check(renderer{}, profileData, manifestData, policyData)
}

func renderProtectedRule(clients []string, index int, target shared.ProtectedTarget, descriptor opcatalog.Descriptor) policyRule {
	policyTarget := map[string]any{"kind": target.Kind, "owner": target.Owner, "name": target.Name}
	if target.Type != "" {
		policyTarget["type"] = target.Type
	}
	return policyRule{
		ID:     fmt.Sprintf("protected-%d-%s", index+1, strings.ReplaceAll(descriptor.Name, ".", "-")),
		Effect: string(shared.EffectDeny), Clients: clients, Operations: []string{descriptor.Name},
		Targets: []map[string]any{policyTarget}, Description: "Protected target deny generated by the Hugging Face policy preset.",
	}
}

func renderAnonymousFetchRule(clients []string, descriptor opcatalog.Descriptor) policyRule {
	target := map[string]any{"kind": descriptor.TargetKind, "type": "*", "owner": "*", "name": "*"}
	return policyRule{
		ID: "preset-git-fetch-anonymous", Effect: string(shared.EffectAllow),
		Clients: clients, Operations: []string{descriptor.Name}, Targets: []map[string]any{target},
		CredentialUses: []corepolicy.CredentialUse{corepolicy.CredentialUseNone},
		Description:    "Allow anonymous Git fetches that the upstream serves without a managed credential.",
	}
}

func renderRule(clients []string, descriptor opcatalog.Descriptor, effect shared.Effect) policyRule {
	target := map[string]any{"kind": descriptor.TargetKind, "owner": "*", "name": "*"}
	if descriptor.TargetKind == string(policy.KindRepo) {
		target["type"] = "*"
	}
	rule := policyRule{
		ID: "preset-" + strings.ReplaceAll(descriptor.Name, ".", "-"), Effect: string(effect),
		Clients: clients, Operations: []string{descriptor.Name}, Targets: []map[string]any{target},
		Description: "Generated by Hugging Face policy preset " + RequestAllAgentOperations + ".",
	}
	if effect == shared.EffectRequest {
		rule.GrantPolicy = grantPolicy(descriptor)
	}
	return rule
}

func grantPolicy(descriptor opcatalog.Descriptor) *ruleGrantPolicy {
	maxMinutes := descriptor.ApprovalTTLSeconds / 60
	return &ruleGrantPolicy{
		Mode:           string(descriptor.DefaultAuthorizationMode),
		DefaultMinutes: min(policy.DefaultGrantMinutes, maxMinutes), MaxMinutes: maxMinutes,
		RequestTTLMinutes: descriptor.RequestTTLSeconds / 60,
		DefaultMaxUses:    descriptor.MaxUses, MaxUses: descriptor.MaxUses,
	}
}
