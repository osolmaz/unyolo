// Package policypreset adapts GitHub authorization semantics to the shared
// managed policy artifact lifecycle.
package policypreset

import (
	"fmt"
	"slices"
	"strings"

	usebudget "github.com/osolmaz/unyolo/authorization/budget"
	corepolicy "github.com/osolmaz/unyolo/authorization/policy"
	shared "github.com/osolmaz/unyolo/authorization/preset"
	"github.com/osolmaz/unyolo/brokers/github/internal/opbinding"
	"github.com/osolmaz/unyolo/brokers/github/internal/opcatalog"
	"github.com/osolmaz/unyolo/brokers/github/internal/policy"
	"github.com/osolmaz/unyolo/brokers/github/internal/targetregistry"
)

const RequestAllAgentOperations = "request-all-agent-operations"

const (
	ProfileVersion  = shared.ProfileVersion
	ManifestVersion = shared.ManifestVersion
)

type Profile = shared.Profile
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

type authorizationMetadata struct {
	Descriptor opcatalog.Descriptor      `json:"descriptor"`
	Bindings   []opbinding.Binding       `json:"bindings"`
	Target     targetregistry.Descriptor `json:"target"`
	Attributes []string                  `json:"policy_attributes"`
}

func (renderer) ProviderID() string { return "github" }
func (renderer) PresetName() string { return RequestAllAgentOperations }

func (renderer) Operations() ([]shared.Operation, error) {
	descriptors, err := opcatalog.All()
	if err != nil {
		return nil, err
	}
	targets, err := targetregistry.All()
	if err != nil {
		return nil, err
	}
	bindings, err := opbinding.All()
	if err != nil {
		return nil, err
	}
	operations, err := buildOperations(descriptors, indexTargets(targets), indexBindings(bindings))
	if err != nil {
		return nil, err
	}
	protocol, err := buildProtocolOperations()
	if err != nil {
		return nil, err
	}
	operations = append(operations, protocol...)
	slices.SortFunc(operations, func(a, b shared.Operation) int { return strings.Compare(a.Name, b.Name) })
	return operations, nil
}

type protocolOperation struct {
	name   policy.Operation
	effect opcatalog.DefaultPolicyEffect
}

// protocolOperations are the Git smart-HTTP and GitHub-compatible GraphQL read
// operations, which the REST catalog does not cover. Each default effect
// matches the REST operations that read or change the same data, so an agent
// gets the same answer through Git, GraphQL, and REST.
var protocolOperations = []protocolOperation{
	{policy.OperationGitFetch, opcatalog.DefaultEffectAllow},
	{policy.OperationGitLFSWrite, opcatalog.DefaultEffectRequest},
	{policy.OperationGitPushAdvertise, opcatalog.DefaultEffectAllow},
	{policy.OperationGitPushBranchCreate, opcatalog.DefaultEffectRequest},
	{policy.OperationGitPushFastForward, opcatalog.DefaultEffectRequest},
	{policy.OperationGitPushForce, opcatalog.DefaultEffectRequest},
	{policy.OperationGitRefDelete, opcatalog.DefaultEffectRequest},
	{policy.OperationGitTagUpdate, opcatalog.DefaultEffectRequest},
	{policy.OperationGraphQLRead, opcatalog.DefaultEffectAllow},
}

func buildProtocolOperations() ([]shared.Operation, error) {
	registry, err := policy.CatalogRegistry()
	if err != nil {
		return nil, err
	}
	operations := make([]shared.Operation, 0, len(protocolOperations))
	for _, protocol := range protocolOperations {
		spec, found := registry.Operation(string(protocol.name))
		if !found {
			return nil, fmt.Errorf("protocol operation %q is not registered", protocol.name)
		}
		digest, err := shared.AuthorizationDigest(spec)
		if err != nil {
			return nil, fmt.Errorf("fingerprint operation %s: %w", protocol.name, err)
		}
		operations = append(operations, shared.Operation{Name: string(protocol.name), OperationRevision: 1,
			DefaultEffect: protocol.effect, AuthorizationDigest: digest})
	}
	return operations, nil
}

func isProtocolOperation(name string) bool {
	return slices.ContainsFunc(protocolOperations, func(protocol protocolOperation) bool { return string(protocol.name) == name })
}

func indexTargets(targets []targetregistry.Descriptor) map[string]targetregistry.Descriptor {
	targetByKind := make(map[string]targetregistry.Descriptor, len(targets))
	for _, target := range targets {
		targetByKind[target.Kind] = target
	}
	return targetByKind
}

func indexBindings(bindings []opbinding.Binding) map[string][]opbinding.Binding {
	bindingsByOperation := make(map[string][]opbinding.Binding, len(bindings))
	for _, binding := range bindings {
		bindingsByOperation[binding.Operation] = append(bindingsByOperation[binding.Operation], binding)
	}
	return bindingsByOperation
}

func buildOperations(descriptors []opcatalog.Descriptor, targetByKind map[string]targetregistry.Descriptor, bindingsByOperation map[string][]opbinding.Binding) ([]shared.Operation, error) {
	operations := make([]shared.Operation, 0, len(descriptors))
	for _, descriptor := range descriptors {
		operation, err := buildOperation(descriptor, targetByKind[descriptor.TargetKind], bindingsByOperation[descriptor.Name])
		if err != nil {
			return nil, err
		}
		operations = append(operations, operation)
	}
	return operations, nil
}

func buildOperation(descriptor opcatalog.Descriptor, target targetregistry.Descriptor, bindings []opbinding.Binding) (shared.Operation, error) {
	digest, err := shared.AuthorizationDigest(authorizationMetadata{
		Descriptor: descriptor, Bindings: bindings, Target: target, Attributes: policyAttributes(descriptor.Name),
	})
	if err != nil {
		return shared.Operation{}, fmt.Errorf("fingerprint operation %s: %w", descriptor.Name, err)
	}
	return shared.Operation{Name: descriptor.Name, OperationRevision: descriptor.OperationRevision,
		DefaultEffect: descriptor.DefaultPolicyEffect, AuthorizationDigest: digest}, nil
}

func policyAttributes(operation string) []string {
	return opbinding.AuthorizationAttributes(operation)
}

func (renderer) RenderPolicy(profile shared.Profile, operations []shared.EffectiveOperation) ([]byte, error) {
	scope := policy.Scope{Rules: make([]policy.Rule, 0, len(operations)+1)}
	for _, operation := range operations {
		rule, err := presetRule(profile.Clients, operation)
		if err != nil {
			return nil, err
		}
		scope.Rules = append(scope.Rules, rule)
	}
	scope.Rules = append(scope.Rules, transportAnonymousRule(profile.Clients))
	if _, err := policy.New(scope); err != nil {
		return nil, err
	}
	return shared.MarshalCanonical(scope)
}

func presetRule(clients []string, operation shared.EffectiveOperation) (policy.Rule, error) {
	rule := policy.Rule{
		ID: "preset-" + strings.ReplaceAll(operation.Name, ".", "-"), Effect: policy.Effect(operation.Effect),
		Clients: clients, Operations: []policy.Operation{policy.Operation(operation.Name)},
	}
	if descriptor, found := opcatalog.ByName(operation.Name); found {
		rule.Targets = []policy.Target{wildcardTarget(descriptor.TargetKind)}
		return rule, nil
	}
	if !isProtocolOperation(operation.Name) {
		return policy.Rule{}, fmt.Errorf("operation %q disappeared during policy render", operation.Name)
	}
	rule.Targets = []policy.Target{wildcardTarget("repo")}
	if rule.Effect == policy.EffectRequest {
		rule.GrantPolicy = transportGrantPolicy()
	}
	return rule, nil
}

func transportAnonymousRule(clients []string) policy.Rule {
	return policy.Rule{
		ID: "preset-git-fetch-anonymous", Effect: policy.EffectAllow,
		Clients: clients, Operations: []policy.Operation{policy.OperationGitFetch},
		Targets:        []policy.Target{wildcardTarget("repo")},
		CredentialUses: []corepolicy.CredentialUse{corepolicy.CredentialUseNone},
	}
}

// transportGrantPolicy bounds one Git or GraphQL approval to a one-hour
// session window with a fifteen-minute approval wait, generous enough for
// clone, fetch, LFS transfers, pushes, and GitHub CLI reads of the approved
// repository.
func transportGrantPolicy() *corepolicy.GrantPolicy {
	return &corepolicy.GrantPolicy{
		Mode: string(corepolicy.GrantModeWindow), DefaultMinutes: 60, MaxMinutes: 10080, RequestTTLMinutes: 15,
		DefaultMaxUses: usebudget.MaxFiniteUses, MaxUses: usebudget.MaxFiniteUses,
	}
}

func wildcardTarget(kind string) policy.Target {
	target := policy.Target{Kind: kind}
	if kind == "repo" {
		target.Owner, target.Name = "*", "*"
	}
	return target
}

func (renderer) ValidatePolicy(data []byte) error {
	_, err := policy.Parse(data)
	return err
}

func NewProfile(clients, deniedOperations []string) Profile {
	return shared.NewProfile(renderer{}, clients, deniedOperations)
}

func ParseProfile(data []byte) (Profile, error)   { return shared.ParseProfile(renderer{}, data) }
func ParseManifest(data []byte) (Manifest, error) { return shared.ParseManifest(renderer{}, data) }
func ParseInstalledProfile(data []byte) (Profile, error) {
	return shared.ParseInstalledProfile(renderer{}, data)
}
func Render(profile Profile) (Artifacts, error) { return shared.Render(renderer{}, profile) }
func Check(profileData, manifestData, policyData []byte) DriftReport {
	return shared.Check(renderer{}, profileData, manifestData, policyData)
}
