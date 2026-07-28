// Package policypreset adapts GitHub authorization semantics to the shared
// managed policy artifact lifecycle.
package policypreset

import (
	"fmt"
	"strings"

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
	return buildOperations(descriptors, indexTargets(targets), indexBindings(bindings))
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
	scope := policy.Scope{Rules: make([]policy.Rule, 0, len(operations))}
	for _, operation := range operations {
		descriptor, found := opcatalog.ByName(operation.Name)
		if !found {
			return nil, fmt.Errorf("operation %q disappeared during policy render", operation.Name)
		}
		scope.Rules = append(scope.Rules, policy.Rule{
			ID: "preset-" + strings.ReplaceAll(operation.Name, ".", "-"), Effect: policy.Effect(operation.Effect),
			Clients: profile.Clients, Operations: []policy.Operation{policy.Operation(operation.Name)},
			Targets: []policy.Target{wildcardTarget(descriptor.TargetKind)},
		})
	}
	if _, err := policy.New(scope); err != nil {
		return nil, err
	}
	return shared.MarshalCanonical(scope)
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
