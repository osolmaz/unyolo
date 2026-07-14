package policy

import (
	"slices"
	"sync"

	"github.com/osolmaz/brokerkit/brokers/github/internal/opbinding"
	"github.com/osolmaz/brokerkit/brokers/github/internal/opcatalog"
	"github.com/osolmaz/brokerkit/brokers/github/internal/targetregistry"
	corepolicy "github.com/osolmaz/brokerkit/policy"
)

var baseCatalogAttributeNames = []string{
	"actor_id", "actor_login", "base_ref", "environment", "head_ref", "label", "merge_method",
	"path", "permission", "ref", "release_state", "resource_id", "role", "visibility", "workflow", "workflow_ref",
	"credential_kind", "credential_slot",
}

var catalogAttributesOnce sync.Once
var catalogAttributeNames []string
var operationCatalogAttributes map[string][]string
var catalogAttributesErr error

// CatalogRegistry is the generated stage-3 policy vocabulary. The current
// executor cutover continues to use registry() until the later lifecycle stage.
//
//nolint:cyclop // Descriptor policy metadata is translated through one fail-closed registry boundary.
func CatalogRegistry() (corepolicy.Registry, error) {
	descriptors, err := opcatalog.All()
	if err != nil {
		return corepolicy.Registry{}, err
	}
	targets, err := targetregistry.All()
	if err != nil {
		return corepolicy.Registry{}, err
	}
	operations := make(map[string]corepolicy.OperationSpec, len(descriptors))
	for _, descriptor := range descriptors {
		if !descriptor.AgentFacing {
			continue
		}
		operations[descriptor.Name] = corepolicy.OperationSpec{TargetKinds: []string{descriptor.TargetKind}, Attrs: catalogAttributesForOperation(descriptor.Name),
			Grantable: true, GrantMode: map[bool]corepolicy.GrantMode{true: corepolicy.GrantModeExecution, false: corepolicy.GrantModeWindow}[descriptor.AuthorizationMode == opcatalog.ModeExecution]}
	}
	for name, spec := range protocolOperationSpecs() {
		operations[string(name)] = spec
	}
	targetSpecs := make(map[string]corepolicy.TargetSpec, len(targets))
	for _, target := range targets {
		fields := make(map[string]corepolicy.FieldSpec, len(target.PolicyFields))
		for _, name := range target.PolicyFields {
			fields[name] = corepolicy.FieldSpec{Required: target.Kind == "repo" && (name == "owner" || name == "name")}
		}
		targetSpecs[target.Kind] = corepolicy.TargetSpec{Fields: fields}
	}
	attributeNames := CatalogAttributeNames()
	attrs := make(map[string]corepolicy.AttrSpec, len(attributeNames))
	for _, name := range attributeNames {
		attrs[name] = corepolicy.AttrSpec{}
	}
	return corepolicy.Registry{Operations: operations, Targets: targetSpecs, Attrs: attrs}, nil
}

func protocolOperationSpecs() map[Operation]corepolicy.OperationSpec {
	return map[Operation]corepolicy.OperationSpec{
		OperationGitFetch:             {TargetKinds: []string{"repo"}},
		OperationGitPushAdvertise:     {TargetKinds: []string{"repo"}},
		OperationGitPushBranchCreate:  {TargetKinds: []string{"repo"}, Attrs: []string{"ref"}, Grantable: true, GrantMode: corepolicy.GrantModeWindow},
		OperationGitPushFastForward:   {TargetKinds: []string{"repo"}, Attrs: []string{"ref"}, Grantable: true, GrantMode: corepolicy.GrantModeWindow},
		OperationGitPushForce:         {TargetKinds: []string{"repo"}, Attrs: []string{"ref"}, Grantable: true, GrantMode: corepolicy.GrantModeWindow},
		OperationGitRefDelete:         {TargetKinds: []string{"repo"}, Attrs: []string{"ref"}, Grantable: true, GrantMode: corepolicy.GrantModeWindow},
		OperationGitTagUpdate:         {TargetKinds: []string{"repo"}, Attrs: []string{"ref"}, Grantable: true, GrantMode: corepolicy.GrantModeWindow},
		OperationWebhookGitHubReceive: {TargetKinds: []string{"repo"}},
	}
}

func catalogAttributesForOperation(operation string) []string {
	if err := loadCatalogAttributes(); err != nil {
		panic(err)
	}
	return slices.Clone(operationCatalogAttributes[operation])
}

func CatalogAttributeNames() []string {
	if err := loadCatalogAttributes(); err != nil {
		panic(err)
	}
	return slices.Clone(catalogAttributeNames)
}

func loadCatalogAttributes() error {
	catalogAttributesOnce.Do(func() {
		catalogAttributeNames = append([]string(nil), baseCatalogAttributeNames...)
		operationCatalogAttributes = map[string][]string{}
		descriptors, err := opcatalog.All()
		if err != nil {
			catalogAttributesErr = err
			return
		}
		for _, descriptor := range descriptors {
			operationCatalogAttributes[descriptor.Name] = append([]string(nil), baseCatalogAttributeNames...)
		}
		bindings, err := opbinding.All()
		if err != nil {
			catalogAttributesErr = err
			return
		}
		for _, binding := range bindings {
			for _, parameter := range binding.AuthorizationParameters {
				catalogAttributeNames = append(catalogAttributeNames, parameter.Attribute)
				operationCatalogAttributes[binding.Operation] = append(operationCatalogAttributes[binding.Operation], parameter.Attribute)
			}
		}
		slices.Sort(catalogAttributeNames)
		catalogAttributeNames = slices.Compact(catalogAttributeNames)
		for operation, attributes := range operationCatalogAttributes {
			slices.Sort(attributes)
			operationCatalogAttributes[operation] = slices.Compact(attributes)
		}
	})
	return catalogAttributesErr
}
