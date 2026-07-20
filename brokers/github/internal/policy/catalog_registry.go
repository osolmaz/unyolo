package policy

import (
	"slices"
	"sync"

	corepolicy "github.com/osolmaz/brokerkit/authorization/policy"
	"github.com/osolmaz/brokerkit/brokers/github/internal/opbinding"
	"github.com/osolmaz/brokerkit/brokers/github/internal/opcatalog"
	"github.com/osolmaz/brokerkit/brokers/github/internal/targetregistry"
)

var baseCatalogAttributeNames = []string{
	"actor_id", "actor_login", "base_ref", "environment", "head_ref", "label", "merge_method",
	"path", "permission", "ref", "release_state", "resource_id", "resource_name", "resource_owner", "role", "visibility", "workflow", "workflow_ref",
	"credential_kind", "credential_slot",
}

var catalogAttributesOnce sync.Once
var catalogAttributeNames []string
var operationCatalogAttributes map[string][]string
var catalogAttributesErr error

// CatalogRegistry is the generated stage-3 policy vocabulary. The current
// executor cutover continues to use registry() until the later lifecycle stage.
func CatalogRegistry() (corepolicy.Registry, error) {
	descriptors, err := opcatalog.All()
	if err != nil {
		return corepolicy.Registry{}, err
	}
	targets, err := targetregistry.All()
	if err != nil {
		return corepolicy.Registry{}, err
	}
	return corepolicy.Registry{
		Operations: catalogOperationSpecs(descriptors),
		Targets:    catalogTargetSpecs(targets),
		Attrs:      catalogAttributeSpecs(),
	}, nil
}

func catalogOperationSpecs(descriptors []opcatalog.Descriptor) map[string]corepolicy.OperationSpec {
	operations := make(map[string]corepolicy.OperationSpec, len(descriptors))
	for _, descriptor := range descriptors {
		operations[descriptor.Name] = catalogOperationSpec(descriptor)
	}
	for name, spec := range protocolOperationSpecs() {
		operations[string(name)] = spec
	}
	return operations
}

func catalogOperationSpec(descriptor opcatalog.Descriptor) corepolicy.OperationSpec {
	spec := corepolicy.OperationSpec{TargetKinds: []string{descriptor.TargetKind}, Attrs: catalogAttributesForOperation(descriptor.Name), Grantable: descriptor.AgentFacing}
	if spec.Grantable {
		spec.GrantMode = map[bool]corepolicy.GrantMode{true: corepolicy.GrantModeExecution, false: corepolicy.GrantModeWindow}[descriptor.AuthorizationMode == opcatalog.ModeExecution]
	}
	return spec
}

func catalogTargetSpecs(targets []targetregistry.Descriptor) map[string]corepolicy.TargetSpec {
	targetSpecs := make(map[string]corepolicy.TargetSpec, len(targets))
	for _, target := range targets {
		targetSpecs[target.Kind] = corepolicy.TargetSpec{Fields: catalogTargetFields(target)}
	}
	return targetSpecs
}

func catalogTargetFields(target targetregistry.Descriptor) map[string]corepolicy.FieldSpec {
	fields := make(map[string]corepolicy.FieldSpec, len(target.PolicyFields))
	for _, name := range target.PolicyFields {
		fields[name] = corepolicy.FieldSpec{Required: target.Kind == "repo" && (name == "owner" || name == "name")}
	}
	return fields
}

func catalogAttributeSpecs() map[string]corepolicy.AttrSpec {
	names := CatalogAttributeNames()
	attrs := make(map[string]corepolicy.AttrSpec, len(names))
	for _, name := range names {
		spec := corepolicy.AttrSpec{}
		if name == "ref" || name == "base_ref" || name == "head_ref" {
			spec.Match = corepolicy.MatchRecursivePathGlob
		}
		attrs[name] = spec
	}
	return attrs
}

func protocolOperationSpecs() map[Operation]corepolicy.OperationSpec {
	return map[Operation]corepolicy.OperationSpec{
		OperationGitFetch:             {TargetKinds: []string{"repo"}},
		OperationGitLFSWrite:          {TargetKinds: []string{"repo"}},
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
