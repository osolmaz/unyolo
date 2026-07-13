package policy

import (
	"github.com/osolmaz/brokerkit/brokers/github/internal/opcatalog"
	"github.com/osolmaz/brokerkit/brokers/github/internal/targetregistry"
	corepolicy "github.com/osolmaz/brokerkit/policy"
)

var catalogAttributeNames = []string{
	"actor_id", "actor_login", "base_ref", "environment", "head_ref", "label", "merge_method",
	"path", "permission", "ref", "release_state", "resource_id", "role", "visibility", "workflow", "workflow_ref",
}

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
	operations := make(map[string]corepolicy.OperationSpec, len(descriptors))
	for _, descriptor := range descriptors {
		if !descriptor.AgentFacing {
			continue
		}
		operations[descriptor.Name] = corepolicy.OperationSpec{TargetKinds: []string{descriptor.TargetKind}, Attrs: catalogAttributeNames,
			Grantable: true, GrantMode: map[bool]corepolicy.GrantMode{true: corepolicy.GrantModeExecution, false: corepolicy.GrantModeWindow}[descriptor.AuthorizationMode == opcatalog.ModeExecution]}
	}
	targetSpecs := make(map[string]corepolicy.TargetSpec, len(targets))
	for _, target := range targets {
		fields := make(map[string]corepolicy.FieldSpec, len(target.PolicyFields))
		for _, name := range target.PolicyFields {
			fields[name] = corepolicy.FieldSpec{Required: name == "kind"}
		}
		targetSpecs[target.Kind] = corepolicy.TargetSpec{Fields: fields}
	}
	attrs := make(map[string]corepolicy.AttrSpec, len(catalogAttributeNames))
	for _, name := range catalogAttributeNames {
		attrs[name] = corepolicy.AttrSpec{}
	}
	return corepolicy.Registry{Operations: operations, Targets: targetSpecs, Attrs: attrs}, nil
}

func CatalogAttributeNames() []string { return append([]string(nil), catalogAttributeNames...) }
