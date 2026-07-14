package schemaregistry_test

import (
	"testing"

	"github.com/osolmaz/brokerkit/brokers/github/internal/mcpprojection"
	"github.com/osolmaz/brokerkit/brokers/github/internal/opcatalog"
	"github.com/osolmaz/brokerkit/brokers/github/internal/schemaregistry"
	"github.com/osolmaz/brokerkit/capability"
)

func TestEveryAgentFacingGitHubSchemaIsTranscriptSafe(t *testing.T) {
	descriptors := opcatalog.MustAll()
	if len(descriptors) != opcatalog.ExpectedCount {
		t.Fatalf("catalog count = %d", len(descriptors))
	}
	for _, descriptor := range descriptors {
		if !descriptor.AgentFacing {
			continue
		}
		projection := mcpprojection.ForOperation(descriptor.Descriptor)
		target, arguments, _ := schemaregistry.InputSchemas(descriptor.Descriptor)
		assertProjectedSchemaSafe(t, descriptor.Name+" target", target, projection.Target)
		assertProjectedSchemaSafe(t, descriptor.Name+" arguments", arguments, projection.Arguments)

		operation, found := schemaregistry.ForOperation(descriptor.Name)
		if !found {
			t.Fatalf("%s result schema is missing", descriptor.Name)
		}
		if descriptor.CredentialOutputKind == nil {
			assertProjectedSchemaSafe(t, descriptor.Name+" result", operation.Result, projection.Result)
		}
	}
}

func assertProjectedSchemaSafe(t *testing.T, name string, schema map[string]any, projection capability.Projection) {
	t.Helper()
	projected := schema
	if !projection.Empty() {
		var err error
		projected, err = projection.MCPSchema(schema)
		if err != nil {
			t.Fatalf("%s projection: %v", name, err)
		}
	}
	if issues := capability.AuditMCPPublicSchema(projected); len(issues) != 0 {
		t.Fatalf("%s has unresolved compatibility issue: %v", name, issues[0])
	}
}
