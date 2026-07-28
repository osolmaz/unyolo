package schemaregistry_test

import (
	"encoding/json"
	"os"
	"slices"
	"testing"

	"github.com/osolmaz/unyolo/brokers/github/internal/mcpprojection"
	"github.com/osolmaz/unyolo/brokers/github/internal/opcatalog"
	"github.com/osolmaz/unyolo/brokers/github/internal/schemaregistry"
	"github.com/osolmaz/unyolo/operation/capability"
)

func TestEveryGeneratedGitHubSchemaIsTranscriptSafe(t *testing.T) {
	descriptors := opcatalog.MustAll()
	if len(descriptors) != opcatalog.ExpectedCount {
		t.Fatalf("catalog count = %d", len(descriptors))
	}
	for _, descriptor := range descriptors {
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

func TestCompatibilityManifestMatchesCatalog(t *testing.T) {
	raw, err := os.ReadFile("../../docs/generated/mcp-compatibility.json")
	if err != nil {
		t.Fatal(err)
	}
	var manifest struct {
		APIVersion            string   `json:"api_version"`
		Provider              string   `json:"provider"`
		HostProfiles          []string `json:"host_profiles"`
		AgentFacingOperations int      `json:"agent_facing_operations"`
		AuditedOperations     int      `json:"audited_operations"`
		OperationTools        int      `json:"operation_tools"`
		UtilityTools          int      `json:"utility_tools"`
		ProjectedOperations   []string `json:"projected_operations"`
		UnresolvedCollisions  int      `json:"unresolved_collisions"`
	}
	if err := json.Unmarshal(raw, &manifest); err != nil {
		t.Fatal(err)
	}
	agentFacing, projected := 0, []string{}
	for _, descriptor := range opcatalog.MustAll() {
		if descriptor.AgentFacing {
			agentFacing++
		}
		projection := mcpprojection.ForOperation(descriptor.Descriptor)
		if !projection.Target.Empty() || !projection.Arguments.Empty() || !projection.Attrs.Empty() || !projection.Result.Empty() {
			projected = append(projected, descriptor.Name)
		}
	}
	if manifest.APIVersion != "unyolo.io/mcp-compatibility-manifest/v1" || manifest.Provider != "github" ||
		!slices.Equal(manifest.HostProfiles, []string{"openclaw@2026.7.1"}) ||
		manifest.AgentFacingOperations != agentFacing || manifest.AuditedOperations != opcatalog.ExpectedCount ||
		manifest.OperationTools != agentFacing || manifest.UtilityTools != 3 ||
		!slices.Equal(manifest.ProjectedOperations, projected) || manifest.UnresolvedCollisions != 0 {
		t.Fatalf("compatibility manifest drifted: manifest=%+v projected=%v agent_facing=%d", manifest, projected, agentFacing)
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
