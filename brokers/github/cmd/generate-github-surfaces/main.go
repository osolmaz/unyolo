package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"

	"github.com/osolmaz/brokerkit/brokers/github/internal/opcatalog"
)

var checkOnly bool
var reviewedOverrides overrideFile

func main() {
	flag.BoolVar(&checkOnly, "check", false, "verify checked-in generated artifacts")
	flag.Parse()
	root, err := repositoryRoot()
	if err != nil {
		panic(err)
	}
	base := filepath.Join(root, "brokers", "github")
	upstream := filepath.Join(base, "internal", "upstream", "snapshots")
	if err := loadOverrides(filepath.Join(base, "internal", "inventory", "overrides.json")); err != nil {
		panic(err)
	}
	if err := verifyProvenance(upstream); err != nil {
		panic(err)
	}
	state, err := generate(upstream)
	if err != nil {
		panic(err)
	}
	outputs := map[string]any{
		filepath.Join(base, "internal", "inventory", "rest-coverage.json"):    state.restCoverage,
		filepath.Join(base, "internal", "inventory", "graphql-coverage.json"): state.graphqlCoverage,
		filepath.Join(base, "internal", "inventory", "high-risk-review.json"): state.highRisk,
		filepath.Join(base, "internal", "opcatalog", "catalog.json"):          state.descriptors,
		filepath.Join(base, "internal", "opbinding", "bindings.json"):         state.bindings,
		filepath.Join(base, "internal", "targetregistry", "targets.json"):     state.targets,
		filepath.Join(base, "internal", "schemaregistry", "schemas.json"):     state.schemas,
		filepath.Join(base, "internal", "graphqlmanifest", "manifest.json"):   state.manifest,
		filepath.Join(base, "docs", "generated", "capabilities.json"):         state.descriptors,
	}
	for path, value := range outputs {
		if err := writeJSON(path, value); err != nil {
			panic(err)
		}
	}
	if err := writeCapabilitiesMarkdown(filepath.Join(base, "docs", "generated", "CAPABILITIES.md"), state.descriptors); err != nil {
		panic(err)
	}
	if err := writePermissionProfiles(filepath.Join(base, "docs", "generated", "github-app-permission-profiles.json"), state.descriptors); err != nil {
		panic(err)
	}
	if err := writePermissionProfiles(filepath.Join(base, "internal", "appmanifest", "profiles.json"), state.descriptors); err != nil {
		panic(err)
	}
}

func loadOverrides(path string) error {
	// #nosec G304 -- path is derived from the discovered repository root.
	data, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	if err := json.Unmarshal(data, &reviewedOverrides); err != nil {
		return err
	}
	if reviewedOverrides.Version != 1 || len(reviewedOverrides.RESTOperationNames) == 0 || len(reviewedOverrides.HighRiskOperations) == 0 {
		return errors.New("GitHub inventory overrides are incomplete")
	}
	slices.Sort(reviewedOverrides.HighRiskOperations)
	slices.Sort(reviewedOverrides.InternalGraphQLRoots)
	return nil
}

func repositoryRoot() (string, error) {
	dir, err := os.Getwd()
	if err != nil {
		return "", err
	}
	for {
		if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
			return dir, nil
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			return "", errors.New("go.mod not found")
		}
		dir = parent
	}
}

func verifyProvenance(dir string) error {
	// #nosec G304 -- dir is the fixed repository snapshot directory.
	data, err := os.ReadFile(filepath.Join(dir, "provenance.json"))
	if err != nil {
		return err
	}
	var document struct {
		Artifacts []struct{ Path, SHA256 string } `json:"artifacts"`
	}
	if err := json.Unmarshal(data, &document); err != nil {
		return err
	}
	if len(document.Artifacts) < 3 {
		return errors.New("upstream provenance is incomplete")
	}
	for _, artifact := range document.Artifacts {
		if filepath.IsAbs(artifact.Path) || filepath.Clean(artifact.Path) != artifact.Path || strings.HasPrefix(artifact.Path, "..") {
			return fmt.Errorf("invalid pinned artifact path %q", artifact.Path)
		}
		// #nosec G304 -- artifact paths are traversal-checked reviewed provenance entries.
		content, err := os.ReadFile(filepath.Join(dir, filepath.FromSlash(artifact.Path)))
		if err != nil {
			return fmt.Errorf("read pinned artifact %s: %w", artifact.Path, err)
		}
		digest := sha256.Sum256(content)
		if hex.EncodeToString(digest[:]) != artifact.SHA256 {
			return fmt.Errorf("pinned artifact %s digest drifted", artifact.Path)
		}
	}
	return nil
}

func generate(dir string) (generatedState, error) {
	rest, err := loadREST(filepath.Join(dir, "rest-api-2026-03-10.json"))
	if err != nil {
		return generatedState{}, err
	}
	permissions, err := loadPermissions(filepath.Join(dir, "github-app-permissions-2026-03-10.json"))
	if err != nil {
		return generatedState{}, err
	}
	graphql, fingerprint, err := loadGraphQL(filepath.Join(dir, "graphql-introspection-2026-07-14.json"))
	if err != nil {
		return generatedState{}, err
	}
	state := generatedState{schemas: schemaRegistry{Version: 1, Targets: targetSchemas(), Operations: map[string]operationSchemas{}}}
	state.targets = targetDescriptors(state.schemas.Targets)
	if err := generateREST(&state, rest, permissions); err != nil {
		return generatedState{}, err
	}
	if err := generateGraphQL(&state, graphql, fingerprint); err != nil {
		return generatedState{}, err
	}
	state.descriptors = uniqueSortedDescriptors(state.descriptors)
	slices.SortFunc(state.bindings, func(a, b restBinding) int { return strings.Compare(a.ID, b.ID) })
	slices.SortFunc(state.restCoverage, func(a, b restCoverage) int { return strings.Compare(a.UpstreamID, b.UpstreamID) })
	slices.SortFunc(state.graphqlCoverage, func(a, b graphqlCoverage) int {
		if value := strings.Compare(a.RootType, b.RootType); value != 0 {
			return value
		}
		return strings.Compare(a.Field, b.Field)
	})
	state.highRisk = buildHighRiskReview(state.restCoverage, state.graphqlCoverage)
	return state, nil
}

func loadREST(path string) (openAPIDocument, error) {
	// #nosec G304 -- path is a fixed file under the repository snapshot directory.
	data, err := os.ReadFile(path)
	if err != nil {
		return openAPIDocument{}, err
	}
	var document openAPIDocument
	if err := json.Unmarshal(data, &document); err != nil {
		return document, err
	}
	if document.OpenAPI != "3.0.3" {
		return document, fmt.Errorf("stable REST snapshot is OpenAPI %q", document.OpenAPI)
	}
	return document, nil
}

func loadPermissions(path string) (map[string][]permissionMatch, error) {
	// #nosec G304 -- path is a fixed file under the repository snapshot directory.
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var groups map[string]permissionGroup
	if err := json.Unmarshal(data, &groups); err != nil {
		return nil, err
	}
	result := map[string][]permissionMatch{}
	for permission, group := range groups {
		for _, route := range group.Permissions {
			key := strings.ToUpper(route.Verb) + " " + route.RequestPath
			result[key] = append(result[key], permissionMatch{Name: permission, Route: route})
		}
	}
	return result, nil
}

func loadGraphQL(path string) (graphqlResponse, string, error) {
	// #nosec G304 -- path is a fixed file under the repository snapshot directory.
	data, err := os.ReadFile(path)
	if err != nil {
		return graphqlResponse{}, "", err
	}
	var response graphqlResponse
	if err := json.Unmarshal(data, &response); err != nil {
		return response, "", err
	}
	if len(response.Errors) > 0 || len(response.Data.Schema.Types) < 1000 {
		return response, "", errors.New("GraphQL introspection is incomplete")
	}
	digest := sha256.Sum256(data)
	return response, "sha256:" + hex.EncodeToString(digest[:]), nil
}

func uniqueSortedDescriptors(values []opcatalog.Descriptor) []opcatalog.Descriptor {
	slices.SortFunc(values, func(a, b opcatalog.Descriptor) int { return strings.Compare(a.Name, b.Name) })
	result := values[:0]
	for _, value := range values {
		if len(result) > 0 && result[len(result)-1].Name == value.Name {
			panic("duplicate generated operation: " + value.Name)
		}
		result = append(result, value)
	}
	return result
}

func writeJSON(path string, value any) error {
	data, err := json.MarshalIndent(value, "", "  ")
	if err != nil {
		return err
	}
	data = append(data, '\n')
	return writeFile(path, data)
}

func writeCapabilitiesMarkdown(path string, descriptors []opcatalog.Descriptor) error {
	var out bytes.Buffer
	out.WriteString("# GitHub capability catalog\n\nGenerated from the pinned GitHub REST and GraphQL inventories. Do not edit by hand.\n\n")
	out.WriteString("| Operation | Risk | Status | Credential | Target | Agent surface |\n|---|---|---|---|---|---|\n")
	for _, descriptor := range descriptors {
		agent := "no"
		if descriptor.AgentFacing {
			agent = "typed CLI/MCP"
		}
		fmt.Fprintf(&out, "| `%s` | %s | %s | %s | %s | %s |\n", descriptor.Name, descriptor.Risk, descriptor.Implementation, descriptor.CredentialKind, descriptor.TargetKind, agent)
	}
	return writeFile(path, out.Bytes())
}

func writeFile(path string, data []byte) error {
	if checkOnly {
		// #nosec G304 -- paths are fixed generated outputs below the repository root.
		existing, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		if !bytes.Equal(existing, data) {
			return fmt.Errorf("generated artifact is stale: %s", path)
		}
		return nil
	}
	// #nosec G301 -- generated source directories are intentionally world-readable.
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	// #nosec G306 -- checked-in generated metadata is intentionally world-readable.
	return os.WriteFile(path, data, 0o644)
}

func writePermissionProfiles(path string, descriptors []opcatalog.Descriptor) error {
	profiles := map[string]map[string]string{"code": {}, "automation": {}, "security": {}, "administration": {}, "complete": {}}
	for _, descriptor := range descriptors {
		for permission, access := range descriptor.RequiredGitHubPermissions {
			mergePermission(profiles["complete"], permission, access)
			mergePermission(profiles[permissionProfile(descriptor.Name)], permission, access)
		}
	}
	return writeJSON(path, map[string]any{"version": 1, "api_version": apiVersion, "profiles": profiles})
}

func mergePermission(values map[string]string, permission, access string) {
	if values[permission] != "write" || access == "write" {
		values[permission] = access
	}
}

func permissionProfile(name string) string {
	switch strings.Split(name, ".")[0] {
	case "workflow", "action_run", "artifact", "cache", "runner", "deployment", "environment":
		return "automation"
	case "security", "advisory", "code_scanning", "secret_scanning", "dependabot":
		return "security"
	case "organization", "enterprise", "team", "member", "collaborator", "ruleset", "branch_protection", "webhook", "app":
		return "administration"
	default:
		return "code"
	}
}
