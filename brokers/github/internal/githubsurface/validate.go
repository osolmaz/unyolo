// Package githubsurface validates the complete generated GitHub operation surface.
package githubsurface

import (
	"errors"
	"fmt"
	"slices"
	"strings"

	"github.com/osolmaz/brokerkit/brokers/github/internal/graphqlmanifest"
	"github.com/osolmaz/brokerkit/brokers/github/internal/inventory"
	"github.com/osolmaz/brokerkit/brokers/github/internal/opbinding"
	"github.com/osolmaz/brokerkit/brokers/github/internal/opcatalog"
	"github.com/osolmaz/brokerkit/brokers/github/internal/schemaregistry"
	"github.com/osolmaz/brokerkit/brokers/github/internal/targetregistry"
	"github.com/osolmaz/brokerkit/brokers/github/internal/upstream"
)

//nolint:cyclop // Startup cross-artifact validation is intentionally exhaustive and fail-closed.
func Validate() error {
	if err := upstream.Validate(); err != nil {
		return err
	}
	rest, err := inventory.AllREST()
	if err != nil {
		return err
	}
	graphql, err := inventory.AllGraphQL()
	if err != nil {
		return err
	}
	descriptors, err := opcatalog.All()
	if err != nil {
		return err
	}
	bindings, err := opbinding.All()
	if err != nil {
		return err
	}
	if err := schemaregistry.Validate(); err != nil {
		return err
	}
	if err := graphqlmanifest.Validate(); err != nil {
		return err
	}
	if _, err := targetregistry.All(); err != nil {
		return err
	}
	covered := map[string]bool{}
	for _, row := range rest {
		for _, operation := range row.CatalogOperations {
			if covered[operation] {
				return fmt.Errorf("catalog operation %q has multiple REST dispositions", operation)
			}
			covered[operation] = true
		}
	}
	for _, row := range graphql {
		if row.CatalogOperation != "" {
			if covered[row.CatalogOperation] {
				return fmt.Errorf("catalog operation %q has multiple upstream dispositions", row.CatalogOperation)
			}
			covered[row.CatalogOperation] = true
		}
	}
	bound := map[string]bool{}
	for _, binding := range bindings {
		bound[binding.Operation] = true
	}
	for _, descriptor := range descriptors {
		if !covered[descriptor.Name] {
			return fmt.Errorf("catalog operation %q is absent from coverage maps", descriptor.Name)
		}
		schemas, found := schemaregistry.ForOperation(descriptor.Name)
		if !found {
			return fmt.Errorf("catalog operation %q has no schemas", descriptor.Name)
		}
		for _, path := range sensitiveTopLevelFields(schemas.Arguments) {
			if !slices.Contains(descriptor.SealedInputPaths, path) {
				return fmt.Errorf("catalog operation %q exposes unsealed sensitive input %q", descriptor.Name, path)
			}
		}
		if descriptor.AgentFacing && descriptor.CredentialOutputKind == nil && containsSensitiveField(schemas.Result) {
			return fmt.Errorf("catalog operation %q exposes a sensitive result field", descriptor.Name)
		}
		if descriptor.ExecutorKind == "persisted-graphql" {
			if _, found := graphqlmanifest.ByOperation(descriptor.Name); !found {
				return fmt.Errorf("catalog operation %q has no persisted document", descriptor.Name)
			}
		} else if !bound[descriptor.Name] {
			return fmt.Errorf("catalog operation %q has no REST binding", descriptor.Name)
		}
	}
	if len(covered) != len(descriptors) {
		return errors.New("GitHub coverage and catalog counts drifted")
	}
	return nil
}

func sensitiveTopLevelFields(schema map[string]any) []string {
	properties, _ := schema["properties"].(map[string]any)
	result := []string{}
	for name, value := range properties {
		child, _ := value.(map[string]any)
		if isSensitiveField(name, child) || containsSensitiveField(child) {
			result = append(result, name)
		}
	}
	return result
}

//nolint:cyclop // Recursive startup validation must inspect every supported schema container.
func containsSensitiveField(schema map[string]any) bool {
	if schema == nil {
		return false
	}
	if properties, ok := schema["properties"].(map[string]any); ok {
		for name, value := range properties {
			child, _ := value.(map[string]any)
			if isSensitiveField(name, child) || containsSensitiveField(child) {
				return true
			}
		}
	}
	if items, ok := schema["items"].(map[string]any); ok && containsSensitiveField(items) {
		return true
	}
	for _, keyword := range []string{"oneOf", "anyOf", "allOf"} {
		if branches, ok := schema[keyword].([]any); ok {
			for _, branch := range branches {
				child, _ := branch.(map[string]any)
				if containsSensitiveField(child) {
					return true
				}
			}
		}
	}
	return false
}

func isSensitiveField(name string, schema map[string]any) bool {
	if schema["type"] == "boolean" {
		return false
	}
	normalized := strings.ToLower(name)
	return normalized == "password" || normalized == "secret" || normalized == "token" || normalized == "private_key" ||
		normalized == "encrypted_value" || strings.HasSuffix(normalized, "_password") || strings.HasSuffix(normalized, "_secret") ||
		strings.HasSuffix(normalized, "_token") || strings.HasSuffix(normalized, "_private_key")
}
