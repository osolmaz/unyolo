// Package githubsurface validates the complete generated GitHub operation surface.
package githubsurface

import (
	"errors"
	"fmt"
	"slices"

	"github.com/osolmaz/brokerkit/brokers/github/internal/graphqlmanifest"
	"github.com/osolmaz/brokerkit/brokers/github/internal/inventory"
	"github.com/osolmaz/brokerkit/brokers/github/internal/opbinding"
	"github.com/osolmaz/brokerkit/brokers/github/internal/opcatalog"
	"github.com/osolmaz/brokerkit/brokers/github/internal/schemaregistry"
	"github.com/osolmaz/brokerkit/brokers/github/internal/targetregistry"
	"github.com/osolmaz/brokerkit/brokers/github/internal/upstream"
	"github.com/osolmaz/brokerkit/internal/schemautil"
)

type surfaceArtifacts struct {
	rest        []inventory.RESTRow
	graphql     []inventory.GraphQLRow
	descriptors []opcatalog.Descriptor
	bindings    []opbinding.Binding
}

func Validate() error {
	artifacts, err := loadSurfaceArtifacts()
	if err != nil {
		return err
	}
	return validateSurfaceArtifacts(artifacts)
}

func loadSurfaceArtifacts() (surfaceArtifacts, error) {
	rest, err := inventory.AllREST()
	if err != nil {
		return surfaceArtifacts{}, err
	}
	graphql, err := inventory.AllGraphQL()
	if err != nil {
		return surfaceArtifacts{}, err
	}
	descriptors, err := opcatalog.All()
	if err != nil {
		return surfaceArtifacts{}, err
	}
	bindings, err := opbinding.All()
	if err != nil {
		return surfaceArtifacts{}, err
	}
	if err := validateEmbeddedArtifacts(); err != nil {
		return surfaceArtifacts{}, err
	}
	return surfaceArtifacts{rest: rest, graphql: graphql, descriptors: descriptors, bindings: bindings}, nil
}

func validateEmbeddedArtifacts() error {
	if err := upstream.Validate(); err != nil {
		return err
	}
	if err := schemaregistry.Validate(); err != nil {
		return err
	}
	if err := graphqlmanifest.Validate(); err != nil {
		return err
	}
	_, err := targetregistry.All()
	return err
}

func validateSurfaceArtifacts(artifacts surfaceArtifacts) error {
	covered, err := coveredOperations(artifacts.rest, artifacts.graphql)
	if err != nil {
		return err
	}
	bound := boundOperations(artifacts.bindings)
	return validateDescriptors(artifacts.descriptors, covered, bound)
}

func validateDescriptors(descriptors []opcatalog.Descriptor, covered, bound map[string]bool) error {
	for _, descriptor := range descriptors {
		if err := validateDescriptor(descriptor, covered, bound); err != nil {
			return err
		}
	}
	if len(covered) != len(descriptors) {
		return errors.New("GitHub coverage and catalog counts drifted")
	}
	return nil
}

func coveredOperations(rest []inventory.RESTRow, graphql []inventory.GraphQLRow) (map[string]bool, error) {
	covered := map[string]bool{}
	for _, row := range rest {
		for _, operation := range row.CatalogOperations {
			if covered[operation] {
				return nil, fmt.Errorf("catalog operation %q has multiple REST dispositions", operation)
			}
			covered[operation] = true
		}
	}
	for _, row := range graphql {
		if row.CatalogOperation != "" {
			if covered[row.CatalogOperation] {
				return nil, fmt.Errorf("catalog operation %q has multiple upstream dispositions", row.CatalogOperation)
			}
			covered[row.CatalogOperation] = true
		}
	}
	return covered, nil
}

func boundOperations(bindings []opbinding.Binding) map[string]bool {
	bound := map[string]bool{}
	for _, binding := range bindings {
		bound[binding.Operation] = true
	}
	return bound
}

func validateDescriptor(descriptor opcatalog.Descriptor, covered, bound map[string]bool) error {
	if !covered[descriptor.Name] {
		return fmt.Errorf("catalog operation %q is absent from coverage maps", descriptor.Name)
	}
	schemas, found := schemaregistry.ForOperation(descriptor.Name)
	if !found {
		return fmt.Errorf("catalog operation %q has no schemas", descriptor.Name)
	}
	if err := validateSensitiveInputs(descriptor, schemas.Arguments); err != nil {
		return err
	}
	if exposesSensitiveResult(descriptor, schemas.Result) {
		return fmt.Errorf("catalog operation %q exposes a sensitive result field", descriptor.Name)
	}
	return validateExecutorBinding(descriptor, bound)
}

func exposesSensitiveResult(descriptor opcatalog.Descriptor, result map[string]any) bool {
	return descriptor.AgentFacing && descriptor.CredentialOutputKind == nil && containsSensitiveField(result)
}

func validateSensitiveInputs(descriptor opcatalog.Descriptor, arguments map[string]any) error {
	for _, path := range sensitiveTopLevelFields(arguments) {
		if !slices.Contains(descriptor.SealedInputPaths, path) {
			return fmt.Errorf("catalog operation %q exposes unsealed sensitive input %q", descriptor.Name, path)
		}
	}
	return nil
}

func validateExecutorBinding(descriptor opcatalog.Descriptor, bound map[string]bool) error {
	if descriptor.ExecutorKind == "persisted-graphql" {
		if _, found := graphqlmanifest.ByOperation(descriptor.Name); !found {
			return fmt.Errorf("catalog operation %q has no persisted document", descriptor.Name)
		}
		return nil
	}
	if !bound[descriptor.Name] {
		return fmt.Errorf("catalog operation %q has no REST binding", descriptor.Name)
	}
	return nil
}

func sensitiveTopLevelFields(schema map[string]any) []string {
	return schemautil.SensitiveTopLevelFields(schema)
}

func containsSensitiveField(schema map[string]any) bool {
	return schemautil.ContainsSensitiveField(schema)
}
