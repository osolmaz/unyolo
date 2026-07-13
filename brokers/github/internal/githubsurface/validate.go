// Package githubsurface validates the complete generated GitHub operation surface.
package githubsurface

import (
	"errors"
	"fmt"

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
		if _, found := schemaregistry.ForOperation(descriptor.Name); !found {
			return fmt.Errorf("catalog operation %q has no schemas", descriptor.Name)
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
