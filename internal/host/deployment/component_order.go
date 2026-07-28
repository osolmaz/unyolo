package deployment

import (
	"errors"
	"fmt"
	"slices"

	deploymentplan "github.com/osolmaz/unyolo/deployment/plan"
	"github.com/osolmaz/unyolo/deployment/profile"
)

//nolint:cyclop // Component ordering projects the reviewed action DAG onto atomic component apply operations.
func orderedDeploymentComponents(planned Planned) ([]profile.Component, error) {
	components := deploymentComponents(planned.Snapshot)
	byID := make(map[string]profile.Component, len(components))
	dependencies := make(map[string]map[string]bool, len(components))
	for _, component := range components {
		if _, exists := byID[component.ID]; exists {
			return nil, fmt.Errorf("deployment component %q is duplicated", component.ID)
		}
		byID[component.ID] = component
		dependencies[component.ID] = map[string]bool{}
	}
	actions := make(map[string]deploymentplan.Action, len(planned.Plan.Actions))
	for _, action := range planned.Plan.Actions {
		actions[action.ID] = action
	}
	for _, action := range planned.Plan.Actions {
		if _, exists := byID[action.ComponentID]; !exists {
			continue
		}
		for _, dependencyID := range action.DependsOn {
			dependency, exists := actions[dependencyID]
			if !exists {
				return nil, fmt.Errorf("component execution references unknown action %q", dependencyID)
			}
			if _, componentDependency := byID[dependency.ComponentID]; componentDependency && dependency.ComponentID != action.ComponentID {
				dependencies[action.ComponentID][dependency.ComponentID] = true
			}
		}
	}
	ids := make([]string, 0, len(byID))
	for id := range byID {
		ids = append(ids, id)
	}
	slices.Sort(ids)
	visiting, visited := map[string]bool{}, map[string]bool{}
	result := make([]profile.Component, 0, len(components))
	var visit func(string) error
	visit = func(id string) error {
		if visited[id] {
			return nil
		}
		if visiting[id] {
			return errors.New("cross-component action dependencies require unsupported interleaved component execution")
		}
		if _, exists := byID[id]; !exists {
			return fmt.Errorf("component execution references unknown component %q", id)
		}
		visiting[id] = true
		orderedDependencies := make([]string, 0, len(dependencies[id]))
		for dependency := range dependencies[id] {
			orderedDependencies = append(orderedDependencies, dependency)
		}
		slices.Sort(orderedDependencies)
		for _, dependency := range orderedDependencies {
			if err := visit(dependency); err != nil {
				return err
			}
		}
		visiting[id] = false
		visited[id] = true
		result = append(result, byID[id])
		return nil
	}
	for _, id := range ids {
		if err := visit(id); err != nil {
			return nil, err
		}
	}
	return result, nil
}
