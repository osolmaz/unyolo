package deployment

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"slices"

	"github.com/osolmaz/unyolo/deployment/api"
	componentprofile "github.com/osolmaz/unyolo/deployment/component"
	"github.com/osolmaz/unyolo/deployment/transaction"
)

const cleanupComponentID = "host-cleanup"

func (engine *Engine) planStaleClients(ctx context.Context, responses []api.Response) ([]ResourceReceipt, *api.Response, error) {
	previous, found, err := LoadReceipt(engine.options.Paths.StateDir)
	if err != nil || !found {
		return nil, nil, err
	}
	current := map[string]bool{}
	for _, response := range responses {
		for _, action := range response.Actions {
			if action.Resource.Kind == "client" && action.Resource.Path != "" {
				current[action.Resource.Path] = true
			}
		}
	}
	var stale []ResourceReceipt
	var actions []api.PlannedAction
	for _, resource := range previous.Resources {
		if resource.Kind != "client" || !resource.Created || resource.Path == "" || current[resource.Path] || resource.Fingerprint == "" {
			continue
		}
		actual := componentprofile.ResourceFingerprint(ctx, api.Resource{Kind: "client", ID: resource.ID, Path: resource.Path}, true)
		if actual != "missing" && actual != resource.Fingerprint {
			continue
		}
		stale = append(stale, resource)
		action := api.PlannedAction{
			ID: fmt.Sprintf("remove-client-%03d", len(stale)), Type: "remove", Risk: "medium",
			Resource:     api.Resource{Kind: "client", ID: resource.ComponentID + "." + resource.ID, Path: resource.Path},
			CurrentState: map[bool]string{true: "missing", false: "present"}[actual == "missing"],
		}
		if actual != "missing" {
			action.CurrentDigest = actual
		}
		actions = append(actions, action)
	}
	if len(stale) == 0 {
		return nil, nil, nil
	}
	slices.SortFunc(stale, func(a, b ResourceReceipt) int { return resourceReceiptKeyCompare(a, b) })
	for index := range stale {
		actions[index].ID = fmt.Sprintf("remove-client-%03d", index+1)
	}
	data, err := json.Marshal(actions)
	if err != nil {
		return nil, nil, err
	}
	response := &api.Response{APIVersion: api.APIVersion, ComponentID: cleanupComponentID, Status: "planned", PlanDigest: digestText(string(data)), Actions: actions}
	if err := response.Validate(); err != nil {
		return nil, nil, err
	}
	return stale, response, nil
}

func resourceReceiptKeyCompare(a, b ResourceReceipt) int {
	if a.ComponentID != b.ComponentID {
		if a.ComponentID < b.ComponentID {
			return -1
		}
		return 1
	}
	if a.ActionID < b.ActionID {
		return -1
	}
	if a.ActionID > b.ActionID {
		return 1
	}
	return 0
}

func (engine *Engine) staleClientSteps(planned Planned) []transaction.Step {
	steps := make([]transaction.Step, 0, len(planned.StaleClients))
	for index, resource := range planned.StaleClients {
		resource := resource
		steps = append(steps, transaction.Step{
			ID: fmt.Sprintf("cleanup.client.%03d", index+1), Kind: "cleanup:client",
			Apply: func(ctx context.Context) (string, error) {
				return engine.quarantineStaleClient(ctx, resource)
			},
			Rollback: func(ctx context.Context, handle string) error {
				return engine.restoreStaleClient(ctx, handle)
			},
			RollbackRunning: func(ctx context.Context) error {
				return engine.restoreStaleClient(ctx, staleClientHandle(resource))
			},
		})
	}
	return steps
}

func (engine *Engine) finalizeStaleClient(_ context.Context, handle string) error {
	return engine.discardStaleClientBackup(handle)
}

func (engine *Engine) cleanupHandlers() map[string]func(context.Context, string) error {
	return map[string]func(context.Context, string) error{
		"cleanup:client": engine.finalizeStaleClient,
	}
}

func cleanupMetadataPath(stateDir, handle string) (string, error) {
	if len(handle) != 64 {
		return "", errors.New("stale client cleanup handle is invalid")
	}
	for _, value := range handle {
		if value < '0' || value > '9' && value < 'a' || value > 'f' {
			return "", errors.New("stale client cleanup handle is invalid")
		}
	}
	return stateDir + string(os.PathSeparator) + "reconfigure-cleanup" + string(os.PathSeparator) + handle + ".json", nil
}
