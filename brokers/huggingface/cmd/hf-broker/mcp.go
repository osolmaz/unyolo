package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/osolmaz/unyolo/agent/client"
	"github.com/osolmaz/unyolo/agent/mcp"
	usebudget "github.com/osolmaz/unyolo/authorization/budget"
	"github.com/osolmaz/unyolo/authorization/grants"
	"github.com/osolmaz/unyolo/brokers/huggingface/internal/mcpprojection"
	"github.com/osolmaz/unyolo/brokers/huggingface/internal/opcatalog"
	"github.com/osolmaz/unyolo/brokers/huggingface/internal/operations"
	"github.com/osolmaz/unyolo/brokers/huggingface/internal/policy"
	"github.com/osolmaz/unyolo/internal/strictjson"
	"github.com/osolmaz/unyolo/mcp/grant"
	"github.com/osolmaz/unyolo/mcp/operation"
	"github.com/osolmaz/unyolo/mcp/server"
)

func runMCP(ctx context.Context, getenv func(string) string, stdin io.Reader, stdout, _ io.Writer, args []string) error {
	if len(args) != 0 {
		return exitError{code: 64, message: "usage: hf-broker mcp"}
	}
	client, err := loadAgentClient(getenv)
	if err != nil {
		return err
	}
	bridge, err := newHFMCPBridge(client)
	if err != nil {
		return err
	}
	server, err := mcpserver.New(mcpserver.Config{
		Name: "hf-broker", Version: version, ListChanged: true,
		Tools: func(ctx context.Context) ([]map[string]any, error) {
			discovery, err := client.operations.Discover(ctx)
			if err != nil {
				return nil, err
			}
			return mcpTools(discovery.Operations), nil
		},
		Call: bridge.Call, ErrorValue: func(err error) any { return mcpoperation.ErrorValue(err) },
	})
	if err != nil {
		return err
	}
	return server.Serve(ctx, stdin, stdout)
}

func newHFMCPBridge(client *agentClient) (*agentmcp.Bridge, error) {
	if client == nil || client.operations == nil || client.grantClient == nil {
		return nil, errors.New("HF MCP client is incomplete")
	}
	utilities := map[string]func(context.Context, json.RawMessage) (any, error){
		"hf_grant_request": func(ctx context.Context, raw json.RawMessage) (any, error) {
			return callMCPGrantRequest(ctx, client.grantClient, raw)
		},
	}
	for _, action := range []string{"get", "wait", "cancel", "revoke"} {
		name := "hf_grant_" + action
		utilities[name] = func(ctx context.Context, raw json.RawMessage) (any, error) {
			return callMCPGrantLifecycle(ctx, client.grantClient, name, raw)
		}
	}
	return agentmcp.New(agentmcp.Config{
		Prefix: "hf_", Client: func(context.Context) (*agentclient.Client, error) { return client.operations, nil },
		Select: func(tool string) (agentmcp.Selection, error) {
			descriptor, found := descriptorByMCPTool(tool)
			if !found {
				return agentmcp.Selection{}, fmt.Errorf("unknown tool %q", tool)
			}
			return agentmcp.Selection{Operation: descriptor.Name, Provider: descriptor}, nil
		},
		Prepare: func(ctx context.Context, selection agentmcp.Selection, input *agentmcp.Input) error {
			descriptor, ok := selection.Provider.(opcatalog.Descriptor)
			if !ok {
				return errors.New("invalid Hugging Face MCP descriptor")
			}
			return prepareHFMCPInput(ctx, client, descriptor, input)
		},
		Project: mcpprojection.ResultToMCP, Utilities: utilities,
	})
}

func prepareHFMCPInput(ctx context.Context, client *agentClient, descriptor opcatalog.Descriptor, input *agentmcp.Input) error {
	local := mcpCatalogOperationInput{
		Target: input.Target, Arguments: input.Arguments, SealedArguments: input.SealedArguments,
		CredentialSlot: input.CredentialSlot, StreamInput: input.StreamInput, Reason: input.Reason, RequestID: input.RequestID,
	}
	if err := validateMCPCatalogOperation(descriptor, local); err != nil {
		return err
	}
	arguments, err := mcpprojection.ArgumentsToCanonical(descriptor, local.Arguments)
	if err != nil {
		return err
	}
	if descriptor.ExecutorKind == "bounded-stream" {
		arguments, err = operations.BindBucketObjectStreamInput(arguments, local.StreamInput, local.RequestID)
		if err != nil {
			return err
		}
	}
	request, err := buildOperationSubmitRequest(ctx, client, descriptor, local.Target, arguments, "", local.SealedArguments,
		local.CredentialSlot, local.Reason, local.RequestID)
	if err != nil {
		return err
	}
	input.Target, input.Arguments = request.Target, request.Arguments
	return nil
}

func mcpTools(operations []string) []map[string]any {
	tools := catalogMCPTools()
	available := make(map[string]struct{}, len(operations))
	for _, operation := range operations {
		available[operation] = struct{}{}
	}
	filtered := tools[:0]
	for _, tool := range tools {
		name, _ := tool["name"].(string)
		descriptor, found := descriptorByMCPTool(name)
		_, allowed := available[descriptor.Name]
		if found && allowed || len(available) > 0 && strings.HasPrefix(name, "hf_operation_") {
			filtered = append(filtered, tool)
		}
	}
	tools = filtered
	return append(tools,
		map[string]any{"name": "hf_grant_request", "description": "Request a scoped temporary HF Broker grant and wait up to 25 seconds for its decision. This does not execute the operation.", "inputSchema": mcpGrantRequestSchema()},
		map[string]any{"name": "hf_grant_get", "description": "Get a temporary HF Broker grant by ID.", "inputSchema": mcpIDSchema("grant_id", false)},
		map[string]any{"name": "hf_grant_wait", "description": "Wait briefly for a temporary HF Broker grant decision, then call again if it remains pending.", "inputSchema": mcpIDSchema("grant_id", true)},
		map[string]any{"name": "hf_grant_cancel", "description": "Cancel a pending temporary HF Broker grant.", "inputSchema": mcpIDSchema("grant_id", false)},
		map[string]any{"name": "hf_grant_revoke", "description": "Revoke an active temporary HF Broker grant.", "inputSchema": mcpIDSchema("grant_id", false)},
	)
}

func mcpGrantRequestSchema() map[string]any {
	stringArray := map[string]any{"type": "array", "maxItems": 32, "items": map[string]any{"type": "string", "minLength": 1, "maxLength": 256}}
	target := map[string]any{
		"type": "object", "additionalProperties": false, "required": []string{"kind", "name"},
		"properties": map[string]any{
			"kind":  map[string]any{"type": "string", "enum": []string{"repo", "bucket", "inference"}},
			"type":  map[string]any{"type": "string", "enum": []string{"model", "dataset", "space"}},
			"owner": map[string]any{"type": "string", "minLength": 1, "maxLength": 128},
			"name":  map[string]any{"type": "string", "minLength": 1, "maxLength": 128},
			"refs":  stringArray, "paths": stringArray, "keys": stringArray, "visibility": stringArray,
		},
	}
	return map[string]any{
		"type": "object", "additionalProperties": false, "required": []string{"operation", "target", "reason"},
		"properties": map[string]any{
			"operation":    map[string]any{"type": "string", "minLength": 1, "maxLength": 128},
			"target":       target,
			"attrs":        map[string]any{"type": "object", "maxProperties": 32},
			"minutes":      map[string]any{"type": "integer", "minimum": 1, "maximum": 7 * 24 * 60},
			"max_uses":     map[string]any{"type": []string{"integer", "null"}, "minimum": 1, "maximum": int(usebudget.MaxFiniteUses)},
			"reason":       map[string]any{"type": "string", "minLength": 1, "maxLength": 2000},
			"request_id":   map[string]any{"type": "string", "minLength": 1, "maxLength": 128},
			"wait_seconds": map[string]any{"type": "integer", "minimum": 0, "maximum": mcpoperation.MaxWaitSeconds, "default": mcpoperation.DefaultWaitSeconds},
		},
	}
}

func mcpIDSchema(idField string, wait bool) map[string]any {
	properties := map[string]any{idField: map[string]any{"type": "string"}}
	if wait {
		properties["wait_seconds"] = map[string]any{"type": "integer", "minimum": 1, "maximum": mcpoperation.MaxWaitSeconds}
	}
	return map[string]any{"type": "object", "additionalProperties": false, "required": []string{idField}, "properties": properties}
}

type mcpGrantRequestInput struct {
	Operation   string             `json:"operation"`
	Target      policy.Target      `json:"target"`
	Attrs       map[string]any     `json:"attrs"`
	Minutes     int                `json:"minutes"`
	MaxUses     usebudget.Optional `json:"max_uses,omitempty"`
	Reason      string             `json:"reason"`
	RequestID   string             `json:"request_id"`
	WaitSeconds int                `json:"wait_seconds"`
}

func callMCPGrantRequest(ctx context.Context, client *hfGrantClient, raw json.RawMessage) (mcpgrant.Grant, error) {
	input, request, err := buildMCPGrantRequest(raw)
	if err != nil {
		return mcpgrant.Grant{}, err
	}
	grant, err := client.Request(ctx, request)
	if err != nil {
		return mcpgrant.Grant{}, err
	}
	grant, err = waitForPendingMCPGrant(ctx, client, grant, input.WaitSeconds)
	if err != nil {
		return mcpgrant.Grant{}, err
	}
	return projectHFMCPGrant(grant)
}

func buildMCPGrantRequest(raw json.RawMessage) (mcpGrantRequestInput, hfGrantRequest, error) {
	input, err := decodeMCPGrantRequest(raw)
	if err != nil {
		return input, hfGrantRequest{}, err
	}
	requestID, err := mcpoperation.ResolveRequestID(input.RequestID)
	if err != nil {
		return input, hfGrantRequest{}, err
	}
	request := hfGrantRequest{Operation: policy.Operation(input.Operation), Target: input.Target, Attrs: input.Attrs,
		Minutes: input.Minutes, Reason: input.Reason, ClientRequestID: requestID}
	if input.MaxUses.Specified {
		request.MaxUses = &input.MaxUses.Limit
	}
	return input, request, nil
}

func waitForPendingMCPGrant(ctx context.Context, client *hfGrantClient, grant hfClientGrant, waitSeconds int) (hfClientGrant, error) {
	if grant.Status != string(grants.StatusPending) {
		return grant, nil
	}
	if waitSeconds == 0 {
		waitSeconds = mcpoperation.DefaultWaitSeconds
	}
	return waitForMCPGrant(ctx, client, grant.ID, time.Duration(waitSeconds)*time.Second)
}

func decodeMCPGrantRequest(raw json.RawMessage) (mcpGrantRequestInput, error) {
	var input mcpGrantRequestInput
	if err := decodeMCPArguments(raw, &input); err != nil {
		return input, err
	}
	input.Operation, input.Reason = strings.TrimSpace(input.Operation), strings.TrimSpace(input.Reason)
	if !validMCPGrantRequestInput(input) {
		return input, errors.New("grant request input is invalid")
	}
	if err := policy.ValidateGrantRequest(policy.Request{Operation: policy.Operation(input.Operation), Target: input.Target, Attrs: input.Attrs}); err != nil {
		return input, err
	}
	return input, nil
}

func validMCPGrantRequestInput(input mcpGrantRequestInput) bool {
	return policy.IsOperation(input.Operation) && input.Reason != "" && input.Minutes >= 0 &&
		input.WaitSeconds >= 0 && input.WaitSeconds <= mcpoperation.MaxWaitSeconds
}

func projectHFMCPGrant(grant hfClientGrant) (mcpgrant.Grant, error) {
	return mcpgrant.Project(mcpgrant.Input{
		ID: grant.ID, RequestID: grant.ClientRequestID, Status: grant.Status, Operation: grant.Operation,
		Target: grant.Target, Attrs: grant.Attrs, Mode: string(grant.Mode), Minutes: grant.Minutes,
		MaxUses: grant.MaxUses, UsesRemaining: grant.UsesRemaining, UsedCount: grant.UsedCount,
		PendingUntil: grant.PendingUntil, ExpiresAt: grant.ExpiresAt,
	})
}

func callMCPGrantLifecycle(ctx context.Context, client *hfGrantClient, name string, raw json.RawMessage) (mcpgrant.Grant, error) {
	input, err := decodeMCPGrantLifecycle(raw)
	if err != nil {
		return mcpgrant.Grant{}, err
	}
	action := strings.TrimPrefix(name, "hf_grant_")
	var grant hfClientGrant
	if action == "wait" {
		grant, err = waitForMCPGrantInput(ctx, client, input)
	} else if input.WaitSeconds != 0 {
		return mcpgrant.Grant{}, errors.New("wait_seconds is valid only for hf_grant_wait")
	} else {
		grant, err = performGrantAction(ctx, client, action, input.GrantID, 0)
	}
	if err != nil {
		return mcpgrant.Grant{}, err
	}
	return projectHFMCPGrant(grant)
}

type mcpGrantLifecycleInput struct {
	GrantID     string `json:"grant_id"`
	WaitSeconds int    `json:"wait_seconds"`
}

func decodeMCPGrantLifecycle(raw json.RawMessage) (mcpGrantLifecycleInput, error) {
	var input mcpGrantLifecycleInput
	if err := decodeMCPArguments(raw, &input); err != nil || input.GrantID == "" {
		return input, errors.New("grant_id is required")
	}
	return input, nil
}

func waitForMCPGrantInput(ctx context.Context, client *hfGrantClient, input mcpGrantLifecycleInput) (hfClientGrant, error) {
	if input.WaitSeconds < 0 || input.WaitSeconds > mcpoperation.MaxWaitSeconds {
		return hfClientGrant{}, fmt.Errorf("wait_seconds must be between 0 and %d", mcpoperation.MaxWaitSeconds)
	}
	if input.WaitSeconds == 0 {
		input.WaitSeconds = mcpoperation.DefaultWaitSeconds
	}
	return waitForMCPGrant(ctx, client, input.GrantID, time.Duration(input.WaitSeconds)*time.Second)
}

// waitForMCPGrant returns the latest durable projection when its bounded wait
// expires. Pending grants remain resumable by ID through hf_grant_wait instead
// of holding an MCP call open indefinitely.
func waitForMCPGrant(ctx context.Context, client *hfGrantClient, id string, timeout time.Duration) (hfClientGrant, error) {
	waitCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	grant, err := client.Wait(waitCtx, id)
	if waitCtx.Err() != nil && grant.ID != "" {
		return grant, nil
	}
	return grant, err
}

func decodeMCPArguments(raw json.RawMessage, out any) error {
	if err := strictjson.Decode(raw, out, true); err != nil {
		return errors.New("invalid tool arguments")
	}
	return nil
}
