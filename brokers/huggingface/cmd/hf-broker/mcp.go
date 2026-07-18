package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/osolmaz/brokerkit/agentclient"
	"github.com/osolmaz/brokerkit/agentmcp"
	"github.com/osolmaz/brokerkit/brokers/huggingface/internal/mcpprojection"
	"github.com/osolmaz/brokerkit/brokers/huggingface/internal/opcatalog"
	"github.com/osolmaz/brokerkit/internal/strictjson"
	"github.com/osolmaz/brokerkit/mcpoperation"
	"github.com/osolmaz/brokerkit/mcpserver"
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
	utilities := map[string]func(context.Context, json.RawMessage) (any, error){}
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
		CredentialSlot: input.CredentialSlot, Reason: input.Reason, RequestID: input.RequestID,
	}
	if err := validateMCPCatalogOperation(descriptor, local); err != nil {
		return err
	}
	arguments, err := mcpprojection.ArgumentsToCanonical(descriptor, local.Arguments)
	if err != nil {
		return err
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
		if _, allowed := available[descriptor.Name]; found && allowed {
			filtered = append(filtered, tool)
		}
	}
	tools = filtered
	return append(tools,
		map[string]any{"name": "hf_grant_get", "description": "Get a temporary HF Broker grant by ID.", "inputSchema": mcpIDSchema("grant_id", false)},
		map[string]any{"name": "hf_grant_wait", "description": "Wait briefly for a temporary HF Broker grant decision, then call again if it remains pending.", "inputSchema": mcpIDSchema("grant_id", true)},
		map[string]any{"name": "hf_grant_cancel", "description": "Cancel a pending temporary HF Broker grant.", "inputSchema": mcpIDSchema("grant_id", false)},
		map[string]any{"name": "hf_grant_revoke", "description": "Revoke an active temporary HF Broker grant.", "inputSchema": mcpIDSchema("grant_id", false)},
	)
}

func mcpIDSchema(idField string, wait bool) map[string]any {
	properties := map[string]any{idField: map[string]any{"type": "string"}}
	if wait {
		properties["wait_seconds"] = map[string]any{"type": "integer", "minimum": 1, "maximum": mcpoperation.MaxWaitSeconds}
	}
	return map[string]any{"type": "object", "additionalProperties": false, "required": []string{idField}, "properties": properties}
}

func callMCPGrantLifecycle(ctx context.Context, client *hfGrantClient, name string, raw json.RawMessage) (hfClientGrant, error) {
	input, err := decodeMCPGrantLifecycle(raw)
	if err != nil {
		return hfClientGrant{}, err
	}
	action := strings.TrimPrefix(name, "hf_grant_")
	if action == "wait" {
		return waitForMCPGrantInput(ctx, client, input)
	}
	if input.WaitSeconds != 0 {
		return hfClientGrant{}, errors.New("wait_seconds is valid only for hf_grant_wait")
	}
	return performGrantAction(ctx, client, action, input.GrantID, 0)
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
