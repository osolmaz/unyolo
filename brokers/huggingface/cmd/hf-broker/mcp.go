package main

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/osolmaz/brokerkit/brokers/huggingface/internal/mcpprojection"
	"github.com/osolmaz/brokerkit/internal/strictjson"
	"github.com/osolmaz/brokerkit/mcpoperation"
)

type mcpRequest struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      json.RawMessage `json:"id,omitempty"`
	Method  string          `json:"method"`
	Params  json.RawMessage `json:"params,omitempty"`
}

type mcpResponse struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      json.RawMessage `json:"id,omitempty"`
	Result  any             `json:"result,omitempty"`
	Error   *mcpError       `json:"error,omitempty"`
}

type mcpError struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
}

type mcpToolCall struct {
	Name      string          `json:"name"`
	Arguments json.RawMessage `json:"arguments"`
}

func runMCP(ctx context.Context, getenv func(string) string, stdin io.Reader, stdout, _ io.Writer, args []string) error {
	if len(args) != 0 {
		return exitError{code: 64, message: "usage: hf-broker mcp"}
	}
	client, err := loadAgentClient(getenv)
	if err != nil {
		return err
	}
	scanner := bufio.NewScanner(stdin)
	scanner.Buffer(make([]byte, 4096), 1024*1024)
	encoder := json.NewEncoder(stdout)
	for scanner.Scan() {
		var request mcpRequest
		if err := json.Unmarshal(scanner.Bytes(), &request); err != nil {
			if err := encoder.Encode(mcpResponse{JSONRPC: "2.0", Error: &mcpError{Code: -32700, Message: "Parse error"}}); err != nil {
				return err
			}
			continue
		}
		if len(request.ID) == 0 {
			continue
		}
		response := handleMCPRequest(ctx, client, request)
		if err := encoder.Encode(response); err != nil {
			return err
		}
	}
	return scanner.Err()
}

func handleMCPRequest(ctx context.Context, client *agentClient, request mcpRequest) mcpResponse {
	response := mcpResponse{JSONRPC: "2.0", ID: request.ID}
	switch request.Method {
	case "initialize":
		response.Result = map[string]any{"protocolVersion": "2025-06-18", "capabilities": map[string]any{"tools": map[string]any{}}, "serverInfo": map[string]any{"name": "hf-broker", "version": version}}
	case "ping":
		response.Result = map[string]any{}
	case "tools/list":
		response.Result = map[string]any{"tools": mcpTools()}
	case "tools/call":
		var call mcpToolCall
		if json.Unmarshal(request.Params, &call) != nil {
			response.Error = &mcpError{Code: -32602, Message: "Invalid tool call"}
			return response
		}
		result, err := callMCPTool(ctx, client, call)
		if err != nil {
			response.Result = mcpToolResult(mcpoperation.ErrorValue(err), true)
		} else {
			response.Result = mcpToolResult(result, false)
		}
	default:
		response.Error = &mcpError{Code: -32601, Message: "Method not found"}
	}
	return response
}

func mcpTools() []map[string]any {
	tools := catalogMCPTools()
	return append(tools,
		map[string]any{"name": "hf_operation_cancel", "description": "Cancel a pending or approved HF Broker operation.", "inputSchema": mcpIDSchema("operation_id", false)},
		map[string]any{"name": "hf_grant_get", "description": "Get a temporary HF Broker grant by ID.", "inputSchema": mcpIDSchema("grant_id", false)},
		map[string]any{"name": "hf_grant_wait", "description": "Wait for a temporary HF Broker grant decision.", "inputSchema": mcpIDSchema("grant_id", true)},
		map[string]any{"name": "hf_grant_cancel", "description": "Cancel a pending temporary HF Broker grant.", "inputSchema": mcpIDSchema("grant_id", false)},
		map[string]any{"name": "hf_grant_revoke", "description": "Revoke an active temporary HF Broker grant.", "inputSchema": mcpIDSchema("grant_id", false)},
	)
}

func mcpIDSchema(idField string, wait bool) map[string]any {
	properties := map[string]any{idField: map[string]any{"type": "string"}}
	if wait {
		properties["wait_seconds"] = map[string]any{"type": "integer", "minimum": 1, "maximum": 900}
	}
	return map[string]any{"type": "object", "additionalProperties": false, "required": []string{idField}, "properties": properties}
}

func callMCPTool(ctx context.Context, client *agentClient, call mcpToolCall) (any, error) {
	if descriptor, found := descriptorByMCPTool(call.Name); found {
		return callMCPCatalogOperation(ctx, client, descriptor, call.Arguments)
	}
	switch call.Name {
	case "hf_operation_get", "hf_operation_wait", "hf_operation_list", "hf_operation_cancel":
		return callMCPOperation(ctx, client, call.Name, call.Arguments)
	case "hf_grant_get", "hf_grant_wait", "hf_grant_cancel", "hf_grant_revoke":
		return callMCPGrantLifecycle(ctx, client.grantClient, call.Name, call.Arguments)
	default:
		return nil, fmt.Errorf("unknown tool %q", call.Name)
	}
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
	return performGrantAction(ctx, client, action, input.GrantID, time.Duration(input.WaitSeconds)*time.Second)
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
	if input.WaitSeconds < 0 || input.WaitSeconds > 900 {
		return hfClientGrant{}, errors.New("wait_seconds must be between 0 and 900")
	}
	if input.WaitSeconds == 0 {
		input.WaitSeconds = 30
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

func callMCPOperation(ctx context.Context, client *agentClient, name string, raw json.RawMessage) (any, error) {
	if name == "hf_operation_list" {
		var input mcpoperation.ListInput
		if err := decodeMCPArguments(raw, &input); err != nil {
			return nil, err
		}
		return mcpoperation.List(ctx, client.operations, input)
	}
	if name == "hf_operation_wait" {
		var input mcpoperation.WaitInput
		if err := decodeMCPArguments(raw, &input); err != nil {
			return nil, err
		}
		return mcpoperation.Wait(ctx, client.operations, input, mcpprojection.ResultToMCP)
	}
	var input mcpoperation.GetInput
	if err := decodeMCPArguments(raw, &input); err != nil {
		return nil, err
	}
	if name == "hf_operation_cancel" {
		operation, err := client.cancel(ctx, input.OperationID)
		if err != nil {
			return nil, err
		}
		return mcpoperation.Project(operation, mcpprojection.ResultToMCP)
	}
	return mcpoperation.Get(ctx, client.operations, input, mcpprojection.ResultToMCP)
}

func decodeMCPArguments(raw json.RawMessage, out any) error {
	if err := strictjson.Decode(raw, out, true); err != nil {
		return errors.New("invalid tool arguments")
	}
	return nil
}

func mcpToolResult(value any, isError bool) map[string]any {
	data, _ := json.Marshal(value)
	return map[string]any{"content": []map[string]any{{"type": "text", "text": string(data)}}, "structuredContent": value, "isError": isError}
}
