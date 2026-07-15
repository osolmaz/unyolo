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
		if err := handleMCPLine(ctx, client, encoder, scanner.Bytes()); err != nil {
			return err
		}
	}
	return scanner.Err()
}

func handleMCPLine(ctx context.Context, client *agentClient, encoder *json.Encoder, line []byte) error {
	var request mcpRequest
	if err := json.Unmarshal(line, &request); err != nil {
		return encoder.Encode(mcpResponse{JSONRPC: "2.0", Error: &mcpError{Code: -32700, Message: "Parse error"}})
	}
	if len(request.ID) == 0 {
		return nil
	}
	return encoder.Encode(handleMCPRequest(ctx, client, request))
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
		response.Result, response.Error = handleMCPToolCall(ctx, client, request.Params)
	default:
		response.Error = &mcpError{Code: -32601, Message: "Method not found"}
	}
	return response
}

func handleMCPToolCall(ctx context.Context, client *agentClient, params json.RawMessage) (any, *mcpError) {
	var call mcpToolCall
	if json.Unmarshal(params, &call) != nil {
		return nil, &mcpError{Code: -32602, Message: "Invalid tool call"}
	}
	result, err := callMCPTool(ctx, client, call)
	if err != nil {
		return mcpToolResult(mcpoperation.ErrorValue(err), true), nil
	}
	return mcpToolResult(result, false), nil
}

func mcpTools() []map[string]any {
	tools := catalogMCPTools()
	return append(tools,
		map[string]any{"name": "hf_operation_cancel", "description": "Cancel a pending or approved HF Broker operation.", "inputSchema": mcpIDSchema("operation_id", false)},
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

func callMCPOperation(ctx context.Context, client *agentClient, name string, raw json.RawMessage) (any, error) {
	call, found := mcpOperationCalls[name]
	if !found {
		return nil, fmt.Errorf("unknown operation tool %q", name)
	}
	return call(ctx, client, raw)
}

type mcpOperationCall func(context.Context, *agentClient, json.RawMessage) (any, error)

var mcpOperationCalls = map[string]mcpOperationCall{
	"hf_operation_get":    decodedMCPCall(executeMCPGetOperation),
	"hf_operation_list":   callMCPListOperation,
	"hf_operation_wait":   decodedMCPCall(executeMCPWaitOperation),
	"hf_operation_cancel": callMCPCancelOperation,
}

func callMCPListOperation(ctx context.Context, client *agentClient, raw json.RawMessage) (any, error) {
	var input mcpoperation.ListInput
	if err := decodeMCPArguments(raw, &input); err != nil {
		return nil, err
	}
	return mcpoperation.List(ctx, client.operations, input)
}

func executeMCPWaitOperation(ctx context.Context, client *agentClient, input mcpoperation.WaitInput) (any, error) {
	return mcpoperation.Wait(ctx, client.operations, input, mcpprojection.ResultToMCP)
}

func executeMCPGetOperation(ctx context.Context, client *agentClient, input mcpoperation.GetInput) (any, error) {
	return mcpoperation.Get(ctx, client.operations, input, mcpprojection.ResultToMCP)
}

func decodedMCPCall[T any](execute func(context.Context, *agentClient, T) (any, error)) mcpOperationCall {
	return func(ctx context.Context, client *agentClient, raw json.RawMessage) (any, error) {
		var input T
		if err := decodeMCPArguments(raw, &input); err != nil {
			return nil, err
		}
		return execute(ctx, client, input)
	}
}

func callMCPCancelOperation(ctx context.Context, client *agentClient, raw json.RawMessage) (any, error) {
	var input mcpoperation.GetInput
	if err := decodeMCPArguments(raw, &input); err != nil {
		return nil, err
	}
	operation, err := client.cancel(ctx, input.OperationID)
	if err != nil {
		return nil, err
	}
	return mcpoperation.Project(operation, mcpprojection.ResultToMCP)
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
