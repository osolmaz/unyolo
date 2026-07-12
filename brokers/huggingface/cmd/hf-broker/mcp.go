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

	"github.com/osolmaz/brokerkit/agentv1"
	"github.com/osolmaz/brokerkit/internal/strictjson"
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
			response.Result = mcpToolResult(map[string]any{"error": err.Error()}, true)
		} else {
			response.Result = mcpToolResult(result, false)
		}
	default:
		response.Error = &mcpError{Code: -32601, Message: "Method not found"}
	}
	return response
}

func mcpTools() []map[string]any {
	return []map[string]any{
		{"name": "hf_repo_create", "description": "Create a Hugging Face repository through HF Broker. Never ask for a Hugging Face token. The operation may wait for user approval.", "inputSchema": map[string]any{"type": "object", "additionalProperties": false, "required": []string{"repo_id", "type", "private", "reason", "idempotency_key"}, "properties": map[string]any{"repo_id": map[string]any{"type": "string"}, "type": map[string]any{"enum": []string{"model", "dataset", "space"}}, "private": map[string]any{"type": "boolean"}, "sdk": map[string]any{"enum": []string{"docker", "gradio", "static"}, "default": "docker", "description": "Space SDK; defaults to docker for Spaces"}, "reason": map[string]any{"type": "string"}, "idempotency_key": map[string]any{"type": "string"}, "wait_seconds": map[string]any{"type": "integer", "minimum": 0, "maximum": 900}}}},
		{"name": "hf_operation_get", "description": "Get a resumable HF Broker operation by ID.", "inputSchema": operationIDSchema(false)},
		{"name": "hf_operation_wait", "description": "Wait for a resumable HF Broker operation without requesting a Hugging Face token.", "inputSchema": operationIDSchema(true)},
	}
}

func operationIDSchema(wait bool) map[string]any {
	properties := map[string]any{"operation_id": map[string]any{"type": "string"}}
	if wait {
		properties["wait_seconds"] = map[string]any{"type": "integer", "minimum": 1, "maximum": 900}
	}
	return map[string]any{"type": "object", "additionalProperties": false, "required": []string{"operation_id"}, "properties": properties}
}

func callMCPTool(ctx context.Context, client *agentClient, call mcpToolCall) (agentv1.Operation, error) {
	switch call.Name {
	case "hf_repo_create":
		return callMCPRepoCreate(ctx, client, call.Arguments)
	case "hf_operation_get", "hf_operation_wait":
		return callMCPOperation(ctx, client, call.Name, call.Arguments)
	default:
		return agentv1.Operation{}, fmt.Errorf("unknown tool %q", call.Name)
	}
}

type mcpRepoCreateInput struct {
	RepoID         string `json:"repo_id"`
	Type           string `json:"type"`
	Private        *bool  `json:"private"`
	SDK            string `json:"sdk"`
	Reason         string `json:"reason"`
	IdempotencyKey string `json:"idempotency_key"`
	WaitSeconds    int    `json:"wait_seconds"`
}

func callMCPRepoCreate(ctx context.Context, client *agentClient, raw json.RawMessage) (agentv1.Operation, error) {
	var input mcpRepoCreateInput
	if err := decodeMCPArguments(raw, &input); err != nil {
		return agentv1.Operation{}, err
	}
	if input.WaitSeconds < 0 || input.WaitSeconds > 900 {
		return agentv1.Operation{}, errors.New("wait_seconds must be between 0 and 900")
	}
	request, err := mcpRepoCreateRequest(input)
	if err != nil {
		return agentv1.Operation{}, err
	}
	operation, err := client.submit(ctx, request)
	if err != nil || input.WaitSeconds <= 0 || operation.State.Terminal() {
		return operation, err
	}
	waitCtx, cancel := context.WithTimeout(ctx, time.Duration(input.WaitSeconds)*time.Second)
	defer cancel()
	operation, err = client.wait(waitCtx, operation)
	if waitCtx.Err() != nil && operation.ID != "" {
		return operation, nil
	}
	return operation, err
}

func mcpRepoCreateRequest(input mcpRepoCreateInput) (agentv1.SubmitRequest, error) {
	if input.Private == nil {
		return agentv1.SubmitRequest{}, errors.New("private is required")
	}
	owner, name, ok := strings.Cut(input.RepoID, "/")
	if !ok || owner == "" || name == "" || strings.Contains(name, "/") {
		return agentv1.SubmitRequest{}, errors.New("repo_id must be OWNER/NAME")
	}
	target, _ := json.Marshal(map[string]any{"kind": "repo", "type": input.Type, "owner": owner, "name": name})
	arguments := map[string]any{"private": *input.Private}
	if input.Type == "space" && input.SDK == "" {
		input.SDK = "docker"
	}
	if input.SDK != "" {
		arguments["sdk"] = input.SDK
	}
	argumentJSON, _ := json.Marshal(arguments)
	return agentv1.SubmitRequest{IdempotencyKey: input.IdempotencyKey, Operation: "repo.create", Target: target, Arguments: argumentJSON, Reason: input.Reason}, nil
}

func callMCPOperation(ctx context.Context, client *agentClient, name string, raw json.RawMessage) (agentv1.Operation, error) {
	var input struct {
		OperationID string `json:"operation_id"`
		WaitSeconds int    `json:"wait_seconds"`
	}
	if err := decodeMCPArguments(raw, &input); err != nil || input.OperationID == "" {
		return agentv1.Operation{}, errors.New("operation_id is required")
	}
	operation, err := client.get(ctx, input.OperationID)
	if err != nil || name == "hf_operation_get" || operation.State.Terminal() {
		return operation, err
	}
	if input.WaitSeconds <= 0 || input.WaitSeconds > 900 {
		input.WaitSeconds = 30
	}
	waitCtx, cancel := context.WithTimeout(ctx, time.Duration(input.WaitSeconds)*time.Second)
	defer cancel()
	operation, err = client.wait(waitCtx, operation)
	if waitCtx.Err() != nil && operation.ID != "" {
		return operation, nil
	}
	return operation, err
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
