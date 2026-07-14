package main

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/osolmaz/brokerkit/agentv1"
	"github.com/osolmaz/brokerkit/brokers/github/internal/mcpcatalog"
	"github.com/osolmaz/brokerkit/brokers/github/internal/opcatalog"
	"github.com/osolmaz/brokerkit/brokers/github/internal/schemaregistry"
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

func runMCP(ctx context.Context, getenv func(string) string, stdin io.Reader, stdout io.Writer, args []string) error {
	if len(args) != 0 {
		return exitError{code: 64, message: "usage: gh-broker mcp"}
	}
	scanner := bufio.NewScanner(stdin)
	scanner.Buffer(make([]byte, 4096), 4<<20)
	encoder := json.NewEncoder(stdout)
	lastTools, _ := mcpToolSignature(getenv)
	for scanner.Scan() {
		var request mcpRequest
		if strictjson.Decode(scanner.Bytes(), &request, true) != nil {
			if err := encoder.Encode(mcpResponse{JSONRPC: "2.0", Error: &mcpError{Code: -32700, Message: "Parse error"}}); err != nil {
				return err
			}
			continue
		}
		if len(request.ID) == 0 {
			continue
		}
		currentTools, signatureErr := mcpToolSignature(getenv)
		if signatureErr == nil && currentTools != lastTools {
			if err := encoder.Encode(map[string]any{"jsonrpc": "2.0", "method": "notifications/tools/list_changed"}); err != nil {
				return err
			}
			lastTools = currentTools
		}
		if err := encoder.Encode(handleMCP(ctx, getenv, request)); err != nil {
			return err
		}
	}
	return scanner.Err()
}

func mcpToolSignature(getenv func(string) string) (string, error) {
	tools, err := configuredMCPTools(getenv)
	if err != nil {
		return "", err
	}
	names := make([]string, 0, len(tools))
	for _, tool := range tools {
		name, _ := tool["name"].(string)
		names = append(names, name)
	}
	return strings.Join(names, "\x00"), nil
}

//nolint:cyclop // JSON-RPC dispatch keeps each supported MCP method explicit.
func handleMCP(ctx context.Context, getenv func(string) string, request mcpRequest) mcpResponse {
	response := mcpResponse{JSONRPC: "2.0", ID: request.ID}
	switch request.Method {
	case "initialize":
		response.Result = map[string]any{"protocolVersion": "2025-06-18", "capabilities": map[string]any{"tools": map[string]any{"listChanged": true}, "resources": map[string]any{}}, "serverInfo": map[string]any{"name": "gh-broker", "version": version}}
	case "ping":
		response.Result = map[string]any{}
	case "tools/list":
		tools, err := configuredMCPTools(getenv)
		if err != nil {
			response.Error = &mcpError{Code: -32603, Message: err.Error()}
		} else {
			response.Result = map[string]any{"tools": tools}
		}
	case "tools/call":
		var call mcpToolCall
		if strictjson.Decode(request.Params, &call, true) != nil {
			response.Error = &mcpError{Code: -32602, Message: "Invalid tool call"}
			break
		}
		value, err := callMCP(ctx, getenv, call)
		response.Result = mcpToolResult(value, err)
		if err != nil {
			response.Result = mcpToolResult(map[string]any{"error": err.Error()}, err)
		}
	case "resources/list":
		response.Result = map[string]any{"resources": []map[string]any{{"uri": "github://operations?limit=50", "name": "GitHub operation catalog", "description": "Paged exhaustive GitHub capability catalog", "mimeType": "application/json"}}}
	case "resources/read":
		value, err := readMCPResource(request.Params)
		if err != nil {
			response.Error = &mcpError{Code: -32602, Message: err.Error()}
		} else {
			response.Result = value
		}
	default:
		response.Error = &mcpError{Code: -32601, Message: "Method not found"}
	}
	return response
}

func configuredMCPTools(getenv func(string) string) ([]map[string]any, error) {
	return mcpcatalog.Tools(mcpExposure(getenv), mcpEnabled(getenv))
}

func mcpExposure(getenv func(string) string) mcpcatalog.Exposure {
	profile := strings.TrimSpace(getenv("GH_BROKER_MCP_EXPOSURE_PROFILE"))
	exposure := mcpcatalog.Exposure{}
	switch profile {
	case "default":
		exposure = mcpcatalog.DefaultExposure()
	case "complete":
		exposure.Complete = true
	}
	exposure.Exact = append(exposure.Exact, splitCSV(getenv("GH_BROKER_MCP_EXACT_OPERATIONS"))...)
	exposure.Families = splitCSV(getenv("GH_BROKER_MCP_FAMILIES"))
	return exposure
}

func mcpEnabled(getenv func(string) string) mcpcatalog.Enabled {
	return mcpcatalog.Enabled{Client: csvSet(getenv("GH_BROKER_MCP_CLIENT_OPERATIONS")), Policy: csvSet(getenv("GH_BROKER_MCP_POLICY_OPERATIONS")), Runtime: csvSet(getenv("GH_BROKER_MCP_RUNTIME_OPERATIONS"))}
}

func splitCSV(value string) []string {
	result := []string{}
	for _, one := range strings.Split(value, ",") {
		if one = strings.TrimSpace(one); one != "" {
			result = append(result, one)
		}
	}
	return result
}
func csvSet(value string) map[string]bool {
	result := map[string]bool{}
	for _, one := range splitCSV(value) {
		result[one] = true
	}
	return result
}

//nolint:cyclop // Typed MCP validation and resumable submission fail closed at each boundary.
func callMCP(ctx context.Context, getenv func(string) string, call mcpToolCall) (any, error) {
	selected, err := mcpcatalog.Selected(mcpExposure(getenv), mcpEnabled(getenv))
	if err != nil {
		return nil, err
	}
	var descriptor opcatalog.Descriptor
	found := false
	for _, value := range selected {
		if value.MCPTool != nil && *value.MCPTool == call.Name {
			descriptor = value
			found = true
			break
		}
	}
	if !found {
		return nil, errors.New("tool is not advertised for this client and deployment")
	}
	var input struct {
		Target          json.RawMessage `json:"target"`
		Arguments       json.RawMessage `json:"arguments"`
		SealedArguments json.RawMessage `json:"sealed_arguments"`
		Attrs           map[string]any  `json:"attrs"`
		Minutes         int             `json:"minutes"`
		MaxUses         json.RawMessage `json:"max_uses"`
		Reason          string          `json:"reason"`
		IdempotencyKey  string          `json:"idempotency_key"`
		WaitSeconds     int             `json:"wait_seconds"`
	}
	if strictjson.Decode(call.Arguments, &input, true) != nil || strings.TrimSpace(input.Reason) == "" || len(input.Reason) > 2000 ||
		input.IdempotencyKey == "" || input.WaitSeconds < 0 || input.WaitSeconds > 900 {
		return nil, errors.New("invalid typed tool arguments")
	}
	if len(input.Arguments) == 0 {
		input.Arguments = json.RawMessage(`{}`)
	}
	connection, err := loadOperationConnection(getenv)
	if err != nil {
		return nil, err
	}
	if descriptor.Sealed {
		if len(input.SealedArguments) == 0 {
			return nil, errors.New("sealed_arguments are required")
		}
		if err := schemaregistry.ValidatePublicSubmission(descriptor.Name, input.Target, input.Arguments); err != nil {
			return nil, err
		}
		if err := schemaregistry.ValidateSealedArguments(descriptor.Name, input.SealedArguments); err != nil {
			return nil, err
		}
		input.Arguments, err = connection.wrapSealedArguments(ctx, descriptor.Name, input.IdempotencyKey, input.Arguments, input.SealedArguments)
		if err != nil {
			return nil, err
		}
	} else {
		if len(input.SealedArguments) != 0 {
			return nil, errors.New("operation does not accept sealed_arguments")
		}
		if err := schemaregistry.ValidateSubmission(descriptor.Name, input.Target, input.Arguments); err != nil {
			return nil, err
		}
	}
	client, err := connection.client()
	if err != nil {
		return nil, err
	}
	operation, err := client.Submit(ctx, agentv1.SubmitRequest{IdempotencyKey: input.IdempotencyKey, Operation: descriptor.Name, Target: input.Target, Arguments: input.Arguments, Reason: input.Reason})
	if err != nil || input.WaitSeconds == 0 || operation.State.Terminal() {
		return operation, err
	}
	waitCtx, cancel := context.WithTimeout(ctx, time.Duration(input.WaitSeconds)*time.Second)
	defer cancel()
	updated, waitErr := client.Wait(waitCtx, operation)
	if waitCtx.Err() != nil && updated.ID != "" {
		return updated, nil
	}
	return updated, waitErr
}

func readMCPResource(raw json.RawMessage) (map[string]any, error) {
	var input struct {
		URI string `json:"uri"`
	}
	if strictjson.Decode(raw, &input, true) != nil {
		return nil, errors.New("invalid resource request")
	}
	parsed, err := url.Parse(input.URI)
	if err != nil || parsed.Scheme != "github" || parsed.Host != "operations" {
		return nil, errors.New("unknown resource URI")
	}
	limit := 50
	if text := parsed.Query().Get("limit"); text != "" {
		limit, err = strconv.Atoi(text)
		if err != nil {
			return nil, errors.New("invalid resource limit")
		}
	}
	page, err := mcpcatalog.Discover(parsed.Query().Get("cursor"), limit)
	if err != nil {
		return nil, err
	}
	data, _ := json.Marshal(page)
	return map[string]any{"contents": []map[string]any{{"uri": input.URI, "mimeType": "application/json", "text": string(data)}}}, nil
}

func mcpToolResult(value any, err error) map[string]any {
	data, _ := json.Marshal(value)
	return map[string]any{"content": []map[string]any{{"type": "text", "text": string(data)}}, "structuredContent": value, "isError": err != nil}
}
