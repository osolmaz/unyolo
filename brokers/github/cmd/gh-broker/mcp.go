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

	"github.com/osolmaz/brokerkit/agentclient"
	"github.com/osolmaz/brokerkit/agentv1"
	"github.com/osolmaz/brokerkit/brokers/github/internal/mcpcatalog"
	"github.com/osolmaz/brokerkit/brokers/github/internal/mcpprojection"
	"github.com/osolmaz/brokerkit/brokers/github/internal/opcatalog"
	"github.com/osolmaz/brokerkit/brokers/github/internal/schemaregistry"
	"github.com/osolmaz/brokerkit/credentialstore"
	"github.com/osolmaz/brokerkit/internal/strictjson"
	"github.com/osolmaz/brokerkit/mcpoperation"
	"github.com/osolmaz/brokerkit/streamstore"
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
type mcpOperationInput struct {
	Target          json.RawMessage     `json:"target"`
	Arguments       json.RawMessage     `json:"arguments"`
	SealedArguments json.RawMessage     `json:"sealed_arguments"`
	CredentialSlot  string              `json:"credential_slot"`
	StreamInput     *mcpStreamReference `json:"stream_input"`
	Reason          string              `json:"reason"`
	RequestID       string              `json:"request_id"`
}

type mcpStreamReference struct {
	ID         string `json:"id"`
	Owner      string `json:"owner"`
	Purpose    string `json:"purpose"`
	TransferID string `json:"transfer_id"`
	Digest     string `json:"digest"`
	Size       int64  `json:"size"`
	MediaType  string `json:"media_type"`
	ExpiresAt  int64  `json:"expires_at"`
}

func (reference mcpStreamReference) canonical() streamstore.Reference {
	return streamstore.Reference{ID: reference.ID, Owner: reference.Owner, Purpose: reference.Purpose,
		RequestKey: reference.TransferID, Digest: reference.Digest, Size: reference.Size,
		MediaType: reference.MediaType, ExpiresAt: reference.ExpiresAt}
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
		if err != nil {
			value = mcpoperation.ErrorValue(err)
		}
		response.Result = mcpToolResult(value, err)
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
	if call.Name == "gh_operation_get" || call.Name == "gh_operation_wait" || call.Name == "gh_operation_list" {
		connection, err := loadOperationConnection(getenv)
		if err != nil {
			return nil, err
		}
		client, err := connection.client()
		if err != nil {
			return nil, err
		}
		return callMCPUtility(ctx, client, call)
	}
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
	var input mcpOperationInput
	if strictjson.Decode(call.Arguments, &input, true) != nil || strings.TrimSpace(input.Reason) == "" || len(input.Reason) > 2000 {
		return nil, errors.New("invalid typed tool arguments")
	}
	requestID, err := mcpoperation.ResolveRequestID(input.RequestID)
	if err != nil {
		return nil, err
	}
	if len(input.Arguments) == 0 {
		input.Arguments = json.RawMessage(`{}`)
	}
	input.RequestID = requestID
	input.Arguments, err = mcpprojection.ArgumentsToCanonical(descriptor.Descriptor, input.Arguments)
	if err != nil {
		return nil, err
	}
	connection, err := loadOperationConnection(getenv)
	if err != nil {
		return nil, err
	}
	if err := prepareMCPArguments(ctx, descriptor, &input, connection); err != nil {
		return nil, err
	}
	client, err := connection.client()
	if err != nil {
		return nil, err
	}
	operation, err := client.Submit(ctx, agentv1.SubmitRequest{IdempotencyKey: requestID, Operation: descriptor.Name, Target: input.Target, Arguments: input.Arguments, Reason: input.Reason})
	if err != nil {
		return nil, mcpoperation.Conflict(ctx, client, requestID, err)
	}
	return mcpoperation.Project(operation, mcpprojection.ResultToMCP)
}

func callMCPUtility(ctx context.Context, client *agentclient.Client, call mcpToolCall) (any, error) {
	switch call.Name {
	case "gh_operation_get":
		return callMCPUtilityInput(call.Arguments, func(input mcpoperation.GetInput) (any, error) {
			return mcpoperation.Get(ctx, client, input, mcpprojection.ResultToMCP)
		})
	case "gh_operation_wait":
		return callMCPUtilityInput(call.Arguments, func(input mcpoperation.WaitInput) (any, error) {
			return mcpoperation.Wait(ctx, client, input, mcpprojection.ResultToMCP)
		})
	case "gh_operation_list":
		return callMCPUtilityInput(call.Arguments, func(input mcpoperation.ListInput) (any, error) {
			return mcpoperation.List(ctx, client, input)
		})
	default:
		return nil, errors.New("unknown operation utility")
	}
}

func callMCPUtilityInput[T any](raw json.RawMessage, execute func(T) (any, error)) (any, error) {
	var input T
	if strictjson.Decode(raw, &input, true) != nil {
		return nil, errors.New("invalid tool arguments")
	}
	return execute(input)
}

func prepareMCPArguments(ctx context.Context, descriptor opcatalog.Descriptor, input *mcpOperationInput, connection operationConnection) error {
	switch {
	case streamDirectionForOperation(descriptor.Name) == "upload":
		return prepareMCPStreamArguments(descriptor, input)
	case descriptor.CredentialOutputKind != nil:
		return prepareMCPCredentialArguments(descriptor, input)
	case descriptor.Sealed:
		return prepareMCPSealedArguments(ctx, descriptor, input, connection)
	default:
		if len(input.SealedArguments) != 0 || input.CredentialSlot != "" || input.StreamInput != nil {
			return errors.New("operation does not accept sealed_arguments")
		}
		return schemaregistry.ValidateSubmission(descriptor.Name, input.Target, input.Arguments)
	}
}

func prepareMCPStreamArguments(descriptor opcatalog.Descriptor, input *mcpOperationInput) error {
	if input.StreamInput == nil || len(input.SealedArguments) != 0 || input.CredentialSlot != "" {
		return errors.New("stream_input is required")
	}
	if err := schemaregistry.ValidateStreamPublic(descriptor.Name, input.Target, input.Arguments); err != nil {
		return err
	}
	encoded, err := json.Marshal(map[string]any{"public": input.Arguments, "stream_input": input.StreamInput.canonical()})
	input.Arguments = encoded
	return err
}

func prepareMCPCredentialArguments(descriptor opcatalog.Descriptor, input *mcpOperationInput) error {
	if len(input.SealedArguments) != 0 || !credentialstore.ValidSlot(input.CredentialSlot) {
		return errors.New("credential_slot is required and sealed_arguments are not accepted")
	}
	if err := schemaregistry.ValidatePublicSubmission(descriptor.Name, input.Target, input.Arguments); err != nil {
		return err
	}
	encoded, err := json.Marshal(map[string]any{"public": input.Arguments, "credential_slot": input.CredentialSlot})
	input.Arguments = encoded
	return err
}

func prepareMCPSealedArguments(ctx context.Context, descriptor opcatalog.Descriptor, input *mcpOperationInput, connection operationConnection) error {
	if err := schemaregistry.ValidatePublicSubmission(descriptor.Name, input.Target, input.Arguments); err != nil {
		return err
	}
	required, err := schemaregistry.SealedArgumentsRequired(descriptor.Name)
	if err != nil {
		return err
	}
	if required && len(input.SealedArguments) == 0 {
		return errors.New("sealed_arguments are required")
	}
	if len(input.SealedArguments) == 0 {
		input.Arguments, err = json.Marshal(map[string]any{"public": input.Arguments})
		return err
	}
	if err := schemaregistry.ValidateSealedArguments(descriptor.Name, input.SealedArguments); err != nil {
		return err
	}
	input.Arguments, err = connection.wrapSealedArguments(ctx, descriptor.Name, input.RequestID, input.Arguments, input.SealedArguments)
	return err
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
