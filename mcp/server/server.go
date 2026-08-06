// Package mcpserver provides a provider-neutral, line-oriented MCP server.
package mcpserver

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"io"

	"github.com/osolmaz/unyolo/internal/strictjson"
)

const (
	ProtocolVersion     = "2025-06-18"
	DefaultMaxLineBytes = 4 << 20
)

type Request struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      json.RawMessage `json:"id,omitempty"`
	Method  string          `json:"method"`
	Params  json.RawMessage `json:"params,omitempty"`
}

type Response struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      json.RawMessage `json:"id,omitempty"`
	Result  any             `json:"result,omitempty"`
	Error   *Error          `json:"error,omitempty"`
}

type Error struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
}

type ToolCall struct {
	Name      string                     `json:"name"`
	Arguments json.RawMessage            `json:"arguments"`
	Meta      map[string]json.RawMessage `json:"_meta,omitempty"`
}

type ResourceRead struct {
	URI  string                     `json:"uri"`
	Meta map[string]json.RawMessage `json:"_meta,omitempty"`
}

type Config struct {
	Name         string
	Version      string
	MaxLineBytes int
	ListChanged  bool
	Tools        func(context.Context) ([]map[string]any, error)
	Call         func(context.Context, ToolCall) (any, error)
	Resources    func(context.Context) ([]map[string]any, error)
	ReadResource func(context.Context, ResourceRead) (any, error)
	ErrorValue   func(error) any
}

type Server struct{ config Config }

func New(config Config) (*Server, error) {
	if config.Name == "" || config.Version == "" || config.Tools == nil || config.Call == nil {
		return nil, errors.New("MCP server configuration is incomplete")
	}
	if config.MaxLineBytes <= 0 {
		config.MaxLineBytes = DefaultMaxLineBytes
	}
	if config.ErrorValue == nil {
		config.ErrorValue = func(err error) any { return map[string]any{"error": err.Error()} }
	}
	return &Server{config: config}, nil
}

func (s *Server) Serve(ctx context.Context, input io.Reader, output io.Writer) error {
	scanner := bufio.NewScanner(input)
	scanner.Buffer(make([]byte, 4096), s.config.MaxLineBytes)
	encoder := json.NewEncoder(output)
	signature, err := s.toolSignature(ctx)
	if err != nil {
		return err
	}
	for scanner.Scan() {
		if err := s.serveLine(ctx, encoder, scanner.Bytes(), &signature); err != nil {
			return err
		}
	}
	return scanner.Err()
}

func (s *Server) serveLine(ctx context.Context, encoder *json.Encoder, line []byte, signature *string) error {
	request, ok := parseRequest(line)
	if !ok {
		return encoder.Encode(Response{JSONRPC: "2.0", Error: &Error{Code: -32700, Message: "Parse error"}})
	}
	if len(request.ID) == 0 {
		return nil
	}
	if err := s.notifyToolChange(ctx, encoder, signature); err != nil {
		return err
	}
	return encoder.Encode(s.Handle(ctx, request))
}

func (s *Server) notifyToolChange(ctx context.Context, encoder *json.Encoder, signature *string) error {
	if !s.config.ListChanged {
		return nil
	}
	next, changed, err := s.toolsChanged(ctx, *signature)
	if err != nil {
		return err
	}
	if changed {
		if err := encoder.Encode(map[string]any{"jsonrpc": "2.0", "method": "notifications/tools/list_changed"}); err != nil {
			return err
		}
	}
	*signature = next
	return nil
}

func parseRequest(data []byte) (Request, bool) {
	var request Request
	if strictjson.Decode(data, &request, true) != nil || request.JSONRPC != "2.0" || request.Method == "" {
		return Request{}, false
	}
	return request, true
}

func (s *Server) Handle(ctx context.Context, request Request) Response {
	response := Response{JSONRPC: "2.0", ID: request.ID}
	switch request.Method {
	case "initialize":
		response.Result = s.initializeResult()
	case "ping":
		response.Result = map[string]any{}
	case "tools/list":
		tools, err := s.config.Tools(ctx)
		response.Result, response.Error = resultOrError(map[string]any{"tools": tools}, err, -32603)
	case "tools/call":
		response.Result, response.Error = s.callTool(ctx, request.Params)
	case "resources/list":
		response.Result, response.Error = s.listResources(ctx)
	case "resources/read":
		response.Result, response.Error = s.readResource(ctx, request.Params)
	default:
		response.Error = &Error{Code: -32601, Message: "Method not found"}
	}
	return response
}

func (s *Server) initializeResult() map[string]any {
	capabilities := map[string]any{"tools": map[string]any{"listChanged": s.config.ListChanged}}
	if s.config.Resources != nil {
		capabilities["resources"] = map[string]any{}
	}
	return map[string]any{
		"protocolVersion": ProtocolVersion,
		"capabilities":    capabilities,
		"serverInfo":      map[string]any{"name": s.config.Name, "version": s.config.Version},
	}
}

func (s *Server) callTool(ctx context.Context, raw json.RawMessage) (any, *Error) {
	var call ToolCall
	if strictjson.Decode(raw, &call, true) != nil || call.Name == "" {
		return nil, &Error{Code: -32602, Message: "Invalid tool call"}
	}
	value, err := s.config.Call(ctx, call)
	if err != nil {
		return ToolResult(s.config.ErrorValue(err), true), nil
	}
	return ToolResult(value, false), nil
}

func (s *Server) listResources(ctx context.Context) (any, *Error) {
	if s.config.Resources == nil {
		return nil, &Error{Code: -32601, Message: "Method not found"}
	}
	resources, err := s.config.Resources(ctx)
	return resultOrError(map[string]any{"resources": resources}, err, -32603)
}

func (s *Server) readResource(ctx context.Context, raw json.RawMessage) (any, *Error) {
	if s.config.ReadResource == nil {
		return nil, &Error{Code: -32601, Message: "Method not found"}
	}
	var input ResourceRead
	if strictjson.Decode(raw, &input, true) != nil || input.URI == "" {
		return nil, &Error{Code: -32602, Message: "Invalid resource request"}
	}
	value, err := s.config.ReadResource(ctx, input)
	return resultOrError(value, err, -32602)
}

func resultOrError(value any, err error, code int) (any, *Error) {
	if err != nil {
		return nil, &Error{Code: code, Message: err.Error()}
	}
	return value, nil
}

func ToolResult(value any, isError bool) map[string]any {
	data, _ := json.Marshal(value)
	return map[string]any{
		"content":           []map[string]any{{"type": "text", "text": string(data)}},
		"structuredContent": value,
		"isError":           isError,
	}
}

func (s *Server) toolSignature(ctx context.Context) (string, error) {
	tools, err := s.config.Tools(ctx)
	if err != nil {
		return "", err
	}
	data, err := json.Marshal(tools)
	return string(data), err
}

func (s *Server) toolsChanged(ctx context.Context, previous string) (string, bool, error) {
	next, err := s.toolSignature(ctx)
	return next, next != previous, err
}
