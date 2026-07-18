// Package agentmcp bridges provider-owned MCP tools to Agent Operations V1.
package agentmcp

import (
	"context"
	"encoding/json"
	"errors"
	"strings"

	"github.com/osolmaz/brokerkit/agentclient"
	"github.com/osolmaz/brokerkit/agentv1"
	"github.com/osolmaz/brokerkit/internal/strictjson"
	"github.com/osolmaz/brokerkit/mcpoperation"
	"github.com/osolmaz/brokerkit/mcpserver"
)

const MaxReasonBytes = 2000

// Input is the shared closed MCP operation envelope. Provider preparation
// validates and canonicalizes each provider-owned field before submission.
type Input struct {
	Target          json.RawMessage `json:"target"`
	Arguments       json.RawMessage `json:"arguments"`
	SealedArguments json.RawMessage `json:"sealed_arguments"`
	CredentialSlot  string          `json:"credential_slot"`
	StreamInput     json.RawMessage `json:"stream_input"`
	Reason          string          `json:"reason"`
	RequestID       string          `json:"request_id"`
}

type Selection struct {
	Operation string
	Provider  any
}

type Config struct {
	Prefix    string
	Client    func(context.Context) (*agentclient.Client, error)
	Select    func(string) (Selection, error)
	Prepare   func(context.Context, Selection, *Input) error
	Project   mcpoperation.ResultProjector
	Utilities map[string]func(context.Context, json.RawMessage) (any, error)
}

type Bridge struct{ config Config }

func New(config Config) (*Bridge, error) {
	if config.Prefix == "" || config.Client == nil || config.Select == nil || config.Prepare == nil || config.Project == nil {
		return nil, errors.New("agent MCP bridge configuration is incomplete")
	}
	return &Bridge{config: config}, nil
}

func (b *Bridge) Call(ctx context.Context, call mcpserver.ToolCall) (any, error) {
	if utility, found := b.config.Utilities[call.Name]; found {
		return utility(ctx, call.Arguments)
	}
	if strings.HasPrefix(call.Name, b.config.Prefix+"operation_") {
		return b.callLifecycle(ctx, call.Name, call.Arguments)
	}
	selection, err := b.config.Select(call.Name)
	if err != nil {
		return nil, err
	}
	input, requestID, err := decodeInput(call.Arguments)
	if err != nil {
		return nil, err
	}
	if err := b.config.Prepare(ctx, selection, &input); err != nil {
		return nil, err
	}
	client, err := b.config.Client(ctx)
	if err != nil {
		return nil, err
	}
	operation, err := client.Submit(ctx, agentv1.SubmitRequest{
		IdempotencyKey: requestID,
		Operation:      selection.Operation,
		Target:         input.Target,
		Arguments:      input.Arguments,
		Reason:         input.Reason,
	})
	if err != nil {
		return nil, mcpoperation.Conflict(ctx, client, requestID, err)
	}
	return mcpoperation.Project(operation, b.config.Project)
}

func decodeInput(raw json.RawMessage) (Input, string, error) {
	var input Input
	if strictjson.Decode(raw, &input, true) != nil {
		return Input{}, "", errors.New("invalid typed tool arguments")
	}
	input.Reason = strings.TrimSpace(input.Reason)
	if input.Reason == "" || len(input.Reason) > MaxReasonBytes {
		return Input{}, "", errors.New("reason is invalid")
	}
	requestID, err := mcpoperation.ResolveRequestID(input.RequestID)
	if err != nil {
		return Input{}, "", err
	}
	if len(input.Arguments) == 0 {
		input.Arguments = json.RawMessage(`{}`)
	}
	input.RequestID = requestID
	return input, requestID, nil
}

func (b *Bridge) callLifecycle(ctx context.Context, name string, raw json.RawMessage) (any, error) {
	client, err := b.config.Client(ctx)
	if err != nil {
		return nil, err
	}
	switch name {
	case b.config.Prefix + "operation_get":
		return lifecycleInput(raw, func(input mcpoperation.GetInput) (any, error) {
			return mcpoperation.Get(ctx, client, input, b.config.Project)
		})
	case b.config.Prefix + "operation_wait":
		return lifecycleInput(raw, func(input mcpoperation.WaitInput) (any, error) {
			return mcpoperation.Wait(ctx, client, input, b.config.Project)
		})
	case b.config.Prefix + "operation_list":
		return lifecycleInput(raw, func(input mcpoperation.ListInput) (any, error) {
			return mcpoperation.List(ctx, client, input)
		})
	case b.config.Prefix + "operation_cancel":
		return lifecycleInput(raw, func(input mcpoperation.GetInput) (any, error) {
			return mcpoperation.Cancel(ctx, client, input, b.config.Project)
		})
	default:
		return nil, errors.New("unknown operation utility")
	}
}

func lifecycleInput[T any](raw json.RawMessage, execute func(T) (any, error)) (any, error) {
	var input T
	if strictjson.Decode(raw, &input, true) != nil {
		return nil, errors.New("invalid tool arguments")
	}
	return execute(input)
}
