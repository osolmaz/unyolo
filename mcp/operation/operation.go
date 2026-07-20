// Package mcpoperation owns the provider-neutral MCP operation projection and
// recovery mechanics layered over Agent Operations V1.
package mcpoperation

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/osolmaz/brokerkit/agent/client"
	"github.com/osolmaz/brokerkit/agent/v1"
)

const (
	OperationAPIVersion = "brokerkit.io/mcp-operation/v1"
	PageAPIVersion      = "brokerkit.io/mcp-operation-page/v1"
	DefaultWaitSeconds  = 25
	MaxWaitSeconds      = 25
	DefaultListLimit    = 20
	MaxListLimit        = 50
)

type Presentation struct {
	Title   string `json:"title"`
	Summary string `json:"summary,omitempty"`
}

type OperationError struct {
	Code    string `json:"code"`
	Message string `json:"message"`
}

// Operation is the closed transcript-safe MCP lifecycle document. It omits
// requester identity, canonical arguments, approvals, and internal plan data.
type Operation struct {
	APIVersion   string          `json:"api_version"`
	ID           string          `json:"id"`
	RequestID    string          `json:"request_id"`
	Operation    string          `json:"operation"`
	State        agentv1.State   `json:"state"`
	Revision     int64           `json:"revision"`
	CreatedAt    time.Time       `json:"created_at"`
	UpdatedAt    time.Time       `json:"updated_at"`
	TerminalAt   *time.Time      `json:"terminal_at,omitempty"`
	Presentation Presentation    `json:"presentation"`
	Result       json.RawMessage `json:"result,omitempty"`
	Error        *OperationError `json:"error,omitempty"`
}

type Page struct {
	APIVersion string      `json:"api_version"`
	Operations []Operation `json:"operations"`
	NextCursor *string     `json:"next_cursor"`
}

type GetInput struct {
	OperationID string `json:"operation_id"`
}

type WaitInput struct {
	OperationID    string `json:"operation_id"`
	TimeoutSeconds *int   `json:"timeout_seconds"`
}

type ListInput struct {
	RequestID string        `json:"request_id"`
	State     agentv1.State `json:"state"`
	Limit     *int          `json:"limit"`
	Cursor    string        `json:"cursor"`
}

type ResultProjector func(string, json.RawMessage) (json.RawMessage, error)

type Client interface {
	Get(context.Context, string) (agentv1.Operation, error)
	List(context.Context, agentv1.ListOptions) (agentv1.OperationPage, error)
	Wait(context.Context, agentv1.Operation) (agentv1.Operation, error)
}

type CancelClient interface {
	Client
	Cancel(context.Context, string) (agentv1.Operation, error)
}

type ConflictExisting struct {
	ID        string        `json:"id"`
	RequestID string        `json:"request_id"`
	Operation string        `json:"operation"`
	State     agentv1.State `json:"state"`
	Revision  int64         `json:"revision"`
}

type RequestIDConflictError struct {
	Existing ConflictExisting
}

func (e *RequestIDConflictError) Error() string {
	return "request_id is already bound to a different operation"
}

// ResolveRequestID validates a supplied exact retry ID or generates one from
// secure entropy when omitted.
func ResolveRequestID(value string) (string, error) { return resolveRequestID(value, rand.Reader) }

func resolveRequestID(value string, entropy io.Reader) (string, error) {
	value = strings.TrimSpace(value)
	if value != "" {
		if !agentv1.ValidIdempotencyKey(value) {
			return "", errors.New("request_id is invalid")
		}
		return value, nil
	}
	var data [18]byte
	if _, err := io.ReadFull(entropy, data[:]); err != nil {
		return "", errors.New("could not generate request_id")
	}
	return "req_" + base64.RawURLEncoding.EncodeToString(data[:]), nil
}

func Project(operation agentv1.Operation, projector ResultProjector) (Operation, error) {
	projected, err := projectSummary(agentv1.OperationSummary{
		APIVersion: operation.APIVersion, ID: operation.ID, Broker: operation.Broker, ClientID: operation.ClientID,
		IdempotencyKey: operation.IdempotencyKey, Operation: operation.Operation, State: operation.State,
		Revision: operation.Revision, CreatedAt: operation.CreatedAt, UpdatedAt: operation.UpdatedAt,
		TerminalAt: operation.TerminalAt, Presentation: operation.Presentation,
	})
	if err != nil {
		return Operation{}, err
	}
	if len(operation.Result) > 0 {
		if projector == nil {
			return Operation{}, errors.New("MCP result projector is required")
		}
		result, err := projector(operation.Operation, operation.Result)
		if err != nil {
			return Operation{}, err
		}
		projected.Result = result
	}
	if operation.Error != nil {
		projected.Error = &OperationError{Code: operation.Error.Code, Message: operation.Error.Message}
	}
	return projected, nil
}

func projectSummary(operation agentv1.OperationSummary) (Operation, error) {
	if !agentv1.ValidIdempotencyKey(operation.IdempotencyKey) {
		return Operation{}, errors.New("operation request_id is invalid")
	}
	return Operation{
		APIVersion: OperationAPIVersion, ID: operation.ID, RequestID: operation.IdempotencyKey,
		Operation: operation.Operation, State: operation.State, Revision: operation.Revision,
		CreatedAt: operation.CreatedAt, UpdatedAt: operation.UpdatedAt, TerminalAt: operation.TerminalAt,
		Presentation: Presentation{Title: operation.Presentation.Title, Summary: operation.Presentation.Summary},
	}, nil
}

func Get(ctx context.Context, client Client, input GetInput, projector ResultProjector) (Operation, error) {
	return operationByID(ctx, input, projector, client.Get)
}

func Cancel(ctx context.Context, client CancelClient, input GetInput, projector ResultProjector) (Operation, error) {
	return operationByID(ctx, input, projector, client.Cancel)
}

func operationByID(ctx context.Context, input GetInput, projector ResultProjector,
	load func(context.Context, string) (agentv1.Operation, error)) (Operation, error) {
	if strings.TrimSpace(input.OperationID) == "" || len(input.OperationID) > 128 {
		return Operation{}, errors.New("operation_id is invalid")
	}
	operation, err := load(ctx, strings.TrimSpace(input.OperationID))
	if err != nil {
		return Operation{}, err
	}
	return Project(operation, projector)
}

func Wait(ctx context.Context, client Client, input WaitInput, projector ResultProjector) (Operation, error) {
	operationID, seconds, err := waitParameters(input)
	if err != nil {
		return Operation{}, err
	}
	operation, err := client.Get(ctx, operationID)
	if err != nil {
		return Operation{}, err
	}
	if operation.State.Terminal() || seconds == 0 {
		return Project(operation, projector)
	}
	updated, err := waitForUpdate(ctx, client, operation, seconds)
	if err != nil {
		return Operation{}, err
	}
	return Project(updated, projector)
}

func waitForUpdate(ctx context.Context, client Client, operation agentv1.Operation, seconds int) (agentv1.Operation, error) {
	waitCtx, cancel := context.WithTimeout(ctx, time.Duration(seconds)*time.Second)
	defer cancel()
	updated, waitErr := client.Wait(waitCtx, operation)
	if waitCtx.Err() != nil && updated.ID != "" {
		return updated, nil
	}
	if waitErr != nil {
		return agentv1.Operation{}, waitErr
	}
	return updated, nil
}

func waitParameters(input WaitInput) (string, int, error) {
	seconds := DefaultWaitSeconds
	if input.TimeoutSeconds != nil {
		seconds = *input.TimeoutSeconds
	}
	operationID := strings.TrimSpace(input.OperationID)
	if operationID == "" || len(operationID) > 128 || seconds < 0 || seconds > MaxWaitSeconds {
		return "", 0, errors.New("operation wait input is invalid")
	}
	return operationID, seconds, nil
}

func List(ctx context.Context, client Client, input ListInput) (Page, error) {
	options, err := listParameters(input)
	if err != nil {
		return Page{}, err
	}
	page, err := client.List(ctx, options)
	if err != nil {
		return Page{}, err
	}
	return projectPage(page)
}

func listParameters(input ListInput) (agentv1.ListOptions, error) {
	limit := DefaultListLimit
	if input.Limit != nil {
		limit = *input.Limit
	}
	input.RequestID = strings.TrimSpace(input.RequestID)
	input.Cursor = strings.TrimSpace(input.Cursor)
	if !validListParameters(input.RequestID, input.Cursor, limit) {
		return agentv1.ListOptions{}, errors.New("operation list input is invalid")
	}
	return agentv1.ListOptions{
		IdempotencyKey: input.RequestID, State: input.State, Limit: limit, Cursor: input.Cursor,
	}, nil
}

func validListParameters(requestID, cursor string, limit int) bool {
	if len(requestID) > 128 || len(cursor) > 128 {
		return false
	}
	if requestID != "" && !agentv1.ValidIdempotencyKey(requestID) {
		return false
	}
	return limit >= 1 && limit <= MaxListLimit
}

func projectPage(page agentv1.OperationPage) (Page, error) {
	result := Page{APIVersion: PageAPIVersion, Operations: make([]Operation, 0, len(page.Operations)), NextCursor: page.NextCursor}
	for _, operation := range page.Operations {
		projected, err := projectSummary(operation)
		if err != nil {
			return Page{}, err
		}
		result.Operations = append(result.Operations, projected)
	}
	return result, nil
}

// Conflict converts Agent V1 idempotency conflicts into the bounded MCP
// request-ID contract and leaves all unrelated failures unchanged.
func Conflict(ctx context.Context, client Client, requestID string, cause error) error {
	var apiErr *agentclient.Error
	if !errors.As(cause, &apiErr) || apiErr.Code != "idempotency_conflict" {
		return cause
	}
	page, err := client.List(ctx, agentv1.ListOptions{IdempotencyKey: requestID, Limit: 1})
	existing, recovered := recoveredConflict(page, err)
	if !recovered {
		return fmt.Errorf("could not recover request_id conflict: %w", cause)
	}
	return &RequestIDConflictError{Existing: ConflictExisting{
		ID: existing.ID, RequestID: existing.IdempotencyKey, Operation: existing.Operation,
		State: existing.State, Revision: existing.Revision,
	}}
}

func recoveredConflict(page agentv1.OperationPage, err error) (agentv1.OperationSummary, bool) {
	if err != nil || len(page.Operations) != 1 {
		return agentv1.OperationSummary{}, false
	}
	existing := page.Operations[0]
	return existing, validConflictSummary(existing)
}

func validConflictSummary(existing agentv1.OperationSummary) bool {
	return agentv1.ValidIdempotencyKey(existing.IdempotencyKey) && existing.ID != "" && existing.Operation != "" &&
		existing.Revision >= 1 && existing.State.Valid()
}

func ErrorValue(err error) map[string]any {
	var conflict *RequestIDConflictError
	if errors.As(err, &conflict) {
		return map[string]any{
			"code": "request_id_conflict", "message": conflict.Error(), "existing": conflict.Existing,
		}
	}
	return map[string]any{"error": err.Error()}
}
