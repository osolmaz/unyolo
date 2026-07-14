// Package mcpoperation owns the provider-neutral MCP operation projection and
// recovery mechanics layered over Agent Operations V1.
package mcpoperation

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"regexp"
	"strings"
	"time"

	"github.com/osolmaz/brokerkit/agentclient"
	"github.com/osolmaz/brokerkit/agentv1"
)

const (
	OperationAPIVersion = "brokerkit.io/mcp-operation/v1"
	PageAPIVersion      = "brokerkit.io/mcp-operation-page/v1"
	DefaultWaitSeconds  = 25
	MaxWaitSeconds      = 25
	DefaultListLimit    = 20
	MaxListLimit        = 50
)

var requestIDPattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$`)

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
		if !requestIDPattern.MatchString(value) {
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
	projected := projectSummary(agentv1.OperationSummary{
		APIVersion: operation.APIVersion, ID: operation.ID, Broker: operation.Broker, ClientID: operation.ClientID,
		IdempotencyKey: operation.IdempotencyKey, Operation: operation.Operation, State: operation.State,
		Revision: operation.Revision, CreatedAt: operation.CreatedAt, UpdatedAt: operation.UpdatedAt,
		TerminalAt: operation.TerminalAt, Presentation: operation.Presentation,
	})
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

func projectSummary(operation agentv1.OperationSummary) Operation {
	return Operation{
		APIVersion: OperationAPIVersion, ID: operation.ID, RequestID: operation.IdempotencyKey,
		Operation: operation.Operation, State: operation.State, Revision: operation.Revision,
		CreatedAt: operation.CreatedAt, UpdatedAt: operation.UpdatedAt, TerminalAt: operation.TerminalAt,
		Presentation: Presentation{Title: operation.Presentation.Title, Summary: operation.Presentation.Summary},
	}
}

func Get(ctx context.Context, client Client, input GetInput, projector ResultProjector) (Operation, error) {
	if strings.TrimSpace(input.OperationID) == "" || len(input.OperationID) > 128 {
		return Operation{}, errors.New("operation_id is invalid")
	}
	operation, err := client.Get(ctx, input.OperationID)
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
	waitCtx, cancel := context.WithTimeout(ctx, time.Duration(seconds)*time.Second)
	defer cancel()
	updated, waitErr := client.Wait(waitCtx, operation)
	if waitCtx.Err() != nil && updated.ID != "" {
		waitErr = nil
	}
	if waitErr != nil {
		return Operation{}, waitErr
	}
	return Project(updated, projector)
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
	limit := DefaultListLimit
	if input.Limit != nil {
		limit = *input.Limit
	}
	input.RequestID = strings.TrimSpace(input.RequestID)
	input.Cursor = strings.TrimSpace(input.Cursor)
	if len(input.RequestID) > 128 || (input.RequestID != "" && !requestIDPattern.MatchString(input.RequestID)) ||
		len(input.Cursor) > 128 || limit < 1 || limit > MaxListLimit {
		return Page{}, errors.New("operation list input is invalid")
	}
	page, err := client.List(ctx, agentv1.ListOptions{
		IdempotencyKey: input.RequestID, State: input.State, Limit: limit, Cursor: input.Cursor,
	})
	if err != nil {
		return Page{}, err
	}
	result := Page{APIVersion: PageAPIVersion, Operations: make([]Operation, 0, len(page.Operations)), NextCursor: page.NextCursor}
	for _, operation := range page.Operations {
		result.Operations = append(result.Operations, projectSummary(operation))
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
	if err != nil || len(page.Operations) != 1 {
		return &RequestIDConflictError{}
	}
	existing := page.Operations[0]
	return &RequestIDConflictError{Existing: ConflictExisting{
		ID: existing.ID, RequestID: existing.IdempotencyKey, Operation: existing.Operation,
		State: existing.State, Revision: existing.Revision,
	}}
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
