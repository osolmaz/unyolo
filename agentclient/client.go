// Package agentclient provides the provider-neutral Agent Operations V1 client.
package agentclient

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"time"

	"github.com/osolmaz/brokerkit/agentv1"
	"github.com/osolmaz/brokerkit/agentv1wire"
	"github.com/osolmaz/brokerkit/clienthttp"
	"github.com/osolmaz/brokerkit/httpx"
	"github.com/osolmaz/brokerkit/internal/strictjson"
	"github.com/osolmaz/brokerkit/protocol/agentwire"
)

// A stored operation may contain a 1 MiB argument object and a 2 MiB result,
// plus its target and lifecycle metadata.
const maxResponseBytes = 4 * 1024 * 1024

// Options configures an Agent Operations V1 client.
type Options struct {
	Endpoint   string
	Credential string
	HTTPClient *http.Client
}

// Client owns provider-neutral operation transport and wait mechanics.
type Client struct {
	api        agentwire.ClientInterface
	baseURL    string
	credential string
	httpClient *http.Client
	transfer   *http.Client
}

// Error is one stable Agent V1 error envelope.
type Error struct {
	Status  int
	Code    string
	Message string
}

func (e *Error) Error() string { return e.Message }

// New validates and constructs an Agent Operations V1 client.
func New(options Options) (*Client, error) {
	baseURL, httpClient, err := clienthttp.ForEndpoint(options.Endpoint, options.HTTPClient)
	if err != nil {
		return nil, err
	}
	if len(options.Credential) < 32 {
		return nil, errors.New("agent credential is invalid")
	}
	api, err := agentwire.NewClient(baseURL, agentwire.WithHTTPClient(httpClient),
		agentwire.WithRequestEditorFn(func(_ context.Context, request *http.Request) error {
			request.Header.Set("Authorization", "Bearer "+options.Credential)
			return nil
		}))
	if err != nil {
		return nil, errors.New("agent base URL is invalid")
	}
	transfer := *httpClient
	transfer.Timeout = 10 * time.Minute
	return &Client{api: api, baseURL: baseURL, credential: options.Credential, httpClient: httpClient, transfer: &transfer}, nil
}

// Submit creates or idempotently replays one provider operation.
func (c *Client) Submit(ctx context.Context, request agentv1.SubmitRequest) (agentv1.Operation, error) {
	wire, err := agentv1wire.SubmitToWire(request)
	if err != nil {
		return agentv1.Operation{}, err
	}
	//nolint:bodyclose // decodeHTTPResponse owns and closes generated responses.
	response, requestErr := c.api.SubmitAgentOperation(ctx, wire)
	return decodeHTTPResponse(response, requestErr)
}

// Get retrieves one operation owned by the authenticated client.
func (c *Client) Get(ctx context.Context, id string) (agentv1.Operation, error) {
	return c.operationByID(ctx, id, c.api.GetAgentOperation)
}

// List returns one authenticated newest-first operation summary page.
func (c *Client) List(ctx context.Context, options agentv1.ListOptions) (agentv1.OperationPage, error) {
	params := &agentwire.ListAgentOperationsParams{}
	if options.IdempotencyKey != "" {
		params.IdempotencyKey = &options.IdempotencyKey
	}
	if options.State != "" {
		state := agentwire.State(options.State)
		params.State = &state
	}
	if options.Limit != 0 {
		params.Limit = &options.Limit
	}
	if options.Cursor != "" {
		params.Cursor = &options.Cursor
	}
	//nolint:bodyclose // decodePageResponse owns and closes generated responses.
	response, err := c.api.ListAgentOperations(ctx, params)
	return decodePageResponse(response, err)
}

// Cancel cancels requester-owned work that has not started executing.
func (c *Client) Cancel(ctx context.Context, id string) (agentv1.Operation, error) {
	return c.operationByID(ctx, id, c.api.CancelAgentOperation)
}

func (c *Client) operationByID(ctx context.Context, id string, call func(context.Context, agentwire.OperationID, ...agentwire.RequestEditorFn) (*http.Response, error)) (agentv1.Operation, error) {
	//nolint:bodyclose // decodeHTTPResponse owns and closes generated responses.
	response, err := call(ctx, id)
	return decodeHTTPResponse(response, err)
}

// Wait follows revision-bounded long polls until operation terminates or ctx ends.
func (c *Client) Wait(ctx context.Context, operation agentv1.Operation) (agentv1.Operation, error) {
	for !operation.State.Terminal() {
		after, wait := int(operation.Revision), 30
		//nolint:bodyclose // decodeHTTPResponse owns and closes generated responses.
		response, requestErr := c.api.WaitForAgentOperation(ctx, operation.ID, &agentwire.WaitForAgentOperationParams{
			AfterRevision: &after, WaitSeconds: &wait,
		})
		next, err := decodeHTTPResponse(response, requestErr)
		if err != nil {
			if ctx.Err() != nil {
				return operation, ctx.Err()
			}
			return operation, err
		}
		operation = next
	}
	return operation, nil
}

func decodeHTTPResponse(response *http.Response, err error) (agentv1.Operation, error) {
	return decodeAgentResponse(response, err, decodeResponse)
}

func decodePageResponse(response *http.Response, err error) (agentv1.OperationPage, error) {
	return decodeAgentResponse(response, err, decodePage)
}

func decodeAgentResponse[T any](response *http.Response, responseErr error, decode func(int, []byte) (T, error)) (T, error) {
	var zero T
	status, data, err := readResponse(response, responseErr)
	if err != nil {
		return zero, err
	}
	return decode(status, data)
}

func readResponse(response *http.Response, err error) (int, []byte, error) {
	if err != nil {
		return 0, nil, err
	}
	if response == nil {
		return 0, nil, errors.New("agent source returned no response")
	}
	defer func() { _ = response.Body.Close() }()
	data, err := httpx.ReadLimited(response.Body, maxResponseBytes)
	if err != nil {
		return 0, nil, err
	}
	return response.StatusCode, data, nil
}

func decodePage(status int, data []byte) (agentv1.OperationPage, error) {
	if status < http.StatusOK || status >= http.StatusMultipleChoices {
		return agentv1.OperationPage{}, decodeError(status, data)
	}
	var wire agentwire.OperationPage
	if strictjson.Decode(data, &wire, false) != nil {
		return agentv1.OperationPage{}, errors.New("agent source returned an invalid operation page")
	}
	page := agentv1wire.OperationPageFromWire(wire)
	if page.APIVersion != agentv1.APIVersion || len(page.Operations) > 50 {
		return agentv1.OperationPage{}, errors.New("agent source returned an invalid operation page")
	}
	return page, nil
}

func decodeResponse(status int, data []byte) (agentv1.Operation, error) {
	if status < http.StatusOK || status >= http.StatusMultipleChoices {
		return agentv1.Operation{}, decodeError(status, data)
	}
	var wire agentwire.Operation
	if err := strictjson.Decode(data, &wire, false); err != nil {
		return agentv1.Operation{}, errors.New("agent source returned an invalid operation")
	}
	operation, err := agentv1wire.OperationFromWire(wire)
	if err != nil || operation.APIVersion != agentv1.APIVersion {
		return agentv1.Operation{}, errors.New("agent source returned an invalid operation")
	}
	return operation, nil
}

func decodeError(status int, data []byte) error {
	var envelope agentwire.ErrorEnvelope
	if strictjson.Decode(data, &envelope, false) == nil && envelope.Error.Message != "" {
		return &Error{Status: status, Code: envelope.Error.Code, Message: envelope.Error.Message}
	}
	return &Error{Status: status, Code: "invalid_response", Message: fmt.Sprintf("agent request failed with HTTP %d", status)}
}
