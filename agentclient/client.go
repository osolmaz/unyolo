// Package agentclient provides the provider-neutral Agent Operations V1 client.
package agentclient

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"strings"

	"github.com/osolmaz/brokerkit/agentv1"
	"github.com/osolmaz/brokerkit/agentv1wire"
	"github.com/osolmaz/brokerkit/clienthttp"
	"github.com/osolmaz/brokerkit/httpx"
	"github.com/osolmaz/brokerkit/internal/strictjson"
	"github.com/osolmaz/brokerkit/protocol/agentwire"
)

const maxResponseBytes = 2 * 1024 * 1024

// Options configures an Agent Operations V1 client.
type Options struct {
	BaseURL    string
	Credential string
	HTTPClient *http.Client
}

// Client owns provider-neutral operation transport and wait mechanics.
type Client struct{ api agentwire.ClientInterface }

// Error is one stable Agent V1 error envelope.
type Error struct {
	Status  int
	Code    string
	Message string
}

func (e *Error) Error() string { return e.Message }

// New validates and constructs an Agent Operations V1 client.
func New(options Options) (*Client, error) {
	base, err := clienthttp.ParseBaseURL(options.BaseURL)
	if err != nil {
		return nil, err
	}
	if len(options.Credential) < 32 {
		return nil, errors.New("agent credential is invalid")
	}
	httpClient := clienthttp.Secure(options.HTTPClient)
	api, err := agentwire.NewClient(strings.TrimRight(base.String(), "/"), agentwire.WithHTTPClient(httpClient),
		agentwire.WithRequestEditorFn(func(_ context.Context, request *http.Request) error {
			request.Header.Set("Authorization", "Bearer "+options.Credential)
			return nil
		}))
	if err != nil {
		return nil, errors.New("agent base URL is invalid")
	}
	return &Client{api: api}, nil
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
	//nolint:bodyclose // decodeHTTPResponse owns and closes generated responses.
	response, err := c.api.GetAgentOperation(ctx, id)
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
	if err != nil {
		return agentv1.Operation{}, err
	}
	if response == nil {
		return agentv1.Operation{}, errors.New("agent source returned no response")
	}
	defer func() { _ = response.Body.Close() }()
	data, err := httpx.ReadLimited(response.Body, maxResponseBytes)
	if err != nil {
		return agentv1.Operation{}, err
	}
	return decodeResponse(response.StatusCode, data)
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
