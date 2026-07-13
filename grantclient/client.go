// Package grantclient provides provider-neutral temporary-grant HTTP mechanics.
package grantclient

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"mime"
	"net/http"
	"net/url"
	"path"
	"strings"
	"time"

	"github.com/osolmaz/brokerkit/clienthttp"
)

const maxResponseBytes = 2 * 1024 * 1024

// Decoder converts one successful broker response into a provider projection.
type Decoder[T any] func([]byte) (T, error)

// Options configures a temporary-grant client.
type Options[T any] struct {
	BaseURL      string
	Credential   string
	HTTPClient   *http.Client
	Decode       Decoder[T]
	Terminal     func(T) bool
	PollInterval time.Duration
}

// Client owns request, lookup, wait, cancel, and revoke transport mechanics.
type Client[T any] struct {
	base         *url.URL
	credential   string
	http         *http.Client
	decode       Decoder[T]
	terminal     func(T) bool
	pollInterval time.Duration
}

// Error is a bounded HTTP failure without response-body disclosure.
type Error struct{ Status int }

func (e *Error) Error() string {
	return fmt.Sprintf("grant request failed with status %d", e.Status)
}

// New validates and constructs a grant client.
func New[T any](options Options[T]) (*Client[T], error) {
	base, err := clienthttp.ParseBaseURL(options.BaseURL)
	if err != nil {
		return nil, err
	}
	if len(options.Credential) < 32 || options.Decode == nil || options.Terminal == nil {
		return nil, errors.New("grant client credential, decoder, and terminal predicate are required")
	}
	options.HTTPClient = clienthttp.Secure(options.HTTPClient)
	if options.PollInterval <= 0 {
		options.PollInterval = time.Second
	}
	return &Client[T]{
		base: base, credential: options.Credential, http: options.HTTPClient,
		decode: options.Decode, terminal: options.Terminal, pollInterval: options.PollInterval,
	}, nil
}

// Request creates or replays one provider-classified temporary grant.
func (c *Client[T]) Request(ctx context.Context, input any) (T, error) {
	body, err := json.Marshal(input)
	if err != nil {
		var zero T
		return zero, fmt.Errorf("encode grant request: %w", err)
	}
	return c.do(ctx, http.MethodPost, "/api/grants", body)
}

// Get retrieves one grant by its opaque handle.
func (c *Client[T]) Get(ctx context.Context, id string) (T, error) {
	return c.do(ctx, http.MethodGet, grantPath(id), nil)
}

// Wait polls a durable grant until it reaches a terminal or active state.
func (c *Client[T]) Wait(ctx context.Context, id string) (T, error) {
	for {
		value, err := c.Get(ctx, id)
		if err != nil || c.terminal(value) {
			return value, err
		}
		timer := time.NewTimer(c.pollInterval)
		select {
		case <-ctx.Done():
			timer.Stop()
			return value, ctx.Err()
		case <-timer.C:
		}
	}
}

// Cancel closes one pending grant owned by the authenticated client.
func (c *Client[T]) Cancel(ctx context.Context, id string) (T, error) {
	return c.do(ctx, http.MethodPost, grantPath(id)+"/cancel", []byte("{}"))
}

// Revoke closes one active grant owned by the authenticated client.
func (c *Client[T]) Revoke(ctx context.Context, id string) (T, error) {
	return c.do(ctx, http.MethodPost, grantPath(id)+"/revoke", []byte("{}"))
}

func (c *Client[T]) do(ctx context.Context, method, requestPath string, body []byte) (T, error) {
	var zero T
	request, err := c.newRequest(ctx, method, requestPath, body)
	if err != nil {
		return zero, err
	}
	response, err := c.http.Do(request)
	if err != nil {
		return zero, fmt.Errorf("send grant request: %w", err)
	}
	grant, decodeErr := c.decodeResponse(response)
	closeErr := response.Body.Close()
	if decodeErr != nil {
		return zero, decodeErr
	}
	if closeErr != nil {
		return zero, fmt.Errorf("close grant response: %w", closeErr)
	}
	return grant, nil
}

func (c *Client[T]) newRequest(ctx context.Context, method, requestPath string, body []byte) (*http.Request, error) {
	endpoint := *c.base
	endpoint.Path = path.Join(strings.TrimSuffix(endpoint.Path, "/"), requestPath)
	var reader io.Reader
	if body != nil {
		reader = bytes.NewReader(body)
	}
	request, err := http.NewRequestWithContext(ctx, method, endpoint.String(), reader)
	if err != nil {
		return nil, errors.New("build grant request")
	}
	request.Header.Set("Authorization", "Bearer "+c.credential)
	if body != nil {
		request.Header.Set("Content-Type", "application/json")
	}
	return request, nil
}

func (c *Client[T]) decodeResponse(response *http.Response) (T, error) {
	var zero T
	data, err := io.ReadAll(io.LimitReader(response.Body, maxResponseBytes+1))
	if err != nil || len(data) > maxResponseBytes {
		return zero, errors.New("read grant response")
	}
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		return zero, &Error{Status: response.StatusCode}
	}
	mediaType, _, err := mime.ParseMediaType(response.Header.Get("Content-Type"))
	if err != nil || mediaType != "application/json" {
		return zero, errors.New("grant response is not JSON")
	}
	value, err := c.decode(data)
	if err != nil {
		return zero, fmt.Errorf("decode grant response: %w", err)
	}
	return value, nil
}

func grantPath(id string) string {
	return "/api/grants/" + url.PathEscape(strings.TrimSpace(id))
}
