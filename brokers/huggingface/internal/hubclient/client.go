// Package hubclient owns the bounded authenticated Hugging Face HTTP boundary.
package hubclient

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
)

const (
	maxRequestBytes  = 1 << 20
	maxResponseBytes = 2 << 20
)

type ErrorCode string

const (
	CodeAuthentication ErrorCode = "operation_upstream_authentication_failed"
	CodeAuthorization  ErrorCode = "operation_upstream_authorization_failed"
	CodeConflict       ErrorCode = "operation_upstream_conflict"
	CodeNotFound       ErrorCode = "operation_target_not_found"
	CodeRateLimited    ErrorCode = "operation_upstream_rate_limited"
	CodeRejected       ErrorCode = "operation_upstream_rejected"
	CodeUnavailable    ErrorCode = "operation_upstream_unavailable"
	CodeUnknownResult  ErrorCode = "upstream_result_unknown"
)

// Error deliberately excludes response bodies and credential-bearing details.
type Error struct {
	Code       ErrorCode
	StatusCode int
	RetryAfter time.Duration
	Ambiguous  bool
}

func (e *Error) Error() string {
	if e.StatusCode > 0 {
		return fmt.Sprintf("Hugging Face request failed (%s, status %d)", e.Code, e.StatusCode)
	}
	return fmt.Sprintf("Hugging Face request failed (%s)", e.Code)
}

// Call is constructed only by registered provider adapters. Requesters never
// control Method or PathTemplate.
type Call struct {
	Method        string
	Path          string
	Query         url.Values
	Body          json.RawMessage
	Idempotent    bool
	ResponseLimit int64
}

type Response struct {
	StatusCode int
	Body       json.RawMessage
	ETag       string
	RequestID  string
}

type Client struct {
	endpoint *url.URL
	token    string
	http     *http.Client
}

func New(endpoint, token string, client *http.Client) (*Client, error) {
	base, err := url.Parse(endpoint)
	if err != nil || (base.Scheme != "http" && base.Scheme != "https") || base.Host == "" || base.User != nil || base.RawQuery != "" || base.Fragment != "" {
		return nil, errors.New("invalid Hugging Face endpoint")
	}
	base.Path = strings.TrimRight(base.Path, "/")
	if client == nil {
		client = &http.Client{Timeout: 30 * time.Second}
	}
	clone := *client
	clone.CheckRedirect = func(*http.Request, []*http.Request) error { return errors.New("Hugging Face redirect refused") }
	return &Client{endpoint: base, token: token, http: &clone}, nil
}

func (c *Client) Do(ctx context.Context, call Call) (Response, error) {
	if c == nil || c.endpoint == nil {
		return Response{}, errors.New("Hugging Face client is unavailable")
	}
	if err := validateCall(call); err != nil {
		return Response{}, err
	}
	requestURL := *c.endpoint
	requestURL.Path = strings.TrimRight(c.endpoint.Path, "/") + call.Path
	requestURL.RawQuery = call.Query.Encode()
	var body io.Reader
	if len(call.Body) > 0 {
		body = bytes.NewReader(call.Body)
	}
	request, err := http.NewRequestWithContext(ctx, call.Method, requestURL.String(), body)
	if err != nil {
		return Response{}, err
	}
	request.Header.Set("Accept", "application/json")
	if len(call.Body) > 0 {
		request.Header.Set("Content-Type", "application/json")
	}
	if c.token != "" {
		request.Header.Set("Authorization", "Bearer "+c.token)
	}
	response, err := c.http.Do(request)
	if err != nil {
		return Response{}, transportError(call)
	}
	defer func() { _ = response.Body.Close() }()
	limit := call.ResponseLimit
	if limit <= 0 || limit > maxResponseBytes {
		limit = maxResponseBytes
	}
	data, err := io.ReadAll(io.LimitReader(response.Body, limit+1))
	if err != nil || int64(len(data)) > limit {
		return Response{}, transportError(call)
	}
	result := Response{StatusCode: response.StatusCode, Body: canonicalResponse(data), ETag: response.Header.Get("ETag"), RequestID: response.Header.Get("X-Request-Id")}
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		return Response{}, statusError(response)
	}
	return result, nil
}

func validateCall(call Call) error {
	if call.Method != http.MethodGet && call.Method != http.MethodPost && call.Method != http.MethodPut && call.Method != http.MethodPatch && call.Method != http.MethodDelete {
		return errors.New("invalid Hugging Face method")
	}
	if !strings.HasPrefix(call.Path, "/") || strings.Contains(call.Path, "?") || strings.Contains(call.Path, "#") || strings.Contains(call.Path, "..") || strings.ContainsAny(call.Path, "\r\n") {
		return errors.New("invalid Hugging Face path")
	}
	if len(call.Body) > maxRequestBytes {
		return errors.New("Hugging Face request body is too large")
	}
	if len(call.Body) > 0 && !json.Valid(call.Body) {
		return errors.New("Hugging Face request body is invalid")
	}
	return nil
}

func transportError(call Call) error {
	if call.Idempotent || call.Method == http.MethodGet {
		return &Error{Code: CodeUnavailable}
	}
	return &Error{Code: CodeUnknownResult, Ambiguous: true}
}

func statusError(response *http.Response) error {
	code := CodeRejected
	switch response.StatusCode {
	case http.StatusUnauthorized:
		code = CodeAuthentication
	case http.StatusForbidden:
		code = CodeAuthorization
	case http.StatusNotFound:
		code = CodeNotFound
	case http.StatusConflict:
		code = CodeConflict
	case http.StatusTooManyRequests:
		code = CodeRateLimited
	default:
		if response.StatusCode >= 500 {
			code = CodeUnavailable
		}
	}
	return &Error{Code: code, StatusCode: response.StatusCode, RetryAfter: retryAfter(response.Header.Get("Retry-After"))}
}

func retryAfter(value string) time.Duration {
	seconds, err := strconv.Atoi(strings.TrimSpace(value))
	if err != nil || seconds < 0 {
		return 0
	}
	return time.Duration(seconds) * time.Second
}

func canonicalResponse(data []byte) json.RawMessage {
	if len(bytes.TrimSpace(data)) == 0 {
		return json.RawMessage(`{}`)
	}
	var compact bytes.Buffer
	if json.Compact(&compact, data) != nil {
		return json.RawMessage(`{}`)
	}
	return compact.Bytes()
}
