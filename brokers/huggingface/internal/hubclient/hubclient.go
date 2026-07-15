// Package hubclient is the typed, bounded Hugging Face Hub administration
// client used by hf-broker operation adapters.
//
// Every exported method owns one static HTTP method and path shape verified
// against the pinned upstream baseline (huggingface_hub commit c4ed724 and
// the 2026-07-13 OpenAPI snapshot). Callers supply validated identifiers and
// typed payload fields only; the package never accepts a caller-controlled
// HTTP method, URL, header set, or raw request path, and it never returns
// credential material or raw upstream response bodies through errors.
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
	defaultTimeout          = 30 * time.Second
	defaultMaxResponseBytes = 1 << 20
	maxRequestBodyBytes     = 1 << 20
)

// Client issues typed Hugging Face Hub administration calls with one
// broker-held credential. The credential is write-only: nothing on Client or
// its errors exposes it.
type Client struct {
	base             string
	origins          map[string]string
	token            string
	httpClient       *http.Client
	timeout          time.Duration
	maxResponseBytes int64
}

// Option adjusts non-security client settings.
type Option func(*Client)

// WithTimeout sets the per-call deadline applied when the caller's context
// has none.
func WithTimeout(timeout time.Duration) Option {
	return func(c *Client) {
		if timeout > 0 {
			c.timeout = timeout
		}
	}
}

// WithMaxResponseBytes caps decoded upstream response bodies.
func WithMaxResponseBytes(limit int64) Option {
	return func(c *Client) {
		if limit > 0 {
			c.maxResponseBytes = limit
		}
	}
}

// WithHTTPTransport installs a custom transport (for tests and proxies).
// Redirect refusal and timeouts remain owned by the client.
func WithHTTPTransport(transport http.RoundTripper) Option {
	return func(c *Client) {
		if transport != nil {
			c.httpClient.Transport = transport
		}
	}
}

// New builds a client for one upstream base URL and one broker-held token.
func New(baseURL, token string, options ...Option) (*Client, error) {
	parsed, err := url.Parse(baseURL)
	if err != nil || !validBaseOrigin(parsed) {
		return nil, errors.New("hubclient: upstream base URL must be a bare http(s) origin")
	}
	if strings.TrimSpace(token) == "" {
		return nil, errors.New("hubclient: upstream token is required")
	}
	client := &Client{
		base: strings.TrimRight(parsed.String(), "/"),
		origins: map[string]string{
			"inference_endpoints": "https://api.endpoints.huggingface.cloud/v2",
			"inference_catalog":   "https://endpoints.huggingface.co/api/catalog",
		},
		token:            token,
		timeout:          defaultTimeout,
		maxResponseBytes: defaultMaxResponseBytes,
		httpClient:       &http.Client{},
	}
	for _, option := range options {
		option(client)
	}
	client.httpClient.CheckRedirect = func(*http.Request, []*http.Request) error {
		return errors.New("upstream redirect refused")
	}
	return client, nil
}

func validBaseOrigin(parsed *url.URL) bool {
	return parsed != nil &&
		(parsed.Scheme == "https" || parsed.Scheme == "http") &&
		parsed.Host != "" &&
		parsed.RawQuery == "" &&
		parsed.Fragment == "" &&
		parsed.User == nil
}

// callSpec is an internal, fully broker-owned request description. Paths are
// composed only from static literals and validated, escaped identifiers.
type callSpec struct {
	method      string
	path        string
	origin      string
	query       url.Values
	body        any
	rawBody     []byte
	contentType string
	out         any
}

func (c *Client) call(ctx context.Context, spec callSpec) error {
	ctx, cancel := c.callContext(ctx)
	defer cancel()
	request, err := c.newRequest(ctx, spec)
	if err != nil {
		return err
	}
	response, err := c.httpClient.Do(request)
	if err != nil {
		return transportError(spec.method, 0)
	}
	defer func() { _ = response.Body.Close() }()
	payload, err := io.ReadAll(io.LimitReader(response.Body, c.maxResponseBytes+1))
	if err != nil {
		return transportError(spec.method, response.StatusCode)
	}
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		return statusError(response.StatusCode, response.Header)
	}
	return classifyDecodedResponse(spec.method, response.StatusCode, decodeResponse(payload, spec.out, c.maxResponseBytes, response.StatusCode))
}

func transportError(method string, status int) *Error {
	if method == http.MethodGet {
		return &Error{Code: CodeUnavailable, StatusCode: status}
	}
	return &Error{Code: CodeResultUnknown, StatusCode: status, Ambiguous: true}
}

func (c *Client) callContext(ctx context.Context) (context.Context, context.CancelFunc) {
	if ctx == nil {
		ctx = context.Background()
	}
	if _, hasDeadline := ctx.Deadline(); hasDeadline {
		return ctx, func() {}
	}
	return context.WithTimeout(ctx, c.timeout)
}

func classifyDecodedResponse(method string, status int, err error) error {
	if err != nil && method != http.MethodGet {
		var classified *Error
		if errors.As(err, &classified) && classified.Code == CodeResponseInvalid {
			return &Error{Code: CodeResultUnknown, StatusCode: status, Ambiguous: true}
		}
	}
	return err
}

func (c *Client) newRequest(ctx context.Context, spec callSpec) (*http.Request, error) {
	reader, err := requestBodyReader(spec)
	if err != nil {
		return nil, err
	}
	endpoint, err := c.requestEndpoint(spec)
	if err != nil {
		return nil, err
	}
	request, err := http.NewRequestWithContext(ctx, spec.method, endpoint, reader)
	if err != nil {
		return nil, fmt.Errorf("hubclient: request construction failed")
	}
	setRequestHeaders(request, c.token, spec)
	return request, nil
}

func requestBodyReader(spec callSpec) (io.Reader, error) {
	if spec.body != nil && len(spec.rawBody) > 0 {
		return nil, errors.New("hubclient: request has conflicting body encodings")
	}
	if len(spec.rawBody) > 0 {
		if len(spec.rawBody) > maxRequestBodyBytes {
			return nil, errors.New("hubclient: request body is invalid")
		}
		return bytes.NewReader(spec.rawBody), nil
	}
	if spec.body == nil {
		return nil, nil
	}
	encoded, err := json.Marshal(spec.body)
	if err != nil || len(encoded) > maxRequestBodyBytes {
		return nil, fmt.Errorf("hubclient: request body is invalid")
	}
	return bytes.NewReader(encoded), nil
}

func (c *Client) requestEndpoint(spec callSpec) (string, error) {
	base := c.base
	if spec.origin != "" {
		var found bool
		base, found = c.origins[spec.origin]
		if !found {
			return "", errors.New("hubclient: fixed upstream origin is unavailable")
		}
	}
	endpoint := base + spec.path
	if len(spec.query) > 0 {
		endpoint += "?" + spec.query.Encode()
	}
	return endpoint, nil
}

func setRequestHeaders(request *http.Request, token string, spec callSpec) {
	request.Header.Set("Authorization", "Bearer "+token)
	request.Header.Set("Accept", "application/json")
	if spec.body != nil || len(spec.rawBody) > 0 {
		contentType := spec.contentType
		if contentType == "" {
			contentType = "application/json"
		}
		request.Header.Set("Content-Type", contentType)
	}
}

func decodeResponse(payload []byte, out any, limit int64, status int) error {
	if out == nil {
		return nil
	}
	if int64(len(payload)) > limit {
		return &Error{Code: CodeResponseInvalid, StatusCode: status}
	}
	if err := json.Unmarshal(payload, out); err != nil {
		return &Error{Code: CodeResponseInvalid, StatusCode: status}
	}
	return nil
}

func statusError(status int, header http.Header) *Error {
	classified := &Error{StatusCode: status}
	if code, found := exactStatusCode(status); found {
		classified.Code = code
	}
	if status == http.StatusTooManyRequests {
		classified.Code = CodeRateLimited
		classified.RetryAfterSeconds = parseRetryAfter(header)
	} else if classified.Code == "" && status >= 500 {
		classified.Code = CodeUnavailable
	} else if classified.Code == "" && status >= 400 {
		classified.Code = CodeInvalid
	} else if classified.Code == "" {
		classified.Code = CodeResponseInvalid
	}
	return classified
}

func exactStatusCode(status int) (ErrorCode, bool) {
	code, found := map[int]ErrorCode{
		http.StatusUnauthorized: CodeUnauthorized,
		http.StatusForbidden:    CodeForbidden,
		http.StatusNotFound:     CodeNotFound,
		http.StatusConflict:     CodeConflict,
	}[status]
	return code, found
}

func parseRetryAfter(header http.Header) int {
	seconds, err := strconv.Atoi(strings.TrimSpace(header.Get("Retry-After")))
	if err != nil || seconds < 0 {
		return 0
	}
	return seconds
}
