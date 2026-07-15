package hubclient

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
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

type sandboxEndpoint struct {
	base  string
	token string
}

type sandboxRequest struct {
	method      string
	path        string
	query       url.Values
	body        any
	rawBody     []byte
	contentType string
	limit       int64
	timeout     time.Duration
}

func (c *Client) DeleteSandbox(ctx context.Context, ref SandboxRef) error {
	job, err := c.inspectSandboxJob(ctx, ref.Namespace, ref.JobID)
	if err != nil {
		return err
	}
	state, err := sandboxStateFromJob(job, ref.Namespace, ref.LocalID)
	if err != nil {
		return err
	}
	if state.Mode == modeDedicated {
		return c.CancelSandboxJob(ctx, ref)
	}
	endpoint, err := c.sandboxEndpoint(job, ref)
	if err != nil {
		return err
	}
	return c.sandboxServerJSON(ctx, endpoint, http.MethodDelete, "/v1/sandboxes/"+url.PathEscape(ref.LocalID), nil, nil, nil, c.maxResponseBytes)
}

func (c *Client) SandboxFileStat(ctx context.Context, ref SandboxRef, path string) (SandboxFileInfo, error) {
	if !validSandboxPath(path) {
		return SandboxFileInfo{}, errors.New("hubclient: sandbox file path is invalid")
	}
	endpoint, basePath, err := c.resolveSandboxEndpoint(ctx, ref)
	if err != nil {
		return SandboxFileInfo{}, err
	}
	query := url.Values{"path": []string{path}}
	var info SandboxFileInfo
	if err := c.sandboxServerJSON(ctx, endpoint, http.MethodGet, basePath+"/files/stat", query, nil, &info, 64*1024); err != nil {
		return SandboxFileInfo{}, err
	}
	if !validSandboxFileInfo(info, path) {
		return SandboxFileInfo{}, &Error{Code: CodeResponseInvalid, StatusCode: http.StatusOK}
	}
	return info, nil
}

func validSandboxFileInfo(info SandboxFileInfo, path string) bool {
	return info.Path == path && info.Size >= 0 && validSandboxFileType(info.Type)
}

func validSandboxFileType(value string) bool {
	return value == "file" || value == "dir" || value == "symlink"
}

func (c *Client) WriteSandboxFile(ctx context.Context, ref SandboxRef, path, mode string, content []byte) error {
	if !validSandboxPath(path) || !ValidSandboxFileMode(mode) || len(content) > maxRequestBodyBytes {
		return errors.New("hubclient: sandbox file write is invalid")
	}
	endpoint, basePath, err := c.resolveSandboxEndpoint(ctx, ref)
	if err != nil {
		return err
	}
	query := url.Values{"path": []string{path}}
	if mode != "" {
		query.Set("mode", mode)
	}
	_, err = c.sandboxServer(ctx, endpoint, sandboxRequest{method: http.MethodPut, path: basePath + "/files/write", query: query,
		rawBody: content, contentType: "application/octet-stream", limit: c.maxResponseBytes})
	return err
}

func (c *Client) MakeSandboxDirectory(ctx context.Context, ref SandboxRef, path string) error {
	if !validSandboxPath(path) {
		return errors.New("hubclient: sandbox directory path is invalid")
	}
	endpoint, basePath, err := c.resolveSandboxEndpoint(ctx, ref)
	if err != nil {
		return err
	}
	return c.sandboxServerJSON(ctx, endpoint, http.MethodPost, basePath+"/files/mkdir", url.Values{"path": []string{path}}, nil, nil, c.maxResponseBytes)
}

func (c *Client) DeleteSandboxFile(ctx context.Context, ref SandboxRef, path string, recursive bool) error {
	if !validSandboxPath(path) {
		return errors.New("hubclient: sandbox file path is invalid")
	}
	endpoint, basePath, err := c.resolveSandboxEndpoint(ctx, ref)
	if err != nil {
		return err
	}
	query := url.Values{"path": []string{path}}
	if recursive {
		query.Set("recursive", "1")
	}
	return c.sandboxServerJSON(ctx, endpoint, http.MethodDelete, basePath+"/files/delete", query, nil, nil, c.maxResponseBytes)
}

func (c *Client) SandboxProcesses(ctx context.Context, ref SandboxRef) ([]SandboxProcess, error) {
	endpoint, basePath, err := c.resolveSandboxEndpoint(ctx, ref)
	if err != nil {
		return nil, err
	}
	var processes []SandboxProcess
	if err := c.sandboxServerJSON(ctx, endpoint, http.MethodGet, basePath+"/processes", nil, nil, &processes, c.maxResponseBytes); err != nil {
		return nil, err
	}
	for _, process := range processes {
		if process.PID < 1 || !validSandboxProcessCommandValue(process.Command) {
			return nil, &Error{Code: CodeResponseInvalid, StatusCode: http.StatusOK}
		}
	}
	return processes, nil
}

func (c *Client) KillSandboxProcess(ctx context.Context, ref SandboxRef, pid int) error {
	if pid < 1 {
		return errors.New("hubclient: sandbox process id is invalid")
	}
	endpoint, basePath, err := c.resolveSandboxEndpoint(ctx, ref)
	if err != nil {
		return err
	}
	return c.sandboxServerJSON(ctx, endpoint, http.MethodDelete, basePath+"/processes/"+strconv.Itoa(pid), nil, nil, nil, c.maxResponseBytes)
}

func (c *Client) CreateSandboxInPool(ctx context.Context, host SandboxRef, environment map[string]string, idleTimeoutSeconds *int) (SandboxRef, error) {
	if err := c.validateSandboxPoolAllocation(host, environment, idleTimeoutSeconds); err != nil {
		return SandboxRef{}, err
	}
	job, err := c.inspectSandboxPoolHost(ctx, host)
	if err != nil {
		return SandboxRef{}, err
	}
	endpoint, err := c.sandboxEndpoint(job, host)
	if err != nil {
		return SandboxRef{}, err
	}
	response, err := c.createSandboxOnHost(ctx, endpoint, environment, idleTimeoutSeconds)
	if err != nil {
		return SandboxRef{}, err
	}
	if !validSandboxCreateResponse(response) {
		return SandboxRef{}, &Error{Code: CodeConflict, StatusCode: http.StatusConflict}
	}
	return SandboxRef{Namespace: host.Namespace, JobID: host.JobID, LocalID: response.Sandboxes[0].ID}, nil
}

type sandboxCreateResponse struct {
	Sandboxes []struct {
		ID string `json:"id"`
	} `json:"sandboxes"`
	Rejected int `json:"rejected"`
}

func (c *Client) validateSandboxPoolAllocation(host SandboxRef, environment map[string]string, idleTimeoutSeconds *int) error {
	if host.LocalID != "" || !validIdleTimeout(idleTimeoutSeconds) || validateSandboxEnvironment(environment, true) != nil {
		return errors.New("hubclient: pooled sandbox configuration is invalid")
	}
	for _, value := range environment {
		if value == c.token {
			return errors.New("hubclient: broker credential cannot be forwarded to a sandbox")
		}
	}
	return nil
}

func (c *Client) inspectSandboxPoolHost(ctx context.Context, host SandboxRef) (sandboxJobWire, error) {
	job, err := c.inspectSandboxJob(ctx, host.Namespace, host.JobID)
	if err != nil {
		return sandboxJobWire{}, err
	}
	state, err := sandboxStateFromJob(job, host.Namespace, "")
	if err != nil || state.Mode != modePool || state.Stage != "RUNNING" {
		return sandboxJobWire{}, errors.New("hubclient: sandbox pool host is unavailable")
	}
	return job, nil
}

func (c *Client) createSandboxOnHost(ctx context.Context, endpoint sandboxEndpoint, environment map[string]string, idleTimeoutSeconds *int) (sandboxCreateResponse, error) {
	body := map[string]any{"count": 1}
	if idleTimeoutSeconds != nil {
		body["idle_timeout_secs"] = *idleTimeoutSeconds
	}
	if len(environment) > 0 {
		body["env"] = environment
	}
	var response sandboxCreateResponse
	if err := c.sandboxServerJSON(ctx, endpoint, http.MethodPost, "/v1/sandboxes", nil, body, &response, 64*1024); err != nil {
		return sandboxCreateResponse{}, err
	}
	return response, nil
}

func validSandboxCreateResponse(response sandboxCreateResponse) bool {
	return response.Rejected == 0 &&
		len(response.Sandboxes) == 1 &&
		sandboxIDPattern.MatchString(response.Sandboxes[0].ID)
}

func (c *Client) resolveSandboxEndpoint(ctx context.Context, ref SandboxRef) (sandboxEndpoint, string, error) {
	if err := ref.Validate(); err != nil {
		return sandboxEndpoint{}, "", err
	}
	job, err := c.inspectSandboxJob(ctx, ref.Namespace, ref.JobID)
	if err != nil {
		return sandboxEndpoint{}, "", err
	}
	state, err := sandboxStateFromJob(job, ref.Namespace, ref.LocalID)
	if err != nil || state.Stage != "RUNNING" {
		return sandboxEndpoint{}, "", errors.New("hubclient: sandbox is not running")
	}
	endpoint, err := c.sandboxEndpoint(job, ref)
	if err != nil {
		return sandboxEndpoint{}, "", err
	}
	basePath := "/v1"
	if ref.LocalID != "" {
		basePath += "/sandboxes/" + url.PathEscape(ref.LocalID)
	}
	return endpoint, basePath, nil
}

func (c *Client) sandboxEndpoint(job sandboxJobWire, ref SandboxRef) (sandboxEndpoint, error) {
	if len(job.Status.ExposeURLs) == 0 {
		return sandboxEndpoint{}, errors.New("hubclient: sandbox server endpoint is unavailable")
	}
	for _, candidate := range job.Status.ExposeURLs {
		parsed, ok := parseSandboxEndpointCandidate(candidate)
		if !ok {
			continue
		}
		if !sandboxEndpointHostMatches(parsed.Hostname(), ref.JobID) {
			continue
		}
		nonce := job.Labels[sandboxNonceLabel]
		if !isHex(nonce, 32) {
			return sandboxEndpoint{}, &Error{Code: CodeResponseInvalid, StatusCode: http.StatusOK}
		}
		return sandboxEndpoint{base: "https://" + parsed.Host, token: c.deriveSandboxToken(nonce)}, nil
	}
	return sandboxEndpoint{}, &Error{Code: CodeResponseInvalid, StatusCode: http.StatusOK}
}

func parseSandboxEndpointCandidate(candidate string) (*url.URL, bool) {
	parsed, err := url.Parse(candidate)
	if err != nil || !validSandboxEndpointURL(parsed) {
		return nil, false
	}
	return parsed, true
}

func validSandboxEndpointURL(parsed *url.URL) bool {
	return parsed.Scheme == "https" &&
		parsed.User == nil &&
		parsed.Port() == "" &&
		parsed.RawQuery == "" &&
		parsed.Fragment == "" &&
		(parsed.Path == "" || parsed.Path == "/")
}

func sandboxEndpointHostMatches(hostname, jobID string) bool {
	host := strings.ToLower(hostname)
	prefix := strings.ToLower(jobID) + "--" + strconv.Itoa(SandboxServerPort) + "."
	return strings.HasPrefix(host, prefix) && strings.HasSuffix(host, ".hf.jobs")
}

func (c *Client) sandboxServerJSON(ctx context.Context, endpoint sandboxEndpoint, method, path string, query url.Values, body, out any, limit int64) error {
	raw, err := c.sandboxServer(ctx, endpoint, sandboxRequest{method: method, path: path, query: query, body: body, limit: limit})
	if err != nil || out == nil {
		return err
	}
	if err := json.Unmarshal(raw, out); err != nil {
		if method == http.MethodGet {
			return &Error{Code: CodeResponseInvalid, StatusCode: http.StatusOK}
		}
		return &Error{Code: CodeResultUnknown, StatusCode: http.StatusOK, Ambiguous: true}
	}
	return nil
}

func (c *Client) sandboxServer(ctx context.Context, endpoint sandboxEndpoint, spec sandboxRequest) ([]byte, error) {
	ctx, cancel := sandboxRequestContext(ctx, c.timeout, spec.timeout)
	defer cancel()
	request, err := sandboxHTTPRequest(ctx, endpoint, spec)
	if err != nil {
		return nil, err
	}
	response, err := c.doSandboxRequest(request, spec.method)
	if err != nil {
		return nil, err
	}
	defer func() { _ = response.Body.Close() }()
	payload, err := c.readSandboxPayload(response, spec)
	if err != nil {
		return nil, err
	}
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		return nil, statusError(response.StatusCode, response.Header)
	}
	return payload, nil
}

func (c *Client) doSandboxRequest(request *http.Request, method string) (*http.Response, error) {
	response, err := c.httpClient.Do(request)
	if err != nil {
		if method == http.MethodGet {
			return nil, &Error{Code: CodeUnavailable}
		}
		return nil, &Error{Code: CodeResultUnknown, Ambiguous: true}
	}
	return response, nil
}

func (c *Client) readSandboxPayload(response *http.Response, spec sandboxRequest) ([]byte, error) {
	payload, err := readSandboxResponseBody(response, sandboxResponseLimit(spec.limit, c.maxResponseBytes))
	if err == nil {
		return payload, nil
	}
	if spec.method == http.MethodGet {
		return nil, &Error{Code: CodeResponseInvalid, StatusCode: response.StatusCode}
	}
	return nil, &Error{Code: CodeResultUnknown, StatusCode: response.StatusCode, Ambiguous: true}
}

func sandboxHTTPRequest(ctx context.Context, endpoint sandboxEndpoint, spec sandboxRequest) (*http.Request, error) {
	reader, contentType, err := sandboxRequestBody(spec)
	if err != nil {
		return nil, err
	}
	request, err := http.NewRequestWithContext(ctx, spec.method, sandboxRequestURL(endpoint.base, spec), reader)
	if err != nil {
		return nil, errors.New("hubclient: sandbox request construction failed")
	}
	setSandboxRequestHeaders(request, endpoint.token, contentType)
	return request, nil
}

func sandboxRequestURL(base string, spec sandboxRequest) string {
	requestURL := base + spec.path
	if len(spec.query) > 0 {
		requestURL += "?" + spec.query.Encode()
	}
	return requestURL
}

func sandboxRequestContext(ctx context.Context, defaultTimeout, requestTimeout time.Duration) (context.Context, context.CancelFunc) {
	if ctx == nil {
		ctx = context.Background()
	}
	timeout := requestTimeout
	if timeout <= 0 {
		timeout = defaultTimeout
	}
	if _, hasDeadline := ctx.Deadline(); hasDeadline {
		return ctx, func() {}
	}
	return context.WithTimeout(ctx, timeout)
}

func setSandboxRequestHeaders(request *http.Request, token, contentType string) {
	request.Header.Set("X-Sandbox-Token", token)
	request.Header.Set("Accept", "application/json")
	if contentType != "" {
		request.Header.Set("Content-Type", contentType)
	}
}

func sandboxResponseLimit(limit, maximum int64) int64 {
	if limit <= 0 || limit > maximum {
		return maximum
	}
	return limit
}

func readSandboxResponseBody(response *http.Response, limit int64) ([]byte, error) {
	payload, err := io.ReadAll(io.LimitReader(response.Body, limit+1))
	if err != nil || int64(len(payload)) > limit {
		return nil, errors.New("hubclient: sandbox response body is invalid")
	}
	return payload, nil
}

func sandboxRequestBody(spec sandboxRequest) (io.Reader, string, error) {
	if spec.body != nil && len(spec.rawBody) > 0 {
		return nil, "", errors.New("hubclient: sandbox request has conflicting bodies")
	}
	if spec.body != nil {
		encoded, err := json.Marshal(spec.body)
		if err != nil || len(encoded) > maxRequestBodyBytes {
			return nil, "", errors.New("hubclient: sandbox request body is invalid")
		}
		return bytes.NewReader(encoded), "application/json", nil
	}
	if len(spec.rawBody) > maxRequestBodyBytes {
		return nil, "", errors.New("hubclient: sandbox request body is invalid")
	}
	if len(spec.rawBody) > 0 {
		return bytes.NewReader(spec.rawBody), spec.contentType, nil
	}
	return nil, spec.contentType, nil
}

func validSandboxProcessCommandValue(value any) bool {
	switch value := value.(type) {
	case string:
		return value != "" && len(value) <= 64*1024
	case []any:
		return validSandboxProcessCommandList(value)
	default:
		return false
	}
}

func validSandboxProcessCommandList(values []any) bool {
	if len(values) == 0 || len(values) > 256 {
		return false
	}
	for _, item := range values {
		text, ok := item.(string)
		if !ok || text == "" || len(text) > 64*1024 {
			return false
		}
	}
	return true
}

// ValidSandboxFileMode reports whether mode is empty or a three/four-digit
// octal file mode accepted by the pinned sandbox API.
func ValidSandboxFileMode(mode string) bool {
	if mode == "" {
		return true
	}
	if len(mode) != 3 && len(mode) != 4 {
		return false
	}
	for _, char := range mode {
		if char < '0' || char > '7' {
			return false
		}
	}
	return true
}

func (c *Client) deriveSandboxToken(nonce string) string {
	mac := hmac.New(sha256.New, []byte(c.token))
	_, _ = fmt.Fprintf(mac, "hf-sandbox:%s", nonce)
	return hex.EncodeToString(mac.Sum(nil))
}

func randomHex(size int) (string, error) {
	value := make([]byte, size)
	if _, err := io.ReadFull(rand.Reader, value); err != nil {
		return "", err
	}
	return hex.EncodeToString(value), nil
}

func isHex(value string, size int) bool {
	if len(value) != size {
		return false
	}
	_, err := hex.DecodeString(value)
	return err == nil
}
