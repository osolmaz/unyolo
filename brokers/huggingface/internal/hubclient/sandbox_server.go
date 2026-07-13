package hubclient

import (
	"bufio"
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

func (c *Client) RunSandboxCommand(ctx context.Context, ref SandboxRef, command SandboxCommand) (SandboxCommandResult, error) {
	if err := validateSandboxCommand(command); err != nil {
		return SandboxCommandResult{}, err
	}
	endpoint, basePath, err := c.resolveSandboxEndpoint(ctx, ref)
	if err != nil {
		return SandboxCommandResult{}, err
	}
	payload := make(map[string]any)
	if command.ShellCommand != "" {
		payload["cmd"] = command.ShellCommand
		payload["shell"] = true
	} else {
		payload["cmd"] = command.Argv
		payload["shell"] = false
	}
	if len(command.Environment) > 0 {
		payload["env"] = command.Environment
	}
	if command.WorkingDir != "" {
		payload["cwd"] = command.WorkingDir
	}
	if command.Background {
		var process struct {
			PID int `json:"pid"`
		}
		if err := c.sandboxServerJSON(ctx, endpoint, http.MethodPost, basePath+"/processes", nil, payload, &process, 64*1024); err != nil {
			return SandboxCommandResult{}, err
		}
		if process.PID < 1 {
			return SandboxCommandResult{}, &Error{Code: CodeResponseInvalid, StatusCode: http.StatusOK}
		}
		return SandboxCommandResult{PID: process.PID}, nil
	}
	if command.TimeoutSeconds > 0 {
		payload["timeout"] = command.TimeoutSeconds
	}
	if command.Stdin != "" {
		payload["stdin"] = command.Stdin
	}
	encoded, err := json.Marshal(payload)
	if err != nil {
		return SandboxCommandResult{}, errors.New("hubclient: sandbox command is invalid")
	}
	responseLimit := int64(command.MaxOutputBytes + 64*1024)
	requestTimeout := c.timeout
	if command.TimeoutSeconds > 0 && time.Duration(command.TimeoutSeconds+10)*time.Second > requestTimeout {
		requestTimeout = time.Duration(command.TimeoutSeconds+10) * time.Second
	}
	raw, err := c.sandboxServer(ctx, endpoint, sandboxRequest{method: http.MethodPost, path: basePath + "/exec", rawBody: encoded,
		contentType: "application/json", limit: responseLimit, timeout: requestTimeout})
	if err != nil {
		return SandboxCommandResult{}, err
	}
	return decodeSandboxCommandEvents(raw, command.MaxOutputBytes)
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
	if info.Path != path || info.Size < 0 || (info.Type != "file" && info.Type != "dir" && info.Type != "symlink") {
		return SandboxFileInfo{}, &Error{Code: CodeResponseInvalid, StatusCode: http.StatusOK}
	}
	return info, nil
}

func (c *Client) WriteSandboxFile(ctx context.Context, ref SandboxRef, path, mode string, content []byte) error {
	if !validSandboxPath(path) || !validSandboxMode(mode) || len(content) > maxRequestBodyBytes {
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
		if process.PID < 1 || !validSandboxCommandValue(process.Command) {
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
	if host.LocalID != "" || !validIdleTimeout(idleTimeoutSeconds) || validateSandboxEnvironment(environment, true) != nil {
		return SandboxRef{}, errors.New("hubclient: pooled sandbox configuration is invalid")
	}
	for _, value := range environment {
		if value == c.token {
			return SandboxRef{}, errors.New("hubclient: broker credential cannot be forwarded to a sandbox")
		}
	}
	job, err := c.inspectSandboxJob(ctx, host.Namespace, host.JobID)
	if err != nil {
		return SandboxRef{}, err
	}
	state, err := sandboxStateFromJob(job, host.Namespace, "")
	if err != nil || state.Mode != modePool || state.Stage != "RUNNING" {
		return SandboxRef{}, errors.New("hubclient: sandbox pool host is unavailable")
	}
	endpoint, err := c.sandboxEndpoint(job, host)
	if err != nil {
		return SandboxRef{}, err
	}
	body := map[string]any{"count": 1}
	if idleTimeoutSeconds != nil {
		body["idle_timeout_secs"] = *idleTimeoutSeconds
	}
	if len(environment) > 0 {
		body["env"] = environment
	}
	var response struct {
		Sandboxes []struct {
			ID string `json:"id"`
		} `json:"sandboxes"`
		Rejected int `json:"rejected"`
	}
	if err := c.sandboxServerJSON(ctx, endpoint, http.MethodPost, "/v1/sandboxes", nil, body, &response, 64*1024); err != nil {
		return SandboxRef{}, err
	}
	if response.Rejected != 0 || len(response.Sandboxes) != 1 || !sandboxIDPattern.MatchString(response.Sandboxes[0].ID) {
		return SandboxRef{}, &Error{Code: CodeConflict, StatusCode: http.StatusConflict}
	}
	return SandboxRef{Namespace: host.Namespace, JobID: host.JobID, LocalID: response.Sandboxes[0].ID}, nil
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
		parsed, err := url.Parse(candidate)
		if err != nil || parsed.Scheme != "https" || parsed.User != nil || parsed.Port() != "" || parsed.RawQuery != "" ||
			parsed.Fragment != "" || parsed.Path != "" && parsed.Path != "/" {
			continue
		}
		host := strings.ToLower(parsed.Hostname())
		prefix := strings.ToLower(ref.JobID) + "--" + strconv.Itoa(SandboxServerPort) + "."
		if !strings.HasPrefix(host, prefix) || !strings.HasSuffix(host, ".hf.jobs") {
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
	if ctx == nil {
		ctx = context.Background()
	}
	timeout := spec.timeout
	if timeout <= 0 {
		timeout = c.timeout
	}
	if _, hasDeadline := ctx.Deadline(); !hasDeadline {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, timeout)
		defer cancel()
	}
	if spec.body != nil && len(spec.rawBody) > 0 {
		return nil, errors.New("hubclient: sandbox request has conflicting bodies")
	}
	var reader io.Reader
	contentType := spec.contentType
	if spec.body != nil {
		encoded, err := json.Marshal(spec.body)
		if err != nil || len(encoded) > maxRequestBodyBytes {
			return nil, errors.New("hubclient: sandbox request body is invalid")
		}
		reader = bytes.NewReader(encoded)
		contentType = "application/json"
	} else if len(spec.rawBody) > 0 {
		if len(spec.rawBody) > maxRequestBodyBytes {
			return nil, errors.New("hubclient: sandbox request body is invalid")
		}
		reader = bytes.NewReader(spec.rawBody)
	}
	requestURL := endpoint.base + spec.path
	if len(spec.query) > 0 {
		requestURL += "?" + spec.query.Encode()
	}
	request, err := http.NewRequestWithContext(ctx, spec.method, requestURL, reader)
	if err != nil {
		return nil, errors.New("hubclient: sandbox request construction failed")
	}
	request.Header.Set("Authorization", "Bearer "+c.token)
	request.Header.Set("X-Sandbox-Token", endpoint.token)
	request.Header.Set("Accept", "application/json")
	if contentType != "" {
		request.Header.Set("Content-Type", contentType)
	}
	response, err := c.httpClient.Do(request)
	if err != nil {
		if spec.method == http.MethodGet {
			return nil, &Error{Code: CodeUnavailable}
		}
		return nil, &Error{Code: CodeResultUnknown, Ambiguous: true}
	}
	defer func() { _ = response.Body.Close() }()
	limit := spec.limit
	if limit <= 0 || limit > c.maxResponseBytes {
		limit = c.maxResponseBytes
	}
	payload, readErr := io.ReadAll(io.LimitReader(response.Body, limit+1))
	if readErr != nil || int64(len(payload)) > limit {
		if spec.method == http.MethodGet {
			return nil, &Error{Code: CodeResponseInvalid, StatusCode: response.StatusCode}
		}
		return nil, &Error{Code: CodeResultUnknown, StatusCode: response.StatusCode, Ambiguous: true}
	}
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		return nil, statusError(response.StatusCode, response.Header)
	}
	return payload, nil
}

func decodeSandboxCommandEvents(raw []byte, maxOutput int) (SandboxCommandResult, error) {
	result := SandboxCommandResult{}
	foundExit := false
	scanner := bufio.NewScanner(bytes.NewReader(raw))
	scanner.Buffer(make([]byte, 64*1024), maxOutput+64*1024)
	for scanner.Scan() {
		if len(bytes.TrimSpace(scanner.Bytes())) == 0 {
			continue
		}
		var event struct {
			Event      string `json:"event"`
			Data       string `json:"data"`
			ExitCode   *int   `json:"exit_code"`
			Signal     *int   `json:"signal"`
			TimedOut   bool   `json:"timed_out"`
			DurationMS int64  `json:"duration_ms"`
		}
		if err := json.Unmarshal(scanner.Bytes(), &event); err != nil {
			return SandboxCommandResult{}, ambiguousSandboxCommandResult()
		}
		switch event.Event {
		case "ping":
		case "stdout":
			result.Stdout += event.Data
		case "stderr":
			result.Stderr += event.Data
		case "exit":
			if foundExit || event.ExitCode == nil {
				return SandboxCommandResult{}, ambiguousSandboxCommandResult()
			}
			foundExit = true
			result.ExitCode, result.Signal, result.TimedOut, result.DurationMS = event.ExitCode, event.Signal, event.TimedOut, event.DurationMS
		default:
			return SandboxCommandResult{}, ambiguousSandboxCommandResult()
		}
		if len(result.Stdout)+len(result.Stderr) > maxOutput {
			return SandboxCommandResult{}, ambiguousSandboxCommandResult()
		}
	}
	if scanner.Err() != nil || !foundExit {
		return SandboxCommandResult{}, ambiguousSandboxCommandResult()
	}
	return result, nil
}

func ambiguousSandboxCommandResult() error {
	return &Error{Code: CodeResultUnknown, StatusCode: http.StatusOK, Ambiguous: true}
}

func validateSandboxCommand(command SandboxCommand) error {
	if (len(command.Argv) == 0) == (command.ShellCommand == "") || len(command.Argv) > 256 || len(command.ShellCommand) > 64*1024 ||
		len(command.Stdin) > 256*1024 || command.TimeoutSeconds < 0 || command.TimeoutSeconds > 60*60 ||
		command.Background && (command.TimeoutSeconds != 0 || command.Stdin != "") ||
		command.MaxOutputBytes < 1 || command.MaxOutputBytes > SandboxMaxCommandOutput ||
		command.WorkingDir != "" && !validSandboxPath(command.WorkingDir) || validateSandboxEnvironment(command.Environment, true) != nil {
		return errors.New("hubclient: sandbox command is invalid")
	}
	for _, argument := range command.Argv {
		if argument == "" || len(argument) > 64*1024 || strings.ContainsRune(argument, 0) {
			return errors.New("hubclient: sandbox command is invalid")
		}
	}
	return nil
}

func validSandboxCommandValue(value any) bool {
	switch value := value.(type) {
	case string:
		return value != "" && len(value) <= 64*1024
	case []any:
		if len(value) == 0 || len(value) > 256 {
			return false
		}
		for _, item := range value {
			text, ok := item.(string)
			if !ok || text == "" || len(text) > 64*1024 {
				return false
			}
		}
		return true
	default:
		return false
	}
}

func validSandboxMode(mode string) bool {
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
