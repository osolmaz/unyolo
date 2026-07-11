package httpapi

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"mime"
	"net/http"
	"regexp"
	"strings"

	"github.com/osolmaz/hf-broker/internal/audit"
)

const (
	maxInferenceRequestBytes  = 4 * 1024 * 1024
	maxInferenceResponseBytes = 64 * 1024 * 1024
)

var inferenceModelPartPattern = regexp.MustCompile(`^[A-Za-z0-9]([A-Za-z0-9._-]{0,126}[A-Za-z0-9])?$`)

type inferenceRequest struct {
	Model string `json:"model"`
}

func isInferencePath(path string) bool {
	return path == "/v1/models" || path == "/v1/chat/completions"
}

func (s *Server) serveInference(w http.ResponseWriter, r *http.Request, client string) {
	switch r.URL.Path {
	case "/v1/models":
		if r.Method != http.MethodGet {
			s.refuseInference(w, client, "inference.models.list", "models", http.StatusMethodNotAllowed, "method_not_allowed")
			return
		}
		if r.URL.RawQuery != "" {
			s.refuseInference(w, client, "inference.models.list", "models", http.StatusBadRequest, "query_not_allowed")
			return
		}
		s.forwardInference(w, r, client, "inference.models.list", "models", nil)
	case "/v1/chat/completions":
		s.serveChatCompletion(w, r, client)
	}
}

func (s *Server) serveChatCompletion(w http.ResponseWriter, r *http.Request, client string) {
	const operation = "inference.chat.complete"
	if r.Method != http.MethodPost {
		s.refuseInference(w, client, operation, "", http.StatusMethodNotAllowed, "method_not_allowed")
		return
	}
	if r.URL.RawQuery != "" {
		s.refuseInference(w, client, operation, "", http.StatusBadRequest, "query_not_allowed")
		return
	}
	if !jsonContentType(r.Header.Get("Content-Type")) {
		s.refuseInference(w, client, operation, "", http.StatusUnsupportedMediaType, "json_content_type_required")
		return
	}
	body, status, reason := readInferenceRequest(w, r)
	if status != 0 {
		s.refuseInference(w, client, operation, "", status, reason)
		return
	}
	model, ok := inferenceRequestModel(body)
	if !ok {
		s.refuseInference(w, client, operation, "", http.StatusBadRequest, "invalid_model")
		return
	}
	s.forwardInference(w, r, client, operation, model, body)
}

func jsonContentType(value string) bool {
	mediaType, _, err := mime.ParseMediaType(value)
	return err == nil && mediaType == "application/json"
}

func readInferenceRequest(w http.ResponseWriter, r *http.Request) ([]byte, int, string) {
	body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, maxInferenceRequestBytes))
	if err == nil {
		return body, 0, ""
	}
	var maxBytesError *http.MaxBytesError
	if errors.As(err, &maxBytesError) {
		return nil, http.StatusRequestEntityTooLarge, "request_body_too_large"
	}
	return nil, http.StatusBadRequest, "invalid_request_body"
}

func inferenceRequestModel(body []byte) (string, bool) {
	var request inferenceRequest
	if len(body) == 0 || json.Unmarshal(body, &request) != nil || !validInferenceModel(request.Model) {
		return "", false
	}
	return request.Model, true
}

func validInferenceModel(model string) bool {
	base, provider, hasProvider := strings.Cut(model, ":")
	if hasProvider && !validInferenceModelPart(provider) {
		return false
	}
	parts := strings.Split(base, "/")
	if len(parts) != 2 {
		return false
	}
	return validInferenceModelPart(parts[0]) && validInferenceModelPart(parts[1])
}

func validInferenceModelPart(part string) bool {
	return inferenceModelPartPattern.MatchString(part) && !strings.Contains(part, "..") && !strings.Contains(part, "--")
}

func (s *Server) refuseInference(w http.ResponseWriter, client, operation, target string, status int, reason string) {
	if status == http.StatusMethodNotAllowed {
		w.Header().Set("Allow", inferenceAllowedMethod(operation))
	}
	writeInferenceError(w, status, reason)
	s.record(client, operation, target, audit.DecisionRefused, reason, 0)
}

func inferenceAllowedMethod(operation string) string {
	if operation == "inference.models.list" {
		return http.MethodGet
	}
	return http.MethodPost
}

func writeInferenceError(w http.ResponseWriter, status int, code string) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(map[string]any{
		"error": map[string]string{"type": "invalid_request_error", "code": code, "message": "Request rejected by hf-broker"},
	})
}

func (s *Server) forwardInference(w http.ResponseWriter, downstream *http.Request, client, operation, target string, body []byte) {
	upstreamURL := *s.routerUpstream
	upstreamURL.Path = downstream.URL.Path
	var requestBody io.Reader
	if body != nil {
		requestBody = bytes.NewReader(body)
	}
	request, err := http.NewRequestWithContext(downstream.Context(), downstream.Method, upstreamURL.String(), requestBody)
	if err != nil {
		s.refuseInference(w, client, operation, target, http.StatusBadGateway, "upstream_unavailable")
		return
	}
	request.Header.Set("Authorization", "Bearer "+s.hfToken)
	request.Header.Set("Accept", inferenceAccept(downstream.Header.Get("Accept")))
	if body != nil {
		request.Header.Set("Content-Type", "application/json")
	}
	response, err := s.inferenceHTTPClient.Do(request)
	if err != nil {
		s.refuseInference(w, client, operation, target, http.StatusBadGateway, "upstream_unavailable")
		return
	}
	defer func() { _ = response.Body.Close() }()
	if !inferenceResponseStreams(response) {
		s.forwardBufferedInference(w, client, operation, target, response)
		return
	}
	copyInferenceHeaders(w.Header(), response.Header)
	w.WriteHeader(response.StatusCode)
	copyErr := copyInferenceBody(w, response)
	s.recordInferenceResult(client, operation, target, response.StatusCode, copyErr)
}

func (s *Server) forwardBufferedInference(w http.ResponseWriter, client, operation, target string, response *http.Response) {
	body, err := readBoundedInferenceBody(response.Body, maxInferenceResponseBytes)
	if err != nil {
		writeInferenceError(w, http.StatusBadGateway, "upstream_response_failed")
		s.record(client, operation, target, audit.DecisionRefused, "upstream_response_failed", response.StatusCode)
		return
	}
	copyInferenceHeaders(w.Header(), response.Header)
	w.WriteHeader(response.StatusCode)
	_, writeErr := w.Write(body)
	s.recordInferenceResult(client, operation, target, response.StatusCode, writeErr)
}

func (s *Server) recordInferenceResult(client, operation, target string, status int, result error) {
	reason := ""
	decision := audit.DecisionAllowed
	if result != nil {
		reason = "upstream_response_failed"
		decision = audit.DecisionRefused
	}
	s.record(client, operation, target, decision, reason, status)
}

func inferenceAccept(value string) string {
	if strings.Contains(strings.ToLower(value), "text/event-stream") {
		return "text/event-stream"
	}
	return "application/json"
}

func copyInferenceHeaders(destination, source http.Header) {
	contentType := source.Get("Content-Type")
	if contentType == "" {
		contentType = "application/json"
	}
	destination.Set("Content-Type", contentType)
	destination.Set("Cache-Control", "no-store")
	destination.Set("X-Content-Type-Options", "nosniff")
}

func inferenceResponseStreams(response *http.Response) bool {
	return strings.HasPrefix(strings.ToLower(response.Header.Get("Content-Type")), "text/event-stream")
}

func readBoundedInferenceBody(body io.Reader, maximum int64) ([]byte, error) {
	value, err := io.ReadAll(io.LimitReader(body, maximum+1))
	if err != nil {
		return nil, err
	}
	if int64(len(value)) > maximum {
		return nil, fmt.Errorf("upstream response exceeds %d bytes", maximum)
	}
	return value, nil
}

func copyInferenceBody(w http.ResponseWriter, response *http.Response) error {
	buffer := make([]byte, 32*1024)
	remaining := int64(maxInferenceResponseBytes)
	for {
		read, readErr := response.Body.Read(buffer)
		if err := writeInferenceChunk(w, buffer[:read], &remaining, true); err != nil {
			return err
		}
		if readErr != nil {
			return inferenceReadError(readErr)
		}
	}
}

func writeInferenceChunk(w http.ResponseWriter, chunk []byte, remaining *int64, streaming bool) error {
	if int64(len(chunk)) > *remaining {
		return fmt.Errorf("upstream response exceeds %d bytes", maxInferenceResponseBytes)
	}
	written, err := w.Write(chunk)
	if err != nil {
		return err
	}
	if written != len(chunk) {
		return io.ErrShortWrite
	}
	*remaining -= int64(written)
	if streaming {
		if flusher, ok := w.(http.Flusher); ok {
			flusher.Flush()
		}
	}
	return nil
}

func inferenceReadError(err error) error {
	if errors.Is(err, io.EOF) {
		return nil
	}
	return err
}
