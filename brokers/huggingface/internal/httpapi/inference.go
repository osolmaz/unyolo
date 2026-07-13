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

	"github.com/osolmaz/brokerkit/audit"
	"github.com/osolmaz/brokerkit/brokers/huggingface/internal/hfgrant"
	"github.com/osolmaz/brokerkit/brokers/huggingface/internal/policy"
	"github.com/osolmaz/brokerkit/grants"
	"github.com/osolmaz/brokerkit/httpx"
	"github.com/osolmaz/brokerkit/internal/strictjson"
)

const (
	maxInferenceRequestBytes  = 100 * 1024 * 1024
	maxInferenceResponseBytes = 64 * 1024 * 1024
)

var inferenceModelPartPattern = regexp.MustCompile(`^[A-Za-z0-9]([A-Za-z0-9._-]{0,126}[A-Za-z0-9])?$`)

var inferenceTopLevelFields = map[string]bool{
	"model": true, "messages": true, "audio": true, "frequency_penalty": true, "function_call": true,
	"functions": true, "logit_bias": true, "logprobs": true, "max_completion_tokens": true, "max_tokens": true,
	"metadata": true, "modalities": true, "n": true, "parallel_tool_calls": true, "prediction": true,
	"presence_penalty": true, "reasoning_effort": true, "response_format": true, "seed": true, "service_tier": true,
	"stop": true, "store": true, "stream": true, "stream_options": true, "temperature": true, "tool_choice": true,
	"tools": true, "top_logprobs": true, "top_p": true, "user": true, "verbosity": true, "web_search_options": true,
}

var inferenceMessageFields = map[string]bool{
	"role": true, "content": true, "name": true, "tool_call_id": true, "tool_calls": true, "function_call": true,
	"audio": true, "refusal": true,
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
		const operation = policy.OpInferenceModels
		target := policy.Target{Kind: policy.KindInference, Owner: "router", Name: "models"}
		reserved, allowed := s.authorizeInference(w, client, operation, target, 0)
		if !allowed {
			return
		}
		s.forwardInference(w, r, client, string(operation), "models", nil, reserved)
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
	target, ok := inferencePolicyTarget(model)
	if !ok {
		s.refuseInference(w, client, operation, model, http.StatusBadRequest, "invalid_model")
		return
	}
	reserved, allowed := s.authorizeInference(w, client, policy.OpInferenceChat, target, len(body))
	if !allowed {
		return
	}
	s.forwardInference(w, r, client, operation, model, body, reserved)
}

func inferencePolicyTarget(model string) (policy.Target, bool) {
	base, provider, _ := strings.Cut(model, ":")
	parts := strings.Split(base, "/")
	if len(parts) != 2 {
		return policy.Target{}, false
	}
	name := parts[1]
	if provider != "" {
		name += ":" + provider
	}
	return policy.Target{Kind: policy.KindInference, Owner: parts[0], Name: name}, true
}

func (s *Server) authorizeInference(w http.ResponseWriter, client string, operation policy.Operation, target policy.Target, bodyBytes int) (*grants.Grant, bool) {
	attrs := map[string]any{}
	if bodyBytes > 0 {
		attrs["max_bytes"] = int64(bodyBytes)
	}
	activeGrants, err := s.activeGrantRules(client)
	targetName := targetNameFromPolicy(target)
	if err != nil {
		writeInferenceError(w, http.StatusInternalServerError, "grant_store_unavailable")
		s.record(client, string(operation), targetName, audit.DecisionRefused, "could not inspect grants", 0)
		return nil, false
	}
	decision := s.policy.Decide(policy.Request{Client: client, Operation: operation, Target: target, Attrs: attrs}, activeGrants, s.utcNow(), false)
	if decision.Effect != policy.EffectAllow {
		writeInferenceError(w, http.StatusForbidden, "policy_denied")
		s.recordPolicyDecision(client, string(operation), targetName, audit.DecisionRefused, decision.Reason, 0, decision)
		return nil, false
	}
	var reserved *grants.Grant
	if decision.GrantID != "" {
		grant, reserveErr := s.reserveInferenceGrant(decision.GrantID, client, operation, targetName, attrs)
		if reserveErr != nil {
			writeInferenceError(w, http.StatusConflict, "grant_unavailable")
			s.recordPolicyDecision(client, string(operation), targetName, audit.DecisionRefused, "grant_unavailable", 0, decision)
			return nil, false
		}
		reserved = &grant
	}
	s.recordPolicyDecision(client, string(operation), targetName, audit.DecisionAllowed, "", 0, decision)
	return reserved, true
}

func (s *Server) reserveInferenceGrant(id, client string, operation policy.Operation, target string, attrs map[string]any) (grants.Grant, error) {
	grant, err := s.grants.Get(id)
	if err != nil || !s.inferenceGrantMatches(grant, client, operation, target) {
		return grants.Grant{}, errors.New("inference grant is not usable")
	}
	values, err := hfgrant.Attrs(grant)
	if err != nil || !policy.AttrValuesMatch(values, attrs) {
		return grants.Grant{}, errors.New("inference grant does not match the request")
	}
	return s.grants.ReserveUse(grant.ID)
}

func (s *Server) inferenceGrantMatches(grant grants.Grant, client string, operation policy.Operation, target string) bool {
	return grant.Client == client && grant.Operation == string(operation) && hfgrant.Target(grant) == target && hfgrant.Ref(grant) == "" &&
		grantEligibleForRule(grant) && s.planValidator.ValidateExecution(grant) == nil
}

func jsonContentType(value string) bool {
	mediaType, _, err := mime.ParseMediaType(value)
	return err == nil && mediaType == "application/json"
}

func readInferenceRequest(w http.ResponseWriter, r *http.Request) ([]byte, int, string) {
	return readInferenceRequestWithLimit(w, r, maxInferenceRequestBytes)
}

func readInferenceRequestWithLimit(w http.ResponseWriter, r *http.Request, limit int64) ([]byte, int, string) {
	body, err := httpx.ReadLimited(r.Body, limit)
	if err == nil {
		return body, 0, ""
	}
	if errors.Is(err, httpx.ErrBodyTooLarge) {
		return nil, http.StatusRequestEntityTooLarge, "request_body_too_large"
	}
	return nil, http.StatusBadRequest, "invalid_request_body"
}

func inferenceRequestModel(body []byte) (string, bool) {
	request, ok := decodeInferenceObject(body)
	if !ok {
		return "", false
	}
	if !knownInferenceFields(request, inferenceTopLevelFields) {
		return "", false
	}
	var model string
	if json.Unmarshal(request["model"], &model) != nil || !validInferenceModel(model) || !validInferenceMessages(request["messages"]) {
		return "", false
	}
	if !validOptionalStream(request["stream"]) {
		return "", false
	}
	return model, true
}

func decodeInferenceObject(body []byte) (map[string]json.RawMessage, bool) {
	var request map[string]json.RawMessage
	if strictjson.Decode(body, &request, false) != nil || len(request) == 0 {
		return nil, false
	}
	return request, true
}

func knownInferenceFields(request map[string]json.RawMessage, allowed map[string]bool) bool {
	for field := range request {
		if !allowed[field] {
			return false
		}
	}
	return true
}

func validOptionalStream(raw json.RawMessage) bool {
	if raw == nil {
		return true
	}
	var stream bool
	return json.Unmarshal(raw, &stream) == nil
}

func validInferenceMessages(raw json.RawMessage) bool {
	var messages []json.RawMessage
	if len(raw) == 0 || json.Unmarshal(raw, &messages) != nil || len(messages) == 0 {
		return false
	}
	for _, rawMessage := range messages {
		if !validInferenceMessage(rawMessage) {
			return false
		}
	}
	return true
}

func validInferenceMessage(raw json.RawMessage) bool {
	var message map[string]json.RawMessage
	if strictjson.Decode(raw, &message, false) != nil || !knownInferenceFields(message, inferenceMessageFields) {
		return false
	}
	var role string
	if json.Unmarshal(message["role"], &role) != nil || !validInferenceRole(role) {
		return false
	}
	return inferenceMessageHasContent(message)
}

func inferenceMessageHasContent(message map[string]json.RawMessage) bool {
	content, hasContent := message["content"]
	_, hasToolCalls := message["tool_calls"]
	_, hasFunctionCall := message["function_call"]
	return hasContent && len(content) > 0 && string(content) != "null" || hasToolCalls || hasFunctionCall
}

func validInferenceRole(role string) bool {
	return role == "developer" || role == "system" || role == "user" || role == "assistant" || role == "tool"
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

func (s *Server) forwardInference(w http.ResponseWriter, downstream *http.Request, client, operation, target string, body []byte, reserved *grants.Grant) {
	upstreamURL := *s.routerUpstream
	upstreamURL.Path = downstream.URL.Path
	var requestBody io.Reader
	if body != nil {
		requestBody = bytes.NewReader(body)
	}
	request, err := http.NewRequestWithContext(downstream.Context(), downstream.Method, upstreamURL.String(), requestBody)
	if err != nil {
		s.settleInferenceGrant(reserved, false)
		s.refuseInference(w, client, operation, target, http.StatusBadGateway, "upstream_unavailable")
		return
	}
	request.Header.Set("Authorization", "Bearer "+s.hfToken)
	request.Header.Set("Accept", inferenceAccept(downstream.Header.Get("Accept")))
	if body != nil {
		request.Header.Set("Content-Type", "application/json")
	}
	response, err := s.inferenceHTTPClient.Do(request) // #nosec G704 -- destination is derived from the startup-validated operator base URL.
	s.settleInferenceGrant(reserved, true)
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

func (s *Server) settleInferenceGrant(reserved *grants.Grant, attempted bool) {
	if reserved == nil {
		return
	}
	if !attempted {
		s.releaseGrantUses([]grants.Grant{*reserved})
		return
	}
	s.updateGrantMessages(s.commitGrantUses([]grants.Grant{*reserved}), s.updateGrantUseMessage)
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
	return httpx.ReadLimited(body, maximum)
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
