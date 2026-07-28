package operations

import (
	"bytes"
	"encoding/json"
	"errors"
	"net/http"
	"slices"

	"github.com/osolmaz/unyolo/brokers/github/internal/githubauth"
	"github.com/osolmaz/unyolo/brokers/github/internal/opbinding"
	"github.com/osolmaz/unyolo/brokers/github/internal/schemaregistry"
	"github.com/osolmaz/unyolo/internal/strictjson"
	"github.com/osolmaz/unyolo/operation/runtime"
)

var IsPossiblePartial = operationruntime.IsPossiblePartial

type credentialResponse struct {
	Token     string `json:"token"`
	ExpiresAt string `json:"expires_at"`
}

func validatedExecutionResult(binding opbinding.Binding, operation string, result githubauth.ExecutionResult) (Outcome, error) {
	if err := executionStatusError(binding, result.StatusCode); err != nil {
		return Outcome{}, err
	}
	if err := schemaregistry.ValidateResult(operation, result.Body); err != nil {
		return Outcome{}, classifyResponseValidationError(binding.Method, err)
	}
	return Outcome{Proven: true, Result: agentOperationResult(result.Body), UpstreamStatus: result.StatusCode}, nil
}

func agentOperationResult(result json.RawMessage) json.RawMessage {
	trimmed := bytes.TrimSpace(result)
	if len(trimmed) > 0 && trimmed[0] == '{' {
		return result
	}
	key := "value"
	if len(trimmed) > 0 && trimmed[0] == '[' {
		key = "items"
	}
	wrapped, _ := json.Marshal(map[string]json.RawMessage{key: result})
	return wrapped
}

func decodeCredentialResponse(binding opbinding.Binding, result githubauth.ExecutionResult) (credentialResponse, error) {
	if err := executionStatusError(binding, result.StatusCode); err != nil {
		return credentialResponse{}, err
	}
	var response credentialResponse
	if strictjson.Decode(result.Body, &response, true) != nil || response.Token == "" || response.ExpiresAt == "" {
		return credentialResponse{}, &PossiblePartialError{Err: errors.New("upstream_result_unknown")}
	}
	return response, nil
}

func executionStatusError(binding opbinding.Binding, status int) error {
	if slices.Contains(binding.SuccessStatusCodes, status) {
		return nil
	}
	unexpected := githubauth.APIError{Code: "unexpected_success_status", StatusCode: status}
	if binding.Method == http.MethodGet || binding.Method == http.MethodHead {
		return unexpected
	}
	return &PossiblePartialError{Err: unexpected}
}

func classifyResponseValidationError(method string, err error) error {
	if err != nil && method != http.MethodGet && method != http.MethodHead {
		return &PossiblePartialError{Err: err}
	}
	return err
}
