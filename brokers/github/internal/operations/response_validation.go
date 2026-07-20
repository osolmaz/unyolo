package operations

import (
	"errors"
	"net/http"
	"slices"

	"github.com/osolmaz/brokerkit/brokers/github/internal/githubauth"
	"github.com/osolmaz/brokerkit/brokers/github/internal/opbinding"
	"github.com/osolmaz/brokerkit/brokers/github/internal/schemaregistry"
	"github.com/osolmaz/brokerkit/internal/strictjson"
	"github.com/osolmaz/brokerkit/operation/runtime"
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
	return Outcome{Proven: true, Result: result.Body, UpstreamStatus: result.StatusCode}, nil
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
