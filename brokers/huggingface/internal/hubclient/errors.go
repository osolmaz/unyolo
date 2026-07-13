package hubclient

import (
	"errors"
	"fmt"
)

// Stable upstream error classes. Adapters translate these into broker
// operation outcome codes; the raw upstream response never crosses this
// boundary.
type ErrorCode string

const (
	CodeInvalid         ErrorCode = "operation_upstream_rejected"
	CodeUnauthorized    ErrorCode = "operation_upstream_authentication_failed"
	CodeForbidden       ErrorCode = "operation_upstream_authorization_failed"
	CodeNotFound        ErrorCode = "operation_target_not_found"
	CodeConflict        ErrorCode = "operation_upstream_conflict"
	CodeRateLimited     ErrorCode = "operation_upstream_rate_limited"
	CodeUnavailable     ErrorCode = "operation_upstream_unavailable"
	CodeResponseInvalid ErrorCode = "operation_upstream_response_invalid"
	CodeResultUnknown   ErrorCode = "upstream_result_unknown"
)

// Error is the only error type returned for upstream call failures. It
// carries classification and retry metadata but never credentials, request
// bodies, or upstream response bodies.
type Error struct {
	Code              ErrorCode
	StatusCode        int
	RetryAfterSeconds int
	Ambiguous         bool
}

func (e *Error) Error() string {
	if e.StatusCode > 0 {
		return fmt.Sprintf("hugging face upstream error %s (HTTP %d)", e.Code, e.StatusCode)
	}
	return "hugging face upstream error " + string(e.Code)
}

// Definitive reports whether the upstream definitively rejected or completed
// the request. Non-definitive failures must never trigger an automatic retry
// of a mutation; the caller reconciles observed state instead.
func (e *Error) Definitive() bool {
	if e.Ambiguous {
		return false
	}
	switch e.Code {
	case CodeInvalid, CodeUnauthorized, CodeForbidden, CodeNotFound, CodeConflict, CodeRateLimited, CodeResponseInvalid:
		return true
	default:
		return false
	}
}

// IsNotFound reports whether err is a definitive upstream 404.
func IsNotFound(err error) bool {
	var classified *Error
	return errors.As(err, &classified) && classified.Code == CodeNotFound
}
