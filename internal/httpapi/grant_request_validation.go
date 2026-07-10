package httpapi

import (
	"net/http"
	"strings"

	"github.com/osolmaz/hf-broker/internal/policy"
)

func validateAPIGrantRequestShape(req apiGrantRequestBody) (int, string, string) {
	if strings.TrimSpace(req.ClientRequestID) == "" {
		return http.StatusBadRequest, "validation_failed", "client_request_id is required"
	}
	if req.Minutes < 0 {
		return http.StatusBadRequest, "validation_failed", "Grant duration must be positive"
	}
	if req.MaxUses < 0 {
		return http.StatusBadRequest, "validation_failed", "Grant max uses must be positive"
	}
	if _, err := policy.AttrConstraintsFromValues(req.Attrs); err != nil {
		return http.StatusBadRequest, "invalid_attrs", "Invalid attrs"
	}
	if err := validateGrantTargetForOperation(req.Operation, req.Target); err != nil {
		return http.StatusBadRequest, "invalid_target", err.Error()
	}
	return 0, "", ""
}
