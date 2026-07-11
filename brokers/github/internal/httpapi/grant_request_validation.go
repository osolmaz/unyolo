package httpapi

import (
	"errors"
	"strings"
)

func validateClientRequestID(value string) error {
	if value == "" {
		return errors.New("client_request_id is required")
	}
	if len(value) > 128 || strings.TrimSpace(value) != value || strings.ContainsAny(value, " \t\r\n") {
		return errors.New("client_request_id must be 1-128 non-whitespace bytes")
	}
	return nil
}
