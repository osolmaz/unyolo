package operations

import "net/http"

func classifyResponseValidationError(method string, err error) error {
	if err != nil && method != http.MethodGet && method != http.MethodHead {
		return &PossiblePartialError{Err: err}
	}
	return err
}
