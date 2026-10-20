// Package apicompat classifies requests that stock GitHub clients, such as
// the GitHub CLI, send to the broker's GitHub-compatible API. A request is
// served only when it classifies to exactly one catalog operation or one
// reviewed GraphQL shape; everything else is refused before any upstream call.
package apicompat

import (
	"fmt"
	"net/http"
)

// Refusal is a request the GitHub-compatible API does not serve. Its message
// never contains request bodies or credentials and is safe to return.
type Refusal struct {
	Status  int
	Message string
}

func (r *Refusal) Error() string { return r.Message }

func refuse(status int, format string, args ...any) *Refusal {
	return &Refusal{Status: status, Message: fmt.Sprintf(format, args...)}
}

func unsupported(format string, args ...any) *Refusal {
	return refuse(http.StatusForbidden, "gh-broker: "+format, args...)
}

func malformed(format string, args ...any) *Refusal {
	return refuse(http.StatusBadRequest, "gh-broker: "+format, args...)
}
