// Package opbinding loads immutable generated GitHub REST bindings.
package opbinding

import (
	_ "embed"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"slices"
	"strings"
	"sync"
)

type Parameter struct {
	Name string `json:"name"`
	In   string `json:"in"`
}

type Binding struct {
	ID                   string      `json:"id"`
	Operation            string      `json:"operation"`
	UpstreamOperationID  string      `json:"upstream_operation_id"`
	Method               string      `json:"method"`
	PathTemplate         string      `json:"path_template"`
	CredentialKind       string      `json:"credential_kind"`
	APIVersion           string      `json:"api_version"`
	MediaType            string      `json:"media_type"`
	TargetPathParameters []string    `json:"target_path_parameters,omitempty"`
	ArgumentParameters   []Parameter `json:"argument_parameters,omitempty"`
	RequestSchema        string      `json:"request_schema"`
	ResponseSchema       string      `json:"response_schema"`
	ResponseProjection   []string    `json:"response_projection,omitempty"`
	RequestBytesLimit    int64       `json:"request_bytes_limit"`
	ResponseBytesLimit   int64       `json:"response_bytes_limit"`
	Pagination           string      `json:"pagination"`
	ConditionalRequest   bool        `json:"conditional_request"`
	RedirectPolicy       string      `json:"redirect_policy"`
	Reconciliation       string      `json:"reconciliation"`
}

//go:embed bindings.json
var raw []byte

var once sync.Once
var values []Binding
var loadErr error

func All() ([]Binding, error) {
	once.Do(func() {
		if err := json.Unmarshal(raw, &values); err != nil {
			loadErr = err
			return
		}
		loadErr = Validate(values)
	})
	return slices.Clone(values), loadErr
}

func ByOperation(name string) []Binding {
	values, err := All()
	if err != nil {
		return nil
	}
	result := []Binding{}
	for _, value := range values {
		if value.Operation == name {
			result = append(result, value)
		}
	}
	return result
}

//nolint:cyclop // Binding transport and projection invariants are reviewed in one pass.
func Validate(values []Binding) error {
	if len(values) != 1152 {
		return fmt.Errorf("GitHub REST binding count=%d, want 1152", len(values))
	}
	seenIDs, seenOperations := map[string]bool{}, map[string]bool{}
	previous := ""
	for _, value := range values {
		if value.ID == "" || value.ID <= previous || seenIDs[value.ID] || seenOperations[value.Operation] {
			return errors.New("GitHub REST bindings are duplicated or unsorted")
		}
		previous, seenIDs[value.ID], seenOperations[value.Operation] = value.ID, true, true
		if !slices.Contains([]string{http.MethodGet, http.MethodPut, http.MethodPost, http.MethodDelete, http.MethodPatch, http.MethodHead}, value.Method) || !strings.HasPrefix(value.PathTemplate, "/") || value.APIVersion != "2026-03-10" || value.CredentialKind == "" || value.RequestSchema == "" || value.ResponseSchema == "" || value.RequestBytesLimit <= 0 || value.ResponseBytesLimit <= 0 || value.RedirectPolicy == "" || value.Reconciliation == "" {
			return fmt.Errorf("GitHub REST binding %q is incomplete", value.ID)
		}
		if strings.Contains(strings.ToLower(value.PathTemplate), "http://") || strings.Contains(strings.ToLower(value.PathTemplate), "https://") {
			return fmt.Errorf("GitHub REST binding %q contains a caller-selectable URL", value.ID)
		}
		for _, parameter := range value.ArgumentParameters {
			if parameter.In != "query" || parameter.Name == "method" || parameter.Name == "graphql" || parameter.Name == "caller" || parameter.Name == "headers" {
				return fmt.Errorf("GitHub REST binding %q exposes unsafe parameters", value.ID)
			}
		}
	}
	return nil
}
