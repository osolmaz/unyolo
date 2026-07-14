// Package opbinding loads immutable generated GitHub REST bindings.
package opbinding

import (
	_ "embed"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"regexp"
	"slices"
	"strings"
	"sync"

	"github.com/osolmaz/brokerkit/internal/sortedlookup"
)

type Parameter struct {
	Name string `json:"name"`
	In   string `json:"in"`
}

type TargetParameter struct {
	Name  string `json:"name"`
	Field string `json:"field"`
}

type Binding struct {
	ID                      string            `json:"id"`
	Operation               string            `json:"operation"`
	UpstreamOperationID     string            `json:"upstream_operation_id"`
	Method                  string            `json:"method"`
	PathTemplate            string            `json:"path_template"`
	CredentialKind          string            `json:"credential_kind"`
	APIVersion              string            `json:"api_version"`
	MediaType               string            `json:"media_type"`
	PathParameters          []string          `json:"path_parameters,omitempty"`
	TargetPathParameters    []TargetParameter `json:"target_path_parameters,omitempty"`
	ArgumentParameters      []Parameter       `json:"argument_parameters,omitempty"`
	RequestSchema           string            `json:"request_schema"`
	ResponseSchema          string            `json:"response_schema"`
	ResponseProjection      []string          `json:"response_projection,omitempty"`
	ResponseRootType        string            `json:"response_root_type"`
	ServerRole              string            `json:"server_role"`
	RequestBytesLimit       int64             `json:"request_bytes_limit"`
	ResponseBytesLimit      int64             `json:"response_bytes_limit"`
	Pagination              string            `json:"pagination"`
	ConditionalRequest      bool              `json:"conditional_request"`
	RedirectPolicy          string            `json:"redirect_policy"`
	StreamDirection         string            `json:"stream_direction,omitempty"`
	Reconciliation          string            `json:"reconciliation"`
	ReconciliationBindingID string            `json:"reconciliation_binding_id,omitempty"`
}

//go:embed bindings.json
var raw []byte

var once sync.Once
var values []Binding
var loadErr error
var safeProjectionSegmentPattern = regexp.MustCompile(`^[A-Za-z0-9_-]{1,255}$`)

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

func ByID(id string) (Binding, bool) {
	return sortedlookup.LoadString(All, id, func(value Binding) string { return value.ID })
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
		if !validTransport(value) || !validSchemas(value) || !validExecution(value) {
			return fmt.Errorf("GitHub REST binding %q is incomplete", value.ID)
		}
		if value.ServerRole == "uploads" && value.StreamDirection != "upload" {
			return fmt.Errorf("GitHub REST binding %q has an invalid server role", value.ID)
		}
		if strings.Contains(strings.ToLower(value.PathTemplate), "http://") || strings.Contains(strings.ToLower(value.PathTemplate), "https://") {
			return fmt.Errorf("GitHub REST binding %q contains a caller-selectable URL", value.ID)
		}
		if value.StreamDirection != "" && value.StreamDirection != "upload" && value.StreamDirection != "download" {
			return fmt.Errorf("GitHub REST binding %q has an invalid stream direction", value.ID)
		}
		if (value.StreamDirection != "") != (value.RedirectPolicy == "github-download-host-allowlist") {
			return fmt.Errorf("GitHub REST binding %q stream metadata drifted", value.ID)
		}
		for _, parameter := range value.TargetPathParameters {
			if !slices.Contains(value.PathParameters, parameter.Name) || !slices.Contains([]string{"id", "number", "owner", "name"}, parameter.Field) {
				return fmt.Errorf("GitHub REST binding %q has invalid target path ownership", value.ID)
			}
		}
		if len(value.ResponseProjection) == 0 {
			return fmt.Errorf("GitHub REST binding %q has no safe response projection", value.ID)
		}
		for _, field := range value.ResponseProjection {
			if !safeResponseField(field) {
				return fmt.Errorf("GitHub REST binding %q exposes unsafe response field %q", value.ID, field)
			}
		}
		for _, parameter := range value.ArgumentParameters {
			if parameter.In != "query" || parameter.Name == "method" || parameter.Name == "graphql" || parameter.Name == "caller" || parameter.Name == "headers" {
				return fmt.Errorf("GitHub REST binding %q exposes unsafe parameters", value.ID)
			}
		}
	}
	for _, value := range values {
		switch value.Reconciliation {
		case "none":
			if value.ReconciliationBindingID != "" {
				return fmt.Errorf("GitHub REST binding %q has an unexpected reconciliation binding", value.ID)
			}
		case "absence-proof":
			read, found := bindingByID(values, value.ReconciliationBindingID)
			if !found || read.Method != http.MethodGet || read.PathTemplate != value.PathTemplate {
				return fmt.Errorf("GitHub REST binding %q has an invalid absence proof", value.ID)
			}
		default:
			return fmt.Errorf("GitHub REST binding %q has unsupported reconciliation", value.ID)
		}
	}
	return nil
}

func validTransport(value Binding) bool {
	return slices.Contains([]string{http.MethodGet, http.MethodPut, http.MethodPost, http.MethodDelete, http.MethodPatch, http.MethodHead}, value.Method) &&
		strings.HasPrefix(value.PathTemplate, "/") && value.APIVersion == "2026-03-10" && value.CredentialKind != "" && value.ServerRole != ""
}

func validSchemas(value Binding) bool {
	return value.RequestSchema != "" && value.ResponseSchema != "" && value.RequestBytesLimit > 0 && value.ResponseBytesLimit > 0 &&
		slices.Contains([]string{"object", "array"}, value.ResponseRootType)
}

func validExecution(value Binding) bool {
	return value.RedirectPolicy != "" && value.Reconciliation != "" && slices.Contains([]string{"api", "uploads"}, value.ServerRole)
}

func bindingByID(values []Binding, id string) (Binding, bool) {
	return sortedlookup.String(values, id, func(value Binding) string { return value.ID })
}

func safeResponseField(field string) bool {
	if field == "$none" {
		return true
	}
	parts := strings.Split(field, ".")
	for _, part := range parts {
		if !safeProjectionSegment(part) {
			return false
		}
	}
	switch parts[len(parts)-1] {
	case "id", "node_id", "name", "number", "state", "status", "type", "sha", "url", "created_at", "updated_at":
		return true
	default:
		return false
	}
}

func safeProjectionSegment(value string) bool {
	return safeProjectionSegmentPattern.MatchString(value)
}
