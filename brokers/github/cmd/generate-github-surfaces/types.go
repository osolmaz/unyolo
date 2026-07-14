package main

import (
	"encoding/json"

	"github.com/osolmaz/brokerkit/brokers/github/internal/opcatalog"
)

const (
	restExpected        = 1196
	activeQueryRoots    = 32
	activeMutationRoots = 252
	apiVersion          = "2026-03-10"
)

type openAPIDocument struct {
	OpenAPI    string                                `json:"openapi"`
	Paths      map[string]map[string]json.RawMessage `json:"paths"`
	Components map[string]any                        `json:"components"`
}

type restOperation struct {
	OperationID string           `json:"operationId"`
	Summary     string           `json:"summary"`
	Tags        []string         `json:"tags"`
	Parameters  []map[string]any `json:"parameters"`
	RequestBody map[string]any   `json:"requestBody"`
	Responses   map[string]any   `json:"responses"`
	GitHub      map[string]any   `json:"x-github"`
	Servers     []server         `json:"servers"`
}

type server struct {
	URL string `json:"url"`
}

type permissionGroup struct {
	Title        string            `json:"title"`
	DisplayTitle string            `json:"displayTitle"`
	Permissions  []permissionRoute `json:"permissions"`
}

type permissionRoute struct {
	Verb                  string `json:"verb"`
	RequestPath           string `json:"requestPath"`
	Access                string `json:"access"`
	UserToServer          bool   `json:"user-to-server"`
	ServerToServer        bool   `json:"server-to-server"`
	AdditionalPermissions bool   `json:"additional-permissions"`
}

type restCoverage struct {
	UpstreamID          string            `json:"upstream_id"`
	Method              string            `json:"method"`
	Path                string            `json:"path"`
	Summary             string            `json:"summary"`
	Disposition         string            `json:"disposition"`
	CatalogOperations   []string          `json:"catalog_operations,omitempty"`
	DuplicateOf         string            `json:"duplicate_of,omitempty"`
	CredentialKind      string            `json:"credential_kind,omitempty"`
	RequiredCredential  string            `json:"required_credential,omitempty"`
	RequiredPermissions map[string]string `json:"required_github_permissions,omitempty"`
	Reason              string            `json:"reason,omitempty"`
	RiskClasses         []string          `json:"risk_classes,omitempty"`
	Reviewed            bool              `json:"reviewed"`
}

type restBinding struct {
	ID                      string                   `json:"id"`
	Operation               string                   `json:"operation"`
	UpstreamOperationID     string                   `json:"upstream_operation_id"`
	Method                  string                   `json:"method"`
	PathTemplate            string                   `json:"path_template"`
	CredentialKind          string                   `json:"credential_kind"`
	APIVersion              string                   `json:"api_version"`
	MediaType               string                   `json:"media_type"`
	PathParameters          []string                 `json:"path_parameters,omitempty"`
	TargetPathParameters    []targetParameter        `json:"target_path_parameters,omitempty"`
	AuthorizationParameters []authorizationParameter `json:"authorization_parameters,omitempty"`
	AuthenticatedUserTarget bool                     `json:"authenticated_user_target,omitempty"`
	ArgumentParameters      []parameterBinding       `json:"argument_parameters,omitempty"`
	RequestSchema           string                   `json:"request_schema"`
	ResponseSchema          string                   `json:"response_schema"`
	ResponseProjection      []string                 `json:"response_projection,omitempty"`
	ResponseRootType        string                   `json:"response_root_type"`
	ServerRole              string                   `json:"server_role"`
	RequestBytesLimit       int64                    `json:"request_bytes_limit"`
	ResponseBytesLimit      int64                    `json:"response_bytes_limit"`
	SuccessStatusCodes      []int                    `json:"success_status_codes"`
	Pagination              string                   `json:"pagination"`
	ConditionalRequest      bool                     `json:"conditional_request"`
	RedirectPolicy          string                   `json:"redirect_policy"`
	StreamDirection         string                   `json:"stream_direction,omitempty"`
	Reconciliation          string                   `json:"reconciliation"`
	ReconciliationBindingID string                   `json:"reconciliation_binding_id,omitempty"`
}

type targetParameter struct {
	Name  string `json:"name"`
	Field string `json:"field"`
}

type authorizationParameter struct {
	Name      string `json:"name"`
	Attribute string `json:"attribute"`
}

type parameterBinding struct {
	Name string `json:"name"`
	In   string `json:"in"`
}

type schemaRegistry struct {
	Version    int                         `json:"version"`
	Targets    map[string]map[string]any   `json:"targets"`
	Operations map[string]operationSchemas `json:"operations"`
}

type operationSchemas struct {
	Target    string         `json:"target"`
	Arguments map[string]any `json:"arguments"`
	Result    map[string]any `json:"result"`
}

type targetDescriptor struct {
	Kind         string   `json:"kind"`
	Schema       string   `json:"schema"`
	PolicyFields []string `json:"policy_fields"`
}

type graphqlResponse struct {
	Data struct {
		Schema introspectionSchema `json:"__schema"`
	} `json:"data"`
	Errors []any `json:"errors"`
}

type introspectionSchema struct {
	QueryType    typeName            `json:"queryType"`
	MutationType typeName            `json:"mutationType"`
	Types        []introspectionType `json:"types"`
}

type typeName struct {
	Name string `json:"name"`
}

type introspectionType struct {
	Kind        string               `json:"kind"`
	Name        string               `json:"name"`
	Fields      []introspectionField `json:"fields"`
	InputFields []introspectionInput `json:"inputFields"`
	EnumValues  []struct {
		Name string `json:"name"`
	} `json:"enumValues"`
}

type introspectionField struct {
	Name              string               `json:"name"`
	Description       string               `json:"description"`
	Args              []introspectionInput `json:"args"`
	Type              typeRef              `json:"type"`
	IsDeprecated      bool                 `json:"isDeprecated"`
	DeprecationReason string               `json:"deprecationReason"`
}

type introspectionInput struct {
	Name         string  `json:"name"`
	Description  string  `json:"description"`
	Type         typeRef `json:"type"`
	DefaultValue *string `json:"defaultValue"`
}

type typeRef struct {
	Kind   string   `json:"kind"`
	Name   string   `json:"name"`
	OfType *typeRef `json:"ofType"`
}

type graphqlCoverage struct {
	RootType           string `json:"root_type"`
	Field              string `json:"field"`
	Deprecated         bool   `json:"deprecated"`
	Disposition        string `json:"disposition"`
	CatalogOperation   string `json:"catalog_operation,omitempty"`
	DuplicateOf        string `json:"duplicate_of,omitempty"`
	RequiredCredential string `json:"required_credential,omitempty"`
	Reason             string `json:"reason,omitempty"`
	PersistedDigest    string `json:"persisted_digest,omitempty"`
	Reviewed           bool   `json:"reviewed"`
}

type persistedDocument struct {
	CatalogOperation   string         `json:"catalog_operation"`
	RootType           string         `json:"root_type"`
	RootField          string         `json:"root_field"`
	OperationName      string         `json:"operation_name"`
	Document           string         `json:"document"`
	SHA256             string         `json:"sha256"`
	VariableSchema     map[string]any `json:"variable_schema"`
	ResponseProjection []string       `json:"response_projection"`
	ExpectedCost       int            `json:"expected_cost"`
	CredentialKind     string         `json:"credential_kind"`
}

type graphqlManifest struct {
	Version           int                 `json:"version"`
	SchemaFingerprint string              `json:"schema_fingerprint"`
	Documents         []persistedDocument `json:"documents"`
}

type highRiskReview struct {
	Version int               `json:"version"`
	Classes []riskReviewClass `json:"classes"`
}

type riskReviewClass struct {
	Name       string   `json:"name"`
	Rule       string   `json:"rule"`
	Operations []string `json:"operations"`
}

type generatedState struct {
	descriptors     []opcatalog.Descriptor
	restCoverage    []restCoverage
	bindings        []restBinding
	graphqlCoverage []graphqlCoverage
	manifest        graphqlManifest
	schemas         schemaRegistry
	targets         []targetDescriptor
	highRisk        highRiskReview
}

type overrideFile struct {
	Version                    int                 `json:"version"`
	RESTOperationNames         map[string][]string `json:"rest_operation_names"`
	RESTOperationRequestFields map[string][]string `json:"rest_operation_request_fields"`
	HighRiskOperations         []string            `json:"high_risk_operations"`
	InternalGraphQLRoots       []string            `json:"internal_graphql_roots"`
}
