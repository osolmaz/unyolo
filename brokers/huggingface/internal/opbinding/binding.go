// Package opbinding loads the pinned, fixed Hugging Face operation bindings.
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

	"github.com/dlclark/regexp2"
	jsonschema "github.com/santhosh-tekuri/jsonschema/v6"

	"github.com/osolmaz/brokerkit/internal/schemautil"
	"github.com/osolmaz/brokerkit/internal/strictjson"
)

//go:embed hf-openapi-2026-07-13.json
var openAPIRaw []byte

//go:embed routes.json
var routesRaw []byte

//go:embed manual-routes.json
var manualRoutesRaw []byte

//go:embed endpoint-routes.json
var endpointRoutesRaw []byte

//go:embed uv-routes.json
var uvRoutesRaw []byte

type routeSource struct {
	Operation          string            `json:"operation"`
	Method             string            `json:"method"`
	Path               string            `json:"path"`
	FixedPath          map[string]any    `json:"fixed_path,omitempty"`
	FixedBody          map[string]any    `json:"fixed_body,omitempty"`
	ArgumentProjection string            `json:"argument_projection,omitempty"`
	ObserveMethod      string            `json:"observe_method,omitempty"`
	ObservePath        string            `json:"observe_path,omitempty"`
	Reconcile          string            `json:"reconcile,omitempty"`
	Origin             string            `json:"origin,omitempty"`
	TargetSchema       map[string]any    `json:"target_schema,omitempty"`
	ArgumentsSchema    map[string]any    `json:"arguments_schema,omitempty"`
	BodyFromTarget     map[string]string `json:"body_from_target,omitempty"`
	UpstreamReference  string            `json:"upstream_reference,omitempty"`
	Transform          string            `json:"transform,omitempty"`
	CaptureResult      bool              `json:"capture_result,omitempty"`
}

type Binding struct {
	Operation          string
	Method             string
	Path               string
	FixedPath          map[string]any
	FixedBody          map[string]any
	ArgumentProjection string
	ObserveMethod      string
	ObservePath        string
	Reconcile          string
	Origin             string
	BodyFromTarget     map[string]string
	UpstreamReference  string
	Transform          string
	CaptureResult      bool
	QueryParameters    []string
	TargetSchema       json.RawMessage
	ArgumentsSchema    json.RawMessage
	ResultSchema       json.RawMessage
	targetValidator    *jsonschema.Schema
	argumentsValidator *jsonschema.Schema
	resultValidator    *jsonschema.Schema
}

// ArgumentsValidator validates one operation's public argument fragment after
// provider-defined sealed paths have been removed from the schema.
type ArgumentsValidator struct {
	validator *jsonschema.Schema
}

type operationDocument struct {
	Parameters  []parameter                `json:"parameters"`
	RequestBody *requestBody               `json:"requestBody"`
	Responses   map[string]json.RawMessage `json:"responses"`
}

type parameter struct {
	Name     string         `json:"name"`
	In       string         `json:"in"`
	Required bool           `json:"required"`
	Schema   map[string]any `json:"schema"`
}

type requestBody struct {
	Content map[string]mediaType `json:"content"`
}

type mediaType struct {
	Schema map[string]any `json:"schema"`
}

type responseBody struct {
	Content map[string]mediaType `json:"content"`
}

var (
	loadOnce sync.Once
	loaded   []Binding
	loadErr  error
)

func All() ([]Binding, error) {
	loadOnce.Do(func() { loaded, loadErr = load() })
	return slices.Clone(loaded), loadErr
}

func MustAll() []Binding {
	values, err := All()
	if err == nil {
		return values
	}
	panic(fmt.Errorf("load Hugging Face operation bindings: %w", err))
}

func ByName(name string) (Binding, bool) {
	values, err := All()
	if err != nil {
		return Binding{}, false
	}
	for _, value := range values {
		if value.Operation == name {
			return value, true
		}
	}
	return Binding{}, false
}

func (b Binding) Validate(target, arguments json.RawMessage) error {
	if err := b.ValidateTarget(target); err != nil {
		return fmt.Errorf("target: %w", err)
	}
	if err := b.ValidateArguments(arguments); err != nil {
		return fmt.Errorf("arguments: %w", err)
	}
	return nil
}

func (b Binding) ValidateTarget(target json.RawMessage) error {
	return validateRaw(target, b.targetValidator)
}

func (b Binding) ValidateArguments(arguments json.RawMessage) error {
	return validateRaw(arguments, b.argumentsValidator)
}

func (b Binding) ValidateResult(result json.RawMessage) error {
	if b.resultValidator == nil {
		return errors.New("operation has no bounded result schema")
	}
	return validateRaw(result, b.resultValidator)
}

// PublicArgumentsValidator compiles the binding's argument schema without the
// paths that are supplied through the sealed payload boundary. The resulting
// validator never needs the sealed plaintext.
func (b Binding) PublicArgumentsValidator(paths []string) (*ArgumentsValidator, error) {
	if len(paths) == 0 {
		return &ArgumentsValidator{validator: b.argumentsValidator}, nil
	}
	var schema map[string]any
	if err := json.Unmarshal(b.ArgumentsSchema, &schema); err != nil {
		return nil, errors.New("decode operation argument schema")
	}
	for _, value := range paths {
		path := strings.Split(value, ".")
		found, err := removeSchemaPath(schema, schema, path)
		if err != nil {
			return nil, err
		}
		if !found {
			return nil, fmt.Errorf("sealed argument path %q is absent from operation schema", value)
		}
	}
	_, validator, err := compileSchema(b.Operation+"-public-arguments", schema, nil)
	if err != nil {
		return nil, fmt.Errorf("compile public argument schema: %w", err)
	}
	return &ArgumentsValidator{validator: validator}, nil
}

// Validate checks one public argument fragment.
func (v *ArgumentsValidator) Validate(arguments json.RawMessage) error {
	if v == nil || v.validator == nil {
		return errors.New("operation argument validator is unavailable")
	}
	return validateRaw(arguments, v.validator)
}

func removeSchemaPath(root, current map[string]any, path []string) (bool, error) {
	if len(path) == 0 {
		return false, errors.New("sealed argument path is empty")
	}
	resolved, err := resolveLocalSchema(root, current)
	if err != nil {
		return false, err
	}
	propertyFound, err := removeSchemaPropertyPath(root, resolved, path)
	if err != nil {
		return false, err
	}
	branchFound, err := removeSchemaPathFromBranches(root, resolved, path)
	if err != nil {
		return false, err
	}
	return propertyFound || branchFound, nil
}

func removeSchemaPropertyPath(root, schema map[string]any, path []string) (bool, error) {
	properties, ok := schema["properties"].(map[string]any)
	if !ok {
		return false, nil
	}
	child, ok := properties[path[0]].(map[string]any)
	if !ok {
		return false, nil
	}
	if len(path) > 1 {
		return removeSchemaPath(root, child, path[1:])
	}
	delete(properties, path[0])
	schemautil.RemoveRequiredProperty(schema, path[0])
	decrementMinimumProperties(schema)
	return true, nil
}

func decrementMinimumProperties(schema map[string]any) {
	minimum, ok := schema["minProperties"].(float64)
	if !ok || minimum <= 0 {
		return
	}
	if minimum == 1 {
		delete(schema, "minProperties")
		return
	}
	schema["minProperties"] = minimum - 1
}

func removeSchemaPathFromBranches(root, schema map[string]any, path []string) (bool, error) {
	found := false
	for _, keyword := range []string{"anyOf", "oneOf", "allOf"} {
		branches, _ := schema[keyword].([]any)
		for _, value := range branches {
			branch, ok := value.(map[string]any)
			if !ok {
				continue
			}
			branchFound, err := removeSchemaPath(root, branch, path)
			if err != nil {
				return false, err
			}
			found = found || branchFound
		}
	}
	return found, nil
}

func resolveLocalSchema(root, schema map[string]any) (map[string]any, error) {
	reference, _ := schema["$ref"].(string)
	if !strings.HasPrefix(reference, "#/") {
		return schema, nil
	}
	var current any = root
	for _, token := range strings.Split(strings.TrimPrefix(reference, "#/"), "/") {
		token = strings.ReplaceAll(strings.ReplaceAll(token, "~1", "/"), "~0", "~")
		object, ok := current.(map[string]any)
		if !ok {
			return nil, fmt.Errorf("operation schema reference %q is invalid", reference)
		}
		current, ok = object[token]
		if !ok {
			return nil, fmt.Errorf("operation schema reference %q is unresolved", reference)
		}
	}
	resolved, ok := current.(map[string]any)
	if !ok {
		return nil, fmt.Errorf("operation schema reference %q is not an object", reference)
	}
	return resolved, nil
}

func validateRaw(raw json.RawMessage, validator *jsonschema.Schema) error {
	var value any
	if err := strictjson.Decode(raw, &value, false); err != nil {
		return errors.New("invalid JSON")
	}
	if err := validator.Validate(value); err != nil {
		return errors.New("does not match the operation schema")
	}
	return nil
}

func load() ([]Binding, error) {
	document, err := loadOpenAPIDocument()
	if err != nil {
		return nil, err
	}
	sources, err := loadRouteSources()
	if err != nil {
		return nil, err
	}
	values, err := bindingsFromSources(document.Paths, document.Components, sources)
	if err != nil {
		return nil, err
	}
	slices.SortFunc(values, func(left, right Binding) int { return strings.Compare(left.Operation, right.Operation) })
	return values, nil
}

type openAPIDocument struct {
	Paths      map[string]map[string]json.RawMessage `json:"paths"`
	Components map[string]any                        `json:"components"`
}

func loadOpenAPIDocument() (openAPIDocument, error) {
	var document openAPIDocument
	if err := json.Unmarshal(openAPIRaw, &document); err != nil {
		return openAPIDocument{}, fmt.Errorf("decode pinned HF OpenAPI: %w", err)
	}
	return document, nil
}

func loadRouteSources() ([]routeSource, error) {
	sources, err := decodeRouteSources(routesRaw, "HF route bindings")
	if err != nil {
		return nil, err
	}
	for _, input := range []struct {
		raw  []byte
		name string
	}{
		{manualRoutesRaw, "manual HF route bindings"},
		{endpointRoutesRaw, "endpoint route bindings"},
		{uvRoutesRaw, "UV Job route bindings"},
	} {
		next, err := decodeRouteSources(input.raw, input.name)
		if err != nil {
			return nil, err
		}
		sources = append(sources, next...)
	}
	return sources, nil
}

func decodeRouteSources(raw []byte, name string) ([]routeSource, error) {
	var sources []routeSource
	if err := strictjson.Decode(raw, &sources, true); err != nil {
		return nil, fmt.Errorf("decode %s: %w", name, err)
	}
	return sources, nil
}

func bindingsFromSources(paths map[string]map[string]json.RawMessage, components map[string]any, sources []routeSource) ([]Binding, error) {
	values := make([]Binding, 0, len(sources))
	seen := make(map[string]bool, len(sources))
	for _, source := range sources {
		binding, err := bindingFromSource(paths, components, source)
		if err != nil {
			return nil, fmt.Errorf("binding %q: %w", source.Operation, err)
		}
		if seen[binding.Operation] {
			return nil, fmt.Errorf("binding %q is duplicated", binding.Operation)
		}
		seen[binding.Operation] = true
		values = append(values, binding)
	}
	return values, nil
}

func bindingFromSource(paths map[string]map[string]json.RawMessage, components map[string]any, source routeSource) (Binding, error) {
	if err := validateBindingSource(source); err != nil {
		return Binding{}, err
	}
	targetSchema, argumentsSchema, queryParameters, err := bindingSchemas(paths, source)
	if err != nil {
		return Binding{}, err
	}
	targetRaw, targetValidator, err := compileSchema(source.Operation+"-target", targetSchema, components)
	if err != nil {
		return Binding{}, err
	}
	argumentsRaw, argumentsValidator, err := compileSchema(source.Operation+"-arguments", argumentsSchema, components)
	if err != nil {
		return Binding{}, err
	}
	resultRaw, resultValidator, err := compileBindingResult(paths, components, source)
	if err != nil {
		return Binding{}, err
	}
	return Binding{Operation: source.Operation, Method: source.Method, Path: source.Path,
		FixedPath: source.FixedPath, FixedBody: source.FixedBody, ArgumentProjection: source.ArgumentProjection,
		ObserveMethod: source.ObserveMethod, ObservePath: source.ObservePath, Reconcile: source.Reconcile,
		Origin: source.Origin, BodyFromTarget: source.BodyFromTarget, UpstreamReference: source.UpstreamReference,
		Transform: source.Transform, CaptureResult: source.CaptureResult, QueryParameters: queryParameters,
		TargetSchema: targetRaw, ArgumentsSchema: argumentsRaw, targetValidator: targetValidator,
		ResultSchema: resultRaw, argumentsValidator: argumentsValidator, resultValidator: resultValidator}, nil
}

func validateBindingSource(source routeSource) error {
	if source.Operation == "" || !validMethod(source.Method) || !strings.HasPrefix(source.Path, "/") {
		return errors.New("operation, method, or path is invalid")
	}
	if err := validateManualSource(source); err != nil {
		return err
	}
	if err := validateObservationSource(source); err != nil {
		return err
	}
	return validateTransformSource(source)
}

func validateManualSource(source routeSource) error {
	if source.TargetSchema != nil && source.ArgumentsSchema != nil && source.UpstreamReference == "" {
		return errors.New("manual binding has no pinned upstream reference")
	}
	return nil
}

func validateObservationSource(source routeSource) error {
	if source.ObserveMethod != "" && (!validMethod(source.ObserveMethod) || !strings.HasPrefix(source.ObservePath, "/") ||
		(source.Reconcile != "present" && source.Reconcile != "absent")) {
		return errors.New("observation binding is invalid")
	}
	return nil
}

func validateTransformSource(source routeSource) error {
	if source.Transform != "" && source.Transform != "uv_job" && source.Transform != "uv_scheduled_job" {
		return errors.New("operation transform is invalid")
	}
	return nil
}

func bindingSchemas(paths map[string]map[string]json.RawMessage, source routeSource) (map[string]any, map[string]any, []string, error) {
	if source.TargetSchema != nil && source.ArgumentsSchema != nil {
		return source.TargetSchema, source.ArgumentsSchema, nil, nil
	}
	operation, err := operationAt(paths, source)
	if err != nil {
		return nil, nil, nil, err
	}
	arguments, err := schemaForArguments(operation, source.FixedBody, source.ArgumentProjection)
	return schemaForTarget(operation.Parameters, source.FixedPath), arguments, queryParameterNames(operation.Parameters), err
}

func schemaForTarget(parameters []parameter, fixed map[string]any) map[string]any {
	pathSchema := schemaForParameters(parameters, "path", fixed)
	querySchema := schemaForParameters(parameters, "query", nil)
	properties := pathSchema["properties"].(map[string]any)
	for name, schema := range querySchema["properties"].(map[string]any) {
		properties[name] = schema
	}
	required, _ := pathSchema["required"].([]string)
	required = append(required, requiredStrings(querySchema)...)
	if len(required) > 0 {
		slices.Sort(required)
		pathSchema["required"] = required
	}
	return pathSchema
}

func requiredStrings(schema map[string]any) []string {
	values, _ := schema["required"].([]string)
	return values
}

func queryParameterNames(parameters []parameter) []string {
	names := make([]string, 0)
	for _, parameter := range parameters {
		if parameter.In == "query" {
			names = append(names, parameter.Name)
		}
	}
	slices.Sort(names)
	return names
}

func compileBindingResult(paths map[string]map[string]json.RawMessage, components map[string]any, source routeSource) (json.RawMessage, *jsonschema.Schema, error) {
	if !source.CaptureResult {
		return nil, nil, nil
	}
	resultSchema, err := successResponseSchema(paths, source)
	if err != nil {
		return nil, nil, err
	}
	return compileSchema(source.Operation+"-result", resultSchema, components)
}

func successResponseSchema(paths map[string]map[string]json.RawMessage, source routeSource) (map[string]any, error) {
	operation, err := operationAt(paths, source)
	if err != nil {
		return nil, err
	}
	for _, status := range []string{"200", "201", "202"} {
		if schema, found, err := responseSchema(operation.Responses[status]); err != nil || found {
			return schema, err
		}
	}
	return nil, errors.New("captured operation has no JSON success response schema")
}

func operationAt(paths map[string]map[string]json.RawMessage, source routeSource) (operationDocument, error) {
	pathItem, found := paths[source.Path]
	if !found {
		return operationDocument{}, fmt.Errorf("path %q is absent from the pinned OpenAPI", source.Path)
	}
	operationRaw, found := pathItem[strings.ToLower(source.Method)]
	if !found {
		return operationDocument{}, fmt.Errorf("method %s is absent from %s", source.Method, source.Path)
	}
	var operation operationDocument
	err := json.Unmarshal(operationRaw, &operation)
	return operation, err
}

func responseSchema(raw json.RawMessage) (map[string]any, bool, error) {
	if len(raw) == 0 {
		return nil, false, nil
	}
	var response responseBody
	if err := json.Unmarshal(raw, &response); err != nil {
		return nil, false, err
	}
	media, found := response.Content["application/json"]
	return media.Schema, found && media.Schema != nil, nil
}

func schemaForParameters(parameters []parameter, location string, fixed map[string]any) map[string]any {
	properties := map[string]any{}
	required := []string{}
	for _, parameter := range parameters {
		if parameter.In != location {
			continue
		}
		if _, isFixed := fixed[parameter.Name]; isFixed {
			continue
		}
		properties[parameter.Name] = parameter.Schema
		if parameter.Required {
			required = append(required, parameter.Name)
		}
	}
	slices.Sort(required)
	schema := map[string]any{"type": "object", "properties": properties, "additionalProperties": false}
	if len(required) > 0 {
		schema["required"] = required
	}
	return schema
}

func schemaForArguments(operation operationDocument, fixed map[string]any, projection string) (map[string]any, error) {
	schema, err := requestBodySchema(operation)
	if err != nil {
		return nil, err
	}
	if schema["type"] == nil {
		return typelessObjectSchema(schema), nil
	}
	if schema["type"] != "object" {
		return projectedBodySchema(schema, projection)
	}
	schema["additionalProperties"] = false
	removeFixedBodyFields(schema, fixed)
	return schema, nil
}

func requestBodySchema(operation operationDocument) (map[string]any, error) {
	schema := map[string]any{"type": "object", "properties": map[string]any{}, "additionalProperties": false}
	if operation.RequestBody == nil {
		return schema, nil
	}
	media, found := operation.RequestBody.Content["application/json"]
	if !found {
		return nil, errors.New("operation request body is not JSON and needs a dedicated adapter")
	}
	if media.Schema != nil {
		return cloneMap(media.Schema), nil
	}
	return schema, nil
}

func typelessObjectSchema(schema map[string]any) map[string]any {
	schema["type"] = "object"
	schema["unevaluatedProperties"] = false
	return schema
}

func projectedBodySchema(schema map[string]any, projection string) (map[string]any, error) {
	if projection == "" {
		return nil, errors.New("operation request body is not an object")
	}
	return map[string]any{
		"type":                 "object",
		"properties":           map[string]any{projection: schema},
		"required":             []any{projection},
		"additionalProperties": false,
	}, nil
}

func removeFixedBodyFields(schema map[string]any, fixed map[string]any) {
	properties, _ := schema["properties"].(map[string]any)
	if properties == nil {
		properties = map[string]any{}
		schema["properties"] = properties
	}
	for key := range fixed {
		delete(properties, key)
	}
	if required, ok := schema["required"].([]any); ok {
		filtered := make([]any, 0, len(required))
		for _, value := range required {
			name, _ := value.(string)
			if _, isFixed := fixed[name]; !isFixed {
				filtered = append(filtered, value)
			}
		}
		schema["required"] = filtered
	}
}

func compileSchema(name string, schema, components map[string]any) (json.RawMessage, *jsonschema.Schema, error) {
	wireSchema := standaloneSchema(schema, components)
	raw, err := json.Marshal(wireSchema)
	if err != nil {
		return nil, nil, err
	}

	schema = cloneMap(wireSchema)
	definitions := takeDefinitions(schema)
	schema["$schema"] = "https://json-schema.org/draft/2020-12/schema"
	rootRaw, err := json.Marshal(schema)
	if err != nil {
		return nil, nil, err
	}
	var root any
	if err := json.Unmarshal(rootRaw, &root); err != nil {
		return nil, nil, err
	}
	definitions["root"] = root
	document := map[string]any{
		"$schema": "https://json-schema.org/draft/2020-12/schema",
		"$ref":    "#/$defs/root", "$defs": definitions,
		"components": components,
	}
	compiler := jsonschema.NewCompiler()
	compiler.UseRegexpEngine(compileECMAScriptRegexp)
	location := "https://brokerkit.local/huggingface/" + name + ".json"
	if err := compiler.AddResource(location, document); err != nil {
		return nil, nil, err
	}
	validator, err := compiler.Compile(location)
	return raw, validator, err
}

func standaloneSchema(schema, components map[string]any) map[string]any {
	result := cloneMap(schema)
	closeObjectSchemas(result)
	result["$schema"] = "https://json-schema.org/draft/2020-12/schema"
	if components != nil {
		result["components"] = cloneMap(components)
	}
	return result
}

func takeDefinitions(schema map[string]any) map[string]any {
	result := map[string]any{}
	local, _ := schema["$defs"].(map[string]any)
	for key, value := range local {
		result[key] = value
	}
	delete(schema, "$defs")
	return result
}

func closeObjectSchemas(value any) {
	switch typed := value.(type) {
	case map[string]any:
		_, hasProperties := typed["properties"]
		if (typed["type"] == "object" || hasProperties) && typed["additionalProperties"] == nil {
			typed["additionalProperties"] = false
		}
		for _, child := range typed {
			closeObjectSchemas(child)
		}
	case []any:
		for _, child := range typed {
			closeObjectSchemas(child)
		}
	}
}

type ecmaRegexp regexp2.Regexp

func (regexp *ecmaRegexp) MatchString(value string) bool {
	matched, err := (*regexp2.Regexp)(regexp).MatchString(value)
	return err == nil && matched
}

func (regexp *ecmaRegexp) String() string { return (*regexp2.Regexp)(regexp).String() }

func compileECMAScriptRegexp(pattern string) (jsonschema.Regexp, error) {
	compiled, err := regexp2.Compile(pattern, regexp2.ECMAScript)
	return (*ecmaRegexp)(compiled), err
}

func cloneMap(value map[string]any) map[string]any {
	raw, _ := json.Marshal(value)
	var clone map[string]any
	_ = json.Unmarshal(raw, &clone)
	return clone
}

func validMethod(method string) bool {
	return slices.Contains([]string{http.MethodGet, http.MethodPost, http.MethodPut, http.MethodPatch, http.MethodDelete}, method)
}
