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
	TargetSchema       json.RawMessage
	ArgumentsSchema    json.RawMessage
	targetValidator    *jsonschema.Schema
	argumentsValidator *jsonschema.Schema
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
	var document struct {
		Paths      map[string]map[string]json.RawMessage `json:"paths"`
		Components map[string]any                        `json:"components"`
	}
	if err := json.Unmarshal(openAPIRaw, &document); err != nil {
		return nil, fmt.Errorf("decode pinned HF OpenAPI: %w", err)
	}
	var sources []routeSource
	if err := strictjson.Decode(routesRaw, &sources, true); err != nil {
		return nil, fmt.Errorf("decode HF route bindings: %w", err)
	}
	var manual []routeSource
	if err := strictjson.Decode(manualRoutesRaw, &manual, true); err != nil {
		return nil, fmt.Errorf("decode manual HF route bindings: %w", err)
	}
	sources = append(sources, manual...)
	var endpoints []routeSource
	if err := strictjson.Decode(endpointRoutesRaw, &endpoints, true); err != nil {
		return nil, fmt.Errorf("decode endpoint route bindings: %w", err)
	}
	sources = append(sources, endpoints...)
	var uv []routeSource
	if err := strictjson.Decode(uvRoutesRaw, &uv, true); err != nil {
		return nil, fmt.Errorf("decode UV Job route bindings: %w", err)
	}
	sources = append(sources, uv...)
	values := make([]Binding, 0, len(sources))
	seen := make(map[string]bool, len(sources))
	for _, source := range sources {
		binding, err := bindingFromSource(document.Paths, document.Components, source)
		if err != nil {
			return nil, fmt.Errorf("binding %q: %w", source.Operation, err)
		}
		if seen[binding.Operation] {
			return nil, fmt.Errorf("binding %q is duplicated", binding.Operation)
		}
		seen[binding.Operation] = true
		values = append(values, binding)
	}
	slices.SortFunc(values, func(left, right Binding) int { return strings.Compare(left.Operation, right.Operation) })
	return values, nil
}

func bindingFromSource(paths map[string]map[string]json.RawMessage, components map[string]any, source routeSource) (Binding, error) {
	if source.Operation == "" || !validMethod(source.Method) || !strings.HasPrefix(source.Path, "/") {
		return Binding{}, errors.New("operation, method, or path is invalid")
	}
	targetSchema, argumentsSchema := source.TargetSchema, source.ArgumentsSchema
	if targetSchema == nil || argumentsSchema == nil {
		pathItem, found := paths[source.Path]
		if !found {
			return Binding{}, fmt.Errorf("path %q is absent from the pinned OpenAPI", source.Path)
		}
		raw, found := pathItem[strings.ToLower(source.Method)]
		if !found {
			return Binding{}, fmt.Errorf("method %s is absent from %s", source.Method, source.Path)
		}
		var operation operationDocument
		if err := json.Unmarshal(raw, &operation); err != nil {
			return Binding{}, err
		}
		targetSchema = schemaForParameters(operation.Parameters, "path", source.FixedPath)
		var err error
		argumentsSchema, err = schemaForArguments(operation, source.FixedBody, source.ArgumentProjection)
		if err != nil {
			return Binding{}, err
		}
	} else if source.UpstreamReference == "" {
		return Binding{}, errors.New("manual binding has no pinned upstream reference")
	}
	targetRaw, targetValidator, err := compileSchema(source.Operation+"-target", targetSchema, components)
	if err != nil {
		return Binding{}, err
	}
	argumentsRaw, argumentsValidator, err := compileSchema(source.Operation+"-arguments", argumentsSchema, components)
	if err != nil {
		return Binding{}, err
	}
	if source.ObserveMethod != "" {
		if !validMethod(source.ObserveMethod) || !strings.HasPrefix(source.ObservePath, "/") ||
			(source.Reconcile != "present" && source.Reconcile != "absent") {
			return Binding{}, errors.New("observation binding is invalid")
		}
	}
	if source.Transform != "" && source.Transform != "uv_job" && source.Transform != "uv_scheduled_job" {
		return Binding{}, errors.New("operation transform is invalid")
	}
	return Binding{Operation: source.Operation, Method: source.Method, Path: source.Path,
		FixedPath: source.FixedPath, FixedBody: source.FixedBody, ArgumentProjection: source.ArgumentProjection,
		ObserveMethod: source.ObserveMethod, ObservePath: source.ObservePath, Reconcile: source.Reconcile,
		Origin: source.Origin, BodyFromTarget: source.BodyFromTarget, UpstreamReference: source.UpstreamReference,
		Transform:    source.Transform,
		TargetSchema: targetRaw, ArgumentsSchema: argumentsRaw, targetValidator: targetValidator,
		argumentsValidator: argumentsValidator}, nil
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
	schema := map[string]any{"type": "object", "properties": map[string]any{}, "additionalProperties": false}
	if operation.RequestBody != nil {
		media, found := operation.RequestBody.Content["application/json"]
		if !found {
			return nil, errors.New("operation request body is not JSON and needs a dedicated adapter")
		}
		if media.Schema != nil {
			schema = cloneMap(media.Schema)
		}
	}
	if schema["type"] == nil {
		schema["type"] = "object"
		schema["unevaluatedProperties"] = false
		return schema, nil
	}
	if schema["type"] != "object" {
		if projection == "" {
			return nil, errors.New("operation request body is not an object")
		}
		schema = map[string]any{
			"type": "object", "properties": map[string]any{projection: schema},
			"required": []any{projection}, "additionalProperties": false,
		}
	}
	schema["additionalProperties"] = false
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
	return schema, nil
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
