// Package schemaregistry owns closed generated GitHub operation schemas.
package schemaregistry

import (
	_ "embed"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"strings"
	"sync"

	jsonschema "github.com/santhosh-tekuri/jsonschema/v6"

	"github.com/osolmaz/brokerkit/brokers/github/internal/opbinding"
	"github.com/osolmaz/brokerkit/brokers/github/internal/opcatalog"
	"github.com/osolmaz/brokerkit/brokers/github/internal/targetregistry"
	"github.com/osolmaz/brokerkit/capability"
	"github.com/osolmaz/brokerkit/internal/strictjson"
)

type Operation struct {
	Target    string         `json:"target"`
	Arguments map[string]any `json:"arguments"`
	Result    map[string]any `json:"result"`
}

type document struct {
	Version    int                       `json:"version"`
	Targets    map[string]map[string]any `json:"targets"`
	Operations map[string]Operation      `json:"operations"`
}

//go:embed schemas.json
var raw []byte

var once sync.Once
var loaded document
var loadErr error

//nolint:cyclop // Registry count and closure checks are kept in the single load boundary.
func load() error {
	once.Do(func() {
		if err := json.Unmarshal(raw, &loaded); err != nil {
			loadErr = err
			return
		}
		if loaded.Version != 1 || len(loaded.Targets) < 30 || len(loaded.Operations) != 1436 {
			loadErr = errors.New("GitHub schema registry count drifted")
			return
		}
		for kind, schema := range loaded.Targets {
			if !targetregistry.Known(kind) || !closedSchema(schema) {
				loadErr = fmt.Errorf("GitHub target schema %q is invalid", kind)
				return
			}
		}
		for name, schemas := range loaded.Operations {
			if schemas.Target == "" || !closedSchema(schemas.Arguments) || !closedSchema(schemas.Result) {
				loadErr = fmt.Errorf("GitHub operation schema %q is invalid", name)
				return
			}
		}
	})
	return loadErr
}

func ForOperation(name string) (Operation, bool) {
	if load() != nil {
		return Operation{}, false
	}
	value, found := loaded.Operations[name]
	return cloneOperation(value), found
}

func Target(kind string) (map[string]any, bool) {
	if load() != nil {
		return nil, false
	}
	value, found := loaded.Targets[kind]
	return cloneMap(value), found
}

func InputSchemas(descriptor capability.Descriptor) (map[string]any, map[string]any, map[string]any) {
	operation, found := ForOperation(descriptor.Name)
	if !found {
		panic("missing GitHub operation schema: " + descriptor.Name)
	}
	if operation.Target != "target."+descriptor.TargetKind+".v1" {
		panic("GitHub operation target schema drifted: " + descriptor.Name)
	}
	target, found := targetSchemaForOperation(descriptor.Name, operation)
	if !found {
		panic("missing GitHub target schema: " + descriptor.TargetKind)
	}
	arguments := cloneMap(operation.Arguments)
	if !descriptor.Sealed {
		return target, arguments, nil
	}
	public, sealed := capability.SplitSealedArgumentsSchema(arguments, descriptor.SealedInputPaths)
	return target, public, sealed
}

func OperationNames() ([]string, error) {
	if err := load(); err != nil {
		return nil, err
	}
	result := make([]string, 0, len(loaded.Operations))
	for name := range loaded.Operations {
		result = append(result, name)
	}
	slices.Sort(result)
	return result, nil
}

//nolint:cyclop // Recursive JSON Schema shapes require explicit map and array handling.
func closedSchema(value any) bool {
	switch typed := value.(type) {
	case map[string]any:
		if _, present := typed["$ref"]; present {
			return false
		}
		if typed["type"] == "object" {
			if extra, present := typed["additionalProperties"]; !present || extra == true {
				return false
			}
		}
		for _, child := range typed {
			if !closedSchema(child) {
				return false
			}
		}
	case []any:
		for _, child := range typed {
			if !closedSchema(child) {
				return false
			}
		}
	}
	return true
}

func containsForbiddenRawField(schema map[string]any) bool {
	properties, _ := schema["properties"].(map[string]any)
	for _, name := range []string{"method", "url", "graphql", "caller", "headers"} {
		if _, found := properties[name]; found {
			return true
		}
	}
	return false
}

func cloneOperation(value Operation) Operation {
	return Operation{Target: value.Target, Arguments: cloneMap(value.Arguments), Result: cloneMap(value.Result)}
}
func cloneMap(value map[string]any) map[string]any {
	data, _ := json.Marshal(value)
	var result map[string]any
	_ = json.Unmarshal(data, &result)
	return result
}

func Validate() error { return load() }

func ValidateSubmission(name string, targetRaw, argumentsRaw json.RawMessage) error {
	if len(targetRaw)+len(argumentsRaw) > 1<<20 {
		return errors.New("GitHub operation input is too large")
	}
	operation, found := ForOperation(name)
	if !found {
		return errors.New("unknown GitHub operation")
	}
	target, found := targetSchemaForOperation(name, operation)
	if !found {
		return errors.New("missing GitHub target schema")
	}
	if err := validateRaw(targetRaw, target); err != nil {
		return fmt.Errorf("target %w", err)
	}
	if err := validateRaw(argumentsRaw, operation.Arguments); err != nil {
		return fmt.Errorf("arguments %w", err)
	}
	return nil
}

func ValidatePublicSubmission(name string, targetRaw, argumentsRaw json.RawMessage) error {
	descriptor, found := opcatalog.ByName(name)
	if !found || !descriptor.Sealed {
		return errors.New("unknown sealed GitHub operation")
	}
	target, public, _ := InputSchemas(descriptor.Descriptor)
	if err := validateRaw(targetRaw, target); err != nil {
		return fmt.Errorf("target %w", err)
	}
	if err := validateRaw(argumentsRaw, public); err != nil {
		return fmt.Errorf("public arguments %w", err)
	}
	return nil
}

func ValidateSealedArguments(name string, argumentsRaw json.RawMessage) error {
	descriptor, found := opcatalog.ByName(name)
	if !found || !descriptor.Sealed {
		return errors.New("unknown sealed GitHub operation")
	}
	_, _, sealed := InputSchemas(descriptor.Descriptor)
	if err := validateRaw(argumentsRaw, sealed); err != nil {
		return fmt.Errorf("sealed arguments %w", err)
	}
	return nil
}

func ValidateArguments(name string, argumentsRaw json.RawMessage) error {
	operation, found := ForOperation(name)
	if !found {
		return errors.New("unknown GitHub operation")
	}
	if err := validateRaw(argumentsRaw, operation.Arguments); err != nil {
		return fmt.Errorf("arguments %w", err)
	}
	return nil
}

func ValidateStreamPublic(name string, targetRaw, argumentsRaw json.RawMessage) error {
	operation, found := ForOperation(name)
	if !found {
		return errors.New("unknown GitHub stream operation")
	}
	target, found := targetSchemaForOperation(name, operation)
	if !found {
		return errors.New("missing GitHub target schema")
	}
	if err := validateRaw(targetRaw, target); err != nil {
		return fmt.Errorf("target %w", err)
	}
	if err := validateRaw(argumentsRaw, operation.Arguments); err != nil {
		return fmt.Errorf("public arguments %w", err)
	}
	return nil
}

func ValidateResult(name string, resultRaw json.RawMessage) error {
	if len(resultRaw) > 1<<20 {
		return errors.New("GitHub operation result is too large")
	}
	operation, found := ForOperation(name)
	if !found {
		return errors.New("unknown GitHub operation")
	}
	if err := validateRaw(resultRaw, operation.Result); err != nil {
		return fmt.Errorf("result %w", err)
	}
	return nil
}

func targetSchemaForID(id string) (map[string]any, bool) {
	const prefix = "target."
	const suffix = ".v1"
	if !strings.HasPrefix(id, prefix) || !strings.HasSuffix(id, suffix) {
		return nil, false
	}
	return Target(strings.TrimSuffix(strings.TrimPrefix(id, prefix), suffix))
}

func targetSchemaForOperation(name string, operation Operation) (map[string]any, bool) {
	target, found := targetSchemaForID(operation.Target)
	if !found {
		return nil, false
	}
	required := stringSet(target["required"])
	bindings := opbinding.ByOperation(name)
	if len(bindings) == 1 {
		for _, parameter := range bindings[0].TargetPathParameters {
			required[parameter.Field] = true
		}
	}
	values := make([]string, 0, len(required))
	for field := range required {
		values = append(values, field)
	}
	slices.Sort(values)
	encoded := make([]any, len(values))
	for index, field := range values {
		encoded[index] = field
	}
	target["required"] = encoded
	return target, true
}

func stringSet(value any) map[string]bool {
	result := map[string]bool{}
	switch values := value.(type) {
	case []any:
		for _, item := range values {
			if field, ok := item.(string); ok {
				result[field] = true
			}
		}
	case []string:
		for _, field := range values {
			result[field] = true
		}
	}
	return result
}

func validateRaw(raw json.RawMessage, schema map[string]any) error {
	var value any
	if err := strictjson.Decode(raw, &value, false); err != nil {
		return errors.New("is invalid JSON")
	}
	compiler := jsonschema.NewCompiler()
	location := "https://brokerkit.local/github/input.json"
	if err := compiler.AddResource(location, schema); err != nil {
		return errors.New("schema is invalid")
	}
	validator, err := compiler.Compile(location)
	if err != nil {
		return errors.New("schema is invalid")
	}
	if err := validator.Validate(value); err != nil {
		return errors.New("does not match the closed schema")
	}
	return nil
}

func HasRawEscapeHatch(name string) bool {
	operation, found := ForOperation(name)
	return found && (containsForbiddenRawField(operation.Arguments) || strings.Contains(strings.ToLower(name), "http.request") || strings.Contains(strings.ToLower(name), "graphql.execute"))
}
