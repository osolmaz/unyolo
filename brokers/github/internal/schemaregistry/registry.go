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
	schemakind "github.com/santhosh-tekuri/jsonschema/v6/kind"

	"github.com/osolmaz/unyolo/brokers/github/internal/opbinding"
	"github.com/osolmaz/unyolo/brokers/github/internal/opcatalog"
	"github.com/osolmaz/unyolo/brokers/github/internal/targetregistry"
	"github.com/osolmaz/unyolo/internal/copyx"
	"github.com/osolmaz/unyolo/internal/strictjson"
	"github.com/osolmaz/unyolo/operation/capability"
)

type Operation struct {
	Target    string         `json:"target"`
	Arguments map[string]any `json:"arguments"`
	Result    map[string]any `json:"result"`
}

// EffectiveSchemas contains the closed schemas enforced for one operation.
type EffectiveSchemas struct {
	Target    map[string]any `json:"target"`
	Arguments map[string]any `json:"arguments"`
	Result    map[string]any `json:"result"`
}

const (
	maxValidationPathRunes        = 192
	maxValidationKeywordRunes     = 64
	maxValidationExpectationRunes = 256
)

// ValidationError is a bounded, value-free description of a schema mismatch.
type ValidationError struct {
	Path        string
	Keyword     string
	Expectation string
}

func (err *ValidationError) Error() string {
	return fmt.Sprintf("%s: %s", err.Path, err.Expectation)
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

func load() error {
	once.Do(func() {
		if err := json.Unmarshal(raw, &loaded); err != nil {
			loadErr = err
			return
		}
		if !validRegistryCounts(loaded) {
			loadErr = errors.New("GitHub schema registry count drifted")
			return
		}
		loadErr = validateRegistrySchemas(loaded)
	})
	return loadErr
}

func validRegistryCounts(value document) bool {
	return value.Version == 1 && len(value.Targets) >= 30 && len(value.Operations) == 1436
}

func validateRegistrySchemas(value document) error {
	if err := validateTargetSchemas(value.Targets); err != nil {
		return err
	}
	return validateOperationSchemas(value.Operations)
}

func validateTargetSchemas(targets map[string]map[string]any) error {
	for kind, schema := range targets {
		if !targetregistry.Known(kind) || !closedSchema(schema) {
			return fmt.Errorf("GitHub target schema %q is invalid", kind)
		}
	}
	return nil
}

func validateOperationSchemas(operations map[string]Operation) error {
	for name, schemas := range operations {
		if schemas.Target == "" || !closedSchema(schemas.Arguments) || !closedSchema(schemas.Result) {
			return fmt.Errorf("GitHub operation schema %q is invalid", name)
		}
	}
	return nil
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
	return copyx.JSONMap(value), found
}

// EffectiveSchemasForOperation returns the same closed schemas used at runtime.
func EffectiveSchemasForOperation(name string) (EffectiveSchemas, error) {
	if err := load(); err != nil {
		return EffectiveSchemas{}, err
	}
	operation, found := loaded.Operations[name]
	if !found {
		return EffectiveSchemas{}, errors.New("unknown GitHub operation")
	}
	target, found := targetSchemaForOperation(name, operation)
	if !found {
		return EffectiveSchemas{}, errors.New("missing GitHub target schema")
	}
	return EffectiveSchemas{
		Target:    target,
		Arguments: copyx.JSONMap(operation.Arguments),
		Result:    copyx.JSONMap(operation.Result),
	}, nil
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
	arguments := copyx.JSONMap(operation.Arguments)
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

func closedSchema(value any) bool {
	switch typed := value.(type) {
	case map[string]any:
		return closedSchemaMap(typed)
	case []any:
		return closedSchemaList(typed)
	}
	return true
}

func closedSchemaMap(value map[string]any) bool {
	if _, present := value["$ref"]; present {
		return false
	}
	if !closedObjectSchema(value) {
		return false
	}
	for _, child := range value {
		if !closedSchema(child) {
			return false
		}
	}
	return true
}

func closedObjectSchema(value map[string]any) bool {
	if value["type"] != "object" {
		return true
	}
	extra, present := value["additionalProperties"]
	return present && extra != true
}

func closedSchemaList(value []any) bool {
	for _, child := range value {
		if !closedSchema(child) {
			return false
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
	return Operation{Target: value.Target, Arguments: copyx.JSONMap(value.Arguments), Result: copyx.JSONMap(value.Result)}
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
	target, public, _, err := sealedSchemas(name)
	if err != nil {
		return err
	}
	if err := validateNamedRaw(targetRaw, target, "target"); err != nil {
		return err
	}
	return validateNamedRaw(argumentsRaw, public, "public arguments")
}

func ValidateSealedArguments(name string, argumentsRaw json.RawMessage) error {
	_, _, sealed, err := sealedSchemas(name)
	if err != nil {
		return err
	}
	return validateNamedRaw(argumentsRaw, sealed, "sealed arguments")
}

// SealedArgumentsRequired reports whether an operation's protected argument
// schema requires a top-level value.
func SealedArgumentsRequired(name string) (bool, error) {
	_, _, sealed, err := sealedSchemas(name)
	if err != nil {
		return false, err
	}
	return len(capability.RequiredPropertyNames(sealed)) > 0, nil
}

func sealedSchemas(name string) (map[string]any, map[string]any, map[string]any, error) {
	descriptor, found := opcatalog.ByName(name)
	if !found || !descriptor.Sealed {
		return nil, nil, nil, errors.New("unknown sealed GitHub operation")
	}
	target, public, sealed := InputSchemas(descriptor.Descriptor)
	return target, public, sealed, nil
}

func validateNamedRaw(raw json.RawMessage, schema map[string]any, name string) error {
	if err := validateRaw(raw, schema); err != nil {
		return fmt.Errorf("%s %w", name, err)
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
	operation, found := ForOperation(name)
	if !found {
		return errors.New("unknown GitHub operation")
	}
	if int64(len(resultRaw)) > resultBytesLimit(name) {
		return errors.New("GitHub operation result is too large")
	}
	if err := validateRaw(resultRaw, operation.Result); err != nil {
		return fmt.Errorf("result %w", err)
	}
	return nil
}

func resultBytesLimit(name string) int64 {
	bindings := opbinding.ByOperation(name)
	if len(bindings) == 1 && bindings[0].ResponseBytesLimit > 0 {
		return bindings[0].ResponseBytesLimit
	}
	return 1 << 20
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
	if len(required) == 1 {
		for _, field := range defaultTargetFields(strings.TrimSuffix(strings.TrimPrefix(operation.Target, "target."), ".v1")) {
			required[field] = true
		}
	}
	addInstallationSelectorRequirement(operation, target, required)
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

func addInstallationSelectorRequirement(operation Operation, target map[string]any, required map[string]bool) {
	if operation.Target == "target.installation.v1" && len(required) == 1 {
		target["anyOf"] = requiredInstallationSelector()
	}
}

func requiredInstallationSelector() []any {
	result := make([]any, 0, 4)
	for _, field := range []string{"id", "installation_id", "installation_account", "name"} {
		result = append(result, map[string]any{"required": []any{field}})
	}
	return result
}

var defaultTargetFieldsByKind = map[string][]string{
	"repo": {"owner", "name"}, "organization": {"name"}, "enterprise": {"name"}, "user": {"name"}, "team": {"name"},
	"environment": {"name"}, "package": {"name"}, "codespace": {"name"}, "advisory": {"name"}, "ref": {"name"},
	"installation": nil, "issue": {"number"}, "pull_request": {"number"}, "alert": {"number"},
}

func defaultTargetFields(kind string) []string {
	if fields, found := defaultTargetFieldsByKind[kind]; found {
		return fields
	}
	return []string{"id"}
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
	location := "https://unyolo.local/github/input.json"
	if err := compiler.AddResource(location, schema); err != nil {
		return errors.New("schema is invalid")
	}
	validator, err := compiler.Compile(location)
	if err != nil {
		return errors.New("schema is invalid")
	}
	if err := validator.Validate(value); err != nil {
		return summarizeValidationError(err)
	}
	return nil
}

func summarizeValidationError(err error) error {
	var validation *jsonschema.ValidationError
	if !errors.As(err, &validation) {
		return errors.New("does not match the closed schema")
	}
	leaf := firstValidationLeaf(validation)
	if leaf == nil || leaf.ErrorKind == nil {
		return errors.New("does not match the closed schema")
	}
	keywordPath := leaf.ErrorKind.KeywordPath()
	keyword := "schema"
	if len(keywordPath) > 0 && keywordPath[0] != "" {
		keyword = keywordPath[0]
	}
	return &ValidationError{
		Path:        boundedString(jsonPointer(leaf.InstanceLocation), maxValidationPathRunes),
		Keyword:     boundedString(keyword, maxValidationKeywordRunes),
		Expectation: boundedString(validationExpectation(leaf.ErrorKind, keyword), maxValidationExpectationRunes),
	}
}

func firstValidationLeaf(err *jsonschema.ValidationError) *jsonschema.ValidationError {
	if err == nil {
		return nil
	}
	for _, cause := range err.Causes {
		if leaf := firstValidationLeaf(cause); leaf != nil {
			return leaf
		}
	}
	return err
}

func jsonPointer(parts []string) string {
	if len(parts) == 0 {
		return "/"
	}
	escaped := make([]string, len(parts))
	for index, part := range parts {
		escaped[index] = strings.ReplaceAll(strings.ReplaceAll(part, "~", "~0"), "/", "~1")
	}
	return "/" + strings.Join(escaped, "/")
}

func boundedString(value string, maxRunes int) string {
	runes := []rune(value)
	if len(runes) <= maxRunes {
		return value
	}
	return string(runes[:maxRunes]) + "…"
}

func validationExpectation(kind jsonschema.ErrorKind, keyword string) string {
	switch typed := kind.(type) {
	case *schemakind.Required:
		missing := slices.Clone(typed.Missing)
		slices.Sort(missing)
		if len(missing) == 1 {
			return fmt.Sprintf("required property %q is missing", missing[0])
		}
		return "required properties are missing"
	case *schemakind.Type:
		want := slices.Clone(typed.Want)
		slices.Sort(want)
		return "must be " + strings.Join(want, " or ")
	case *schemakind.AdditionalProperties:
		return "additional properties are not allowed"
	case *schemakind.Enum:
		return "must match one of the allowed values"
	case *schemakind.Const:
		return "must match the required constant"
	default:
		return keyword + " constraint failed"
	}
}

func HasRawEscapeHatch(name string) bool {
	operation, found := ForOperation(name)
	return found && (containsForbiddenRawField(operation.Arguments) || strings.Contains(strings.ToLower(name), "http.request") || strings.Contains(strings.ToLower(name), "graphql.execute"))
}
