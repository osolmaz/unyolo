package operations

import (
	"reflect"
	"slices"
	"strings"

	hfpolicy "github.com/osolmaz/brokerkit/brokers/huggingface/internal/policy"
)

// InputSchemas describes the requester-visible shape of a custom adapter.
// Provider constraints remain enforced by Decode; these schemas keep MCP and
// other discovery clients structurally typed before submission.
type InputSchemas struct {
	Target    map[string]any
	Arguments map[string]any
	Sealed    map[string]any
}

type inputSchemaExamples struct {
	target    any
	arguments any
	sealed    any
}

var customInputSchemaExamples = map[string]inputSchemaExamples{
	"repo.contents.read":      {repositoryTarget{}, repoContentsArguments{}, nil},
	"repo.list":               {repositoryTarget{}, repoListArguments{}, nil},
	"repo.metadata.read":      {repositoryTarget{}, emptyArguments{}, nil},
	"repo.tree.list":          {repositoryTarget{}, repoTreeArguments{}, nil},
	"repo.create":             {repositoryTarget{}, repoCreateArguments{}, nil},
	"repo.delete":             {repositoryTarget{}, emptyArguments{}, nil},
	"repo.gating.update":      {repositoryTarget{}, gatingArguments{}, nil},
	"repo.move":               {repositoryTarget{}, moveArguments{}, nil},
	"repo.visibility.update":  {repositoryTarget{}, visibilityArguments{}, nil},
	"repo.branch.create":      {refTarget{}, branchCreateArguments{}, nil},
	"repo.branch.delete":      {refTarget{}, emptyArguments{}, nil},
	"repo.tag.create":         {refTarget{}, tagCreateArguments{}, nil},
	"repo.tag.delete":         {refTarget{}, emptyArguments{}, nil},
	"repo.commit.create":      {repositoryContentTarget{}, commitCreateArguments{}, nil},
	"repo.file.copy":          {repositoryContentTarget{}, fileCopyArguments{}, nil},
	"repo.file.delete":        {repositoryContentTarget{}, fileDeleteArguments{}, nil},
	"repo.file.upload":        {repositoryContentTarget{}, fileUploadArguments{}, nil},
	"space.hot_reload.apply":  {repositoryContentTarget{}, commitCreateArguments{}, nil},
	"bucket.batch.apply":      {bucketTarget{}, bucketBatchArguments{}, nil},
	"bucket.sync.apply":       {bucketTarget{}, bucketBatchArguments{}, nil},
	"bucket.move":             {bucketTarget{}, bucketMoveArguments{}, nil},
	"bucket.object.delete":    {bucketTarget{}, bucketDeleteArguments{}, nil},
	"space.restart":           {spaceTarget{}, restartArguments{}, nil},
	"space.hardware.update":   {spaceTarget{}, hardwareArguments{}, nil},
	"space.sleep_time.update": {spaceTarget{}, sleepTimeArguments{}, nil},
	"space.variable.set":      {spaceTarget{}, variableSetArguments{}, nil},
	"space.variable.delete":   {spaceTarget{}, variableDeleteArguments{}, nil},
	"space.pause":             {spaceTarget{}, emptyArguments{}, nil},
	"space.dev_mode.enable":   {spaceTarget{}, emptyArguments{}, nil},
	"space.dev_mode.disable":  {spaceTarget{}, emptyArguments{}, nil},
	"sandbox.create":          {sandboxTarget{}, sandboxCreatePublic{}, sandboxCreateSecret{}},
	"sandbox.pool.create":     {sandboxTarget{}, sandboxPoolCreatePublic{}, nil},
	"sandbox.file.write":      {sandboxTarget{}, sandboxFileWriteArguments{}, nil},
	"sandbox.file.delete":     {sandboxTarget{}, sandboxFileDeleteArguments{}, nil},
	"sandbox.file.mkdir":      {sandboxTarget{}, sandboxFileMkdirArguments{}, nil},
	"sandbox.pool.warm":       {sandboxTarget{}, sandboxPoolWarmArguments{}, nil},
	"sandbox.process.kill":    {sandboxTarget{}, sandboxProcessKillArguments{}, nil},
	"sandbox.delete":          {sandboxTarget{}, emptyArguments{}, nil},
	"sandbox.pool.delete":     {sandboxTarget{}, emptyArguments{}, nil},
}

// CustomInputSchemas returns schemas for adapters that are not generated from
// a pinned upstream binding.
func CustomInputSchemas(name string) (InputSchemas, bool) {
	examples, found := customInputSchemaExamples[name]
	if !found {
		return InputSchemas{}, false
	}
	return InputSchemas{Target: structuralSchema(examples.target), Arguments: structuralSchema(examples.arguments), Sealed: optionalStructuralSchema(examples.sealed)}, true
}

// WindowTargetSchema is the closed provider policy target accepted by bounded
// protocol operations.
func WindowTargetSchema() map[string]any {
	return structuralSchema(hfpolicy.Target{})
}

func optionalStructuralSchema(value any) map[string]any {
	if value == nil {
		return nil
	}
	return structuralSchema(value)
}

func structuralSchema(value any) map[string]any {
	return structuralSchemaType(reflect.TypeOf(value))
}

func structuralSchemaType(value reflect.Type) map[string]any {
	if build, found := structuralSchemaBuilders[value.Kind()]; found {
		return build(value)
	}
	return scalarSchema("string")
}

var structuralSchemaBuilders map[reflect.Kind]func(reflect.Type) map[string]any

func init() {
	structuralSchemaBuilders = map[reflect.Kind]func(reflect.Type) map[string]any{
		reflect.Pointer: schemaForPointer,
		reflect.Struct:  schemaForStruct,
		reflect.Slice:   schemaForSequence,
		reflect.Array:   schemaForSequence,
		reflect.Map:     schemaForMap,
		reflect.Bool:    func(reflect.Type) map[string]any { return scalarSchema("boolean") },
		reflect.Int:     func(reflect.Type) map[string]any { return scalarSchema("integer") },
		reflect.Int8:    func(reflect.Type) map[string]any { return scalarSchema("integer") },
		reflect.Int16:   func(reflect.Type) map[string]any { return scalarSchema("integer") },
		reflect.Int32:   func(reflect.Type) map[string]any { return scalarSchema("integer") },
		reflect.Int64:   func(reflect.Type) map[string]any { return scalarSchema("integer") },
		reflect.Uint:    func(reflect.Type) map[string]any { return scalarSchema("integer") },
		reflect.Uint8:   func(reflect.Type) map[string]any { return scalarSchema("integer") },
		reflect.Uint16:  func(reflect.Type) map[string]any { return scalarSchema("integer") },
		reflect.Uint32:  func(reflect.Type) map[string]any { return scalarSchema("integer") },
		reflect.Uint64:  func(reflect.Type) map[string]any { return scalarSchema("integer") },
		reflect.Float32: func(reflect.Type) map[string]any { return scalarSchema("number") },
		reflect.Float64: func(reflect.Type) map[string]any { return scalarSchema("number") },
	}
}

func schemaForPointer(value reflect.Type) map[string]any { return structuralSchemaType(value.Elem()) }

func schemaForSequence(value reflect.Type) map[string]any {
	return map[string]any{"type": "array", "items": structuralSchemaType(value.Elem())}
}

func schemaForMap(value reflect.Type) map[string]any {
	return map[string]any{"type": "object", "additionalProperties": structuralSchemaType(value.Elem())}
}

func schemaForStruct(value reflect.Type) map[string]any {
	properties := make(map[string]any)
	var required []string
	for index := 0; index < value.NumField(); index++ {
		field := value.Field(index)
		name, optional, visible := jsonField(field)
		if !field.IsExported() || !visible {
			continue
		}
		properties[name] = structuralSchemaType(field.Type)
		if !optional {
			required = append(required, name)
		}
	}
	schema := map[string]any{"type": "object", "properties": properties, "additionalProperties": false}
	if len(required) > 0 {
		schema["required"] = required
	}
	return schema
}

func scalarSchema(kind string) map[string]any {
	return map[string]any{"type": kind}
}

func jsonField(field reflect.StructField) (string, bool, bool) {
	tag := field.Tag.Get("json")
	parts := strings.Split(tag, ",")
	if len(parts) > 0 && parts[0] == "-" {
		return "", false, false
	}
	name := field.Name
	if len(parts) > 0 && parts[0] != "" {
		name = parts[0]
	}
	return name, slices.Contains(parts[1:], "omitempty"), true
}
