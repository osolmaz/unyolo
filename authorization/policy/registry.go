package policy

import (
	"errors"
	"fmt"
	"slices"
	"strconv"
	"strings"

	"github.com/osolmaz/unyolo/authorization/budget"
)

// MatchMode selects how a provider-owned policy field is matched.
type MatchMode string

const (
	// MatchGlob applies path.Match semantics. Wildcards do not cross '/'.
	MatchGlob MatchMode = "glob"
	// MatchAnyGlob accepts a value set when any concrete value matches.
	MatchAnyGlob MatchMode = "any_glob"
	// MatchPathGlob additionally permits a complete "**" path segment.
	MatchPathGlob MatchMode = "path_glob"
	// MatchRecursivePathGlob permits "**" anywhere and lets it cross '/'.
	MatchRecursivePathGlob MatchMode = "recursive_path_glob"
	// MatchPathOutsidePrefix accepts paths outside every configured prefix.
	MatchPathOutsidePrefix MatchMode = "path_outside_prefix"
	// MatchIntegerMaximum treats policy values as inclusive integer ceilings.
	MatchIntegerMaximum MatchMode = "integer_maximum"
)

// GrantMode identifies the execution shape approved by a request rule.
type GrantMode string

const (
	GrantModeWindow    GrantMode = "window"
	GrantModeExecution GrantMode = "execution"
)

// Registry is provider-owned vocabulary for policy validation.
type Registry struct {
	Operations map[string]OperationSpec
	Targets    map[string]TargetSpec
	Attrs      map[string]AttrSpec
}

// OperationSpec describes one provider operation.
type OperationSpec struct {
	TargetKinds                []string
	Attrs                      []string
	Grantable                  bool
	GrantMode                  GrantMode
	GrantModes                 []GrantMode
	MaxGrantMinutes            int
	MaxGrantUses               usebudget.Limit
	DisallowUnlimitedGrantUses bool
}

// TargetSpec describes one target kind.
type TargetSpec struct {
	Fields map[string]FieldSpec
}

// FieldSpec describes one target field.
type FieldSpec struct {
	Required bool
	Match    MatchMode
}

// AttrSpec describes one request attr.
type AttrSpec struct {
	Match        MatchMode
	GrantMatch   MatchMode
	GrantMayOmit bool
}

// Validate checks that a provider registry is internally consistent.
func (r Registry) Validate() error { return r.validate() }

// Operation returns a defensive copy of a registered operation.
func (r Registry) Operation(name string) (OperationSpec, bool) {
	spec, ok := r.Operations[name]
	if !ok {
		return OperationSpec{}, false
	}
	spec.TargetKinds = slices.Clone(spec.TargetKinds)
	spec.Attrs = slices.Clone(spec.Attrs)
	spec.GrantModes = slices.Clone(spec.GrantModes)
	return spec, true
}

// AllowsGrantMode reports whether a registered operation supports mode.
func (op OperationSpec) AllowsGrantMode(mode GrantMode) bool {
	return op.Grantable && op.allowsGrantMode(mode)
}

// ValidateRequest checks a provider-classified request against the registry.
func (r Registry) ValidateRequest(request Request) error { return r.validateRequest(request) }

func (r Registry) validate() error {
	if len(r.Operations) == 0 {
		return errors.New("registry operations must not be empty")
	}
	if len(r.Targets) == 0 {
		return errors.New("registry targets must not be empty")
	}
	if err := r.validateOperations(); err != nil {
		return err
	}
	return r.validateTargets()
}

func (r Registry) validateOperations() error {
	for name, op := range r.Operations {
		if strings.TrimSpace(name) == "" {
			return errors.New("registry operation name is required")
		}
		if err := r.validateOperation(name, op); err != nil {
			return err
		}
	}
	return nil
}

func (r Registry) validateOperation(name string, op OperationSpec) error {
	if len(op.TargetKinds) == 0 {
		return fmt.Errorf("registry operation %q target kinds must not be empty", name)
	}
	for _, kind := range op.TargetKinds {
		if _, ok := r.Targets[kind]; !ok {
			return fmt.Errorf("registry operation %q references unknown target kind %q", name, kind)
		}
	}
	for _, attr := range op.Attrs {
		if _, ok := r.Attrs[attr]; !ok {
			return fmt.Errorf("registry operation %q references unknown attr %q", name, attr)
		}
	}
	return validateOperationGrantMode(name, op)
}

func validateOperationGrantMode(name string, op OperationSpec) error {
	if !op.Grantable {
		return validateNonGrantableOperationModes(name, op)
	}
	if !validGrantMode(defaultedGrantMode(op.GrantMode)) {
		return fmt.Errorf("registry operation %q has unsupported grant mode %q", name, op.GrantMode)
	}
	if err := validateAllowedGrantModes(name, op); err != nil {
		return err
	}
	return validateOperationGrantBounds(name, op)
}

func validateNonGrantableOperationModes(name string, op OperationSpec) error {
	if op.GrantMode != "" || len(op.GrantModes) > 0 || op.MaxGrantMinutes != 0 || op.MaxGrantUses != 0 || op.DisallowUnlimitedGrantUses {
		return fmt.Errorf("registry operation %q is not grantable but declares grant settings", name)
	}
	return nil
}

func validateOperationGrantBounds(name string, op OperationSpec) error {
	if err := validateOperationGrantDuration(name, op.MaxGrantMinutes); err != nil {
		return err
	}
	if err := validateOperationGrantUses(name, op.MaxGrantUses); err != nil {
		return err
	}
	if defaultedGrantMode(op.GrantMode) == GrantModeExecution && op.MaxGrantUses > 1 {
		return fmt.Errorf("registry execution operation %q has invalid reusable grant settings", name)
	}
	return nil
}

func validateOperationGrantDuration(name string, minutes int) error {
	if minutes < 0 || minutes > absoluteMaxGrantMinutes {
		return fmt.Errorf("registry operation %q has invalid maximum grant duration", name)
	}
	return nil
}

func validateOperationGrantUses(name string, uses usebudget.Limit) error {
	if uses < 0 || uses > usebudget.MaxFiniteUses {
		return fmt.Errorf("registry operation %q has invalid maximum grant uses", name)
	}
	return nil
}

func validateAllowedGrantModes(name string, op OperationSpec) error {
	for _, mode := range op.GrantModes {
		if !validGrantMode(mode) {
			return fmt.Errorf("registry operation %q has unsupported allowed grant mode %q", name, mode)
		}
	}
	if len(op.GrantModes) > 0 && !slices.Contains(op.GrantModes, defaultedGrantMode(op.GrantMode)) {
		return fmt.Errorf("registry operation %q default grant mode is not allowed", name)
	}
	return nil
}

func (op OperationSpec) allowsGrantMode(mode GrantMode) bool {
	if len(op.GrantModes) == 0 {
		return defaultedGrantMode(op.GrantMode) == mode
	}
	return slices.Contains(op.GrantModes, mode)
}

func (r Registry) validateTargets() error {
	if err := r.validateTargetSpecs(); err != nil {
		return err
	}
	return r.validateAttrSpecs()
}

func (r Registry) validateTargetSpecs() error {
	for kind, target := range r.Targets {
		if strings.TrimSpace(kind) == "" {
			return errors.New("registry target kind is required")
		}
		for field, spec := range target.Fields {
			if strings.TrimSpace(field) == "" {
				return fmt.Errorf("registry target kind %q field name is required", kind)
			}
			if !validMatchMode(defaultedMatchMode(spec.Match)) {
				return fmt.Errorf("registry target kind %q field %q has unsupported match mode %q", kind, field, spec.Match)
			}
		}
	}
	return nil
}

func (r Registry) validateAttrSpecs() error {
	for attr, spec := range r.Attrs {
		if strings.TrimSpace(attr) == "" {
			return errors.New("registry attr name is required")
		}
		if !validMatchMode(defaultedMatchMode(spec.Match)) {
			return fmt.Errorf("registry attr %q has unsupported match mode %q", attr, spec.Match)
		}
		if spec.GrantMatch != "" && !validMatchMode(spec.GrantMatch) {
			return fmt.Errorf("registry attr %q has unsupported grant match mode %q", attr, spec.GrantMatch)
		}
	}
	return nil
}

func defaultedMatchMode(mode MatchMode) MatchMode {
	if mode == "" {
		return MatchGlob
	}
	return mode
}

func validMatchMode(mode MatchMode) bool {
	return mode == MatchGlob || mode == MatchAnyGlob || mode == MatchPathGlob || mode == MatchRecursivePathGlob ||
		mode == MatchPathOutsidePrefix || mode == MatchIntegerMaximum
}

func defaultedGrantMode(mode GrantMode) GrantMode {
	if mode == "" {
		return GrantModeWindow
	}
	return mode
}

func validGrantMode(mode GrantMode) bool {
	return mode == GrantModeWindow || mode == GrantModeExecution
}

func (r Registry) validateRequest(request Request) error {
	op, ok := r.Operations[request.Operation]
	if !ok {
		return fmt.Errorf("unknown operation %q", request.Operation)
	}
	target, ok := r.Targets[request.Target.Kind]
	if !ok {
		return fmt.Errorf("unknown target kind %q", request.Target.Kind)
	}
	if !slices.Contains(op.TargetKinds, request.Target.Kind) {
		return fmt.Errorf("operation %q does not support target kind %q", request.Operation, request.Target.Kind)
	}
	if err := validateRequestTarget(request.Target, target); err != nil {
		return err
	}
	return validateRequestAttrs(request.Operation, request.Attrs, op, r.Attrs)
}

func validateRequestTarget(target Target, spec TargetSpec) error {
	for name, fieldSpec := range spec.Fields {
		if fieldSpec.Required && len(target.Fields[name]) == 0 {
			return fmt.Errorf("target kind %q requires field %q", target.Kind, name)
		}
	}
	for name, values := range target.Fields {
		fieldSpec, ok := spec.Fields[name]
		if !ok {
			return fmt.Errorf("target kind %q does not support field %q", target.Kind, name)
		}
		if err := validateRequestValues(values, fieldSpec.Match); err != nil {
			return fmt.Errorf("target kind %q field %q: %w", target.Kind, name, err)
		}
	}
	return nil
}

func validateRequestAttrs(operation string, attrs map[string][]string, op OperationSpec, registryAttrs map[string]AttrSpec) error {
	for name, values := range attrs {
		attrSpec, ok := registryAttrs[name]
		if !ok {
			return fmt.Errorf("unknown attr %q", name)
		}
		if !slices.Contains(op.Attrs, name) {
			return fmt.Errorf("operation %q does not support attr %q", operation, name)
		}
		if err := validateRequestValues(values, attrSpec.Match); err != nil {
			return fmt.Errorf("attr %q: %w", name, err)
		}
	}
	return nil
}

func validateRequestValues(values []string, mode MatchMode) error {
	if len(values) == 0 {
		return errors.New("values must not be empty")
	}
	for _, value := range values {
		if err := validateRequestValue(value, mode); err != nil {
			return err
		}
	}
	return nil
}

func validateRequestValue(value string, mode MatchMode) error {
	if strings.TrimSpace(value) == "" {
		return errors.New("value must not be empty")
	}
	switch defaultedMatchMode(mode) {
	case MatchGlob, MatchAnyGlob:
		return nil
	case MatchPathGlob, MatchRecursivePathGlob, MatchPathOutsidePrefix:
		return validatePathRequestValue(value)
	case MatchIntegerMaximum:
		return validateIntegerRequestValue(value)
	}
	return nil
}

func validatePathRequestValue(value string) error {
	if len(value) > maxPathValueBytes {
		return fmt.Errorf("value must not exceed %d bytes", maxPathValueBytes)
	}
	if strings.Count(value, "/") >= maxPathSegments {
		return fmt.Errorf("value must not exceed %d segments", maxPathSegments)
	}
	return nil
}

func validateIntegerRequestValue(value string) error {
	number, err := strconv.ParseInt(value, 10, 64)
	if err != nil || number < 0 {
		return errors.New("value must be a non-negative integer")
	}
	return nil
}
