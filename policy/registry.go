package policy

import (
	"errors"
	"fmt"
	"slices"
	"strings"
)

// Registry is provider-owned vocabulary for policy validation.
type Registry struct {
	Operations map[string]OperationSpec
	Targets    map[string]TargetSpec
	Attrs      map[string]AttrSpec
}

// OperationSpec describes one provider operation.
type OperationSpec struct {
	TargetKinds []string
	Attrs       []string
	Grantable   bool
}

// TargetSpec describes one target kind.
type TargetSpec struct {
	Fields map[string]FieldSpec
}

// FieldSpec describes one target field.
type FieldSpec struct {
	Required bool
}

// AttrSpec describes one request attr.
type AttrSpec struct{}

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
	return nil
}

func (r Registry) validateTargets() error {
	for kind := range r.Targets {
		if strings.TrimSpace(kind) == "" {
			return errors.New("registry target kind is required")
		}
	}
	return nil
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
		if fieldSpec.Required && strings.TrimSpace(target.Fields[name]) == "" {
			return fmt.Errorf("target kind %q requires field %q", target.Kind, name)
		}
	}
	for name := range target.Fields {
		if _, ok := spec.Fields[name]; !ok {
			return fmt.Errorf("target kind %q does not support field %q", target.Kind, name)
		}
	}
	return nil
}

func validateRequestAttrs(operation string, attrs map[string]string, op OperationSpec, registryAttrs map[string]AttrSpec) error {
	for name := range attrs {
		if _, ok := registryAttrs[name]; !ok {
			return fmt.Errorf("unknown attr %q", name)
		}
		if !slices.Contains(op.Attrs, name) {
			return fmt.Errorf("operation %q does not support attr %q", operation, name)
		}
	}
	return nil
}
