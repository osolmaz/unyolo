package operations

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	"github.com/osolmaz/brokerkit/agent/v1"
	"github.com/osolmaz/brokerkit/brokers/huggingface/internal/hubclient"
	"github.com/osolmaz/brokerkit/brokers/huggingface/internal/opcatalog"
	hfpolicy "github.com/osolmaz/brokerkit/brokers/huggingface/internal/policy"
)

type spaceClient interface {
	SpaceRuntime(context.Context, hubclient.SpaceRef) (hubclient.SpaceRuntime, error)
	RestartSpace(context.Context, hubclient.SpaceRef, bool) (hubclient.SpaceRuntime, error)
	PauseSpace(context.Context, hubclient.SpaceRef) (hubclient.SpaceRuntime, error)
	RequestSpaceHardware(context.Context, hubclient.SpaceRef, string, *int) (hubclient.SpaceRuntime, error)
	SetSpaceSleepTime(context.Context, hubclient.SpaceRef, int) (hubclient.SpaceRuntime, error)
	SetSpaceDevMode(context.Context, hubclient.SpaceRef, bool) (hubclient.SpaceRuntime, error)
	SpaceVariables(context.Context, hubclient.SpaceRef) (map[string]hubclient.SpaceVariable, error)
	SetSpaceVariable(context.Context, hubclient.SpaceRef, string, string, string) error
	DeleteSpaceVariable(context.Context, hubclient.SpaceRef, string) error
}

type spaceAdapter struct {
	descriptor opcatalog.Descriptor
	client     spaceClient
}

type spaceTarget struct {
	Kind  string `json:"kind"`
	Owner string `json:"owner"`
	Name  string `json:"name"`
}

type restartArguments struct {
	FactoryReboot bool `json:"factory_reboot"`
}

type hardwareArguments struct {
	Flavor           string `json:"flavor"`
	SleepTimeSeconds *int   `json:"sleep_time_seconds,omitempty"`
}

type sleepTimeArguments struct {
	Seconds int `json:"seconds"`
}

type variableSetArguments struct {
	Key         string `json:"key"`
	Value       string `json:"value"`
	Description string `json:"description,omitempty"`
}

type variableDeleteArguments struct {
	Key string `json:"key"`
}

type spacePreconditions struct {
	ObservedDigest string `json:"observed_digest"`
}

func NewSpaceAdapters(client spaceClient) ([]Adapter, error) {
	if client == nil {
		return nil, errors.New("hugging face space client is required")
	}
	names := []string{"space.dev_mode.disable", "space.dev_mode.enable", "space.hardware.update", "space.pause", "space.restart", "space.sleep_time.update", "space.variable.delete", "space.variable.set"}
	adapters := make([]Adapter, 0, len(names))
	for _, name := range names {
		descriptor, found := opcatalog.ByName(name)
		if !found {
			return nil, fmt.Errorf("operation %q is absent from the catalog", name)
		}
		adapters = append(adapters, &spaceAdapter{descriptor: descriptor, client: client})
	}
	return adapters, nil
}

func (a *spaceAdapter) Descriptor() opcatalog.Descriptor { return a.descriptor }

func (a *spaceAdapter) Decode(targetRaw, argumentsRaw json.RawMessage) (Input, error) {
	var target spaceTarget
	if err := decodeClosed(targetRaw, &target, maxTargetBytes); err != nil || target.Kind != "space" || !hubclient.ValidNamespaceSegment(target.Owner) || !hubclient.ValidNamespaceSegment(target.Name) {
		return Input{}, errors.New("space target is invalid")
	}
	canonicalTarget, _ := canonical(target)
	arguments, err := a.decodeArguments(argumentsRaw)
	if err != nil {
		return Input{}, err
	}
	canonicalArguments, _ := canonical(arguments)
	return Input{Target: canonicalTarget, Arguments: canonicalArguments}, nil
}

func (a *spaceAdapter) decodeArguments(raw json.RawMessage) (any, error) {
	if strings.Contains(a.descriptor.Name, ".variable.") {
		return a.decodeVariableArguments(raw)
	}
	return a.decodeRuntimeArguments(raw)
}

func (a *spaceAdapter) decodeRuntimeArguments(raw json.RawMessage) (any, error) {
	switch a.descriptor.Name {
	case "space.restart":
		return decodeValidated(raw, maxArgumentsBytes, alwaysValid[restartArguments], "space restart arguments are invalid")
	case "space.hardware.update":
		return decodeValidated(raw, maxArgumentsBytes, validHardwareArguments, "space hardware arguments are invalid")
	case "space.sleep_time.update":
		return decodeValidated(raw, maxArgumentsBytes, validSleepTimeArguments, "space sleep-time arguments are invalid")
	case "space.pause", "space.dev_mode.enable", "space.dev_mode.disable":
		return decodeValidated(raw, maxArgumentsBytes, alwaysValid[emptyArguments], "space operation arguments must be empty")
	default:
		return nil, errors.New("space operation is not implemented")
	}
}

func (a *spaceAdapter) decodeVariableArguments(raw json.RawMessage) (any, error) {
	if a.descriptor.Name == "space.variable.set" {
		return decodeValidated(raw, maxArgumentsBytes, validVariableSetArguments, "space variable arguments are invalid")
	}
	return decodeValidated(raw, maxArgumentsBytes, validVariableDeleteArguments, "space variable arguments are invalid")
}

func alwaysValid[T any](T) bool { return true }

func validHardwareArguments(value hardwareArguments) bool {
	return hubclient.ValidHardwareFlavor(value.Flavor) && (value.SleepTimeSeconds == nil || *value.SleepTimeSeconds >= -1)
}

func validSleepTimeArguments(value sleepTimeArguments) bool { return value.Seconds >= -1 }

func validVariableSetArguments(value variableSetArguments) bool {
	return hubclient.ValidVariableKey(value.Key) && len(value.Value) <= 16*1024 && len(value.Description) <= 1000
}

func validVariableDeleteArguments(value variableDeleteArguments) bool {
	return hubclient.ValidVariableKey(value.Key)
}

func (a *spaceAdapter) Resolve(ctx context.Context, input Input) (Plan, error) {
	target, err := decodeSpaceTarget(input.Target)
	if err != nil {
		return Plan{}, err
	}
	observed, err := a.observe(ctx, target)
	if err != nil {
		return Plan{}, err
	}
	preconditions, _ := canonical(spacePreconditions{ObservedDigest: digest(observed)})
	presentation, request := a.presentationAndPolicy(target, input.Arguments)
	return Plan{Operation: a.descriptor.Name, OperationRevision: a.descriptor.OperationRevision, Target: input.Target,
		Arguments: input.Arguments, Preconditions: preconditions, Presentation: presentation, Policy: request}, nil
}

func (a *spaceAdapter) Authorize(plan Plan) hfpolicy.Request {
	return authorizeReconstructed(plan, reconstructPlan(plan.Target, plan.Arguments, decodeSpaceTarget, a.presentationAndPolicy))
}

func (a *spaceAdapter) Present(plan Plan) agentv1.Presentation {
	return presentReconstructed(plan, reconstructPlan(plan.Target, plan.Arguments, decodeSpaceTarget, a.presentationAndPolicy))
}

func (a *spaceAdapter) Execute(ctx context.Context, plan Plan) (Outcome, error) {
	target, expected, err := a.decodePlan(plan)
	if err != nil {
		return Outcome{}, err
	}
	observed, err := a.observe(ctx, target)
	if err != nil || digest(observed) != expected.ObservedDigest {
		if err != nil {
			return Outcome{}, err
		}
		return Outcome{}, errors.New("operation_precondition_failed")
	}
	err = a.executeUpdate(ctx, target.ref(), plan.Arguments)
	if err != nil {
		return Outcome{}, err
	}
	return Outcome{Proven: true, Result: json.RawMessage(`{"updated":true}`)}, nil
}

func (a *spaceAdapter) executeUpdate(ctx context.Context, space hubclient.SpaceRef, raw json.RawMessage) error {
	if strings.Contains(a.descriptor.Name, ".variable.") {
		return a.executeVariableUpdate(ctx, space, raw)
	}
	switch a.descriptor.Name {
	case "space.restart":
		var arguments restartArguments
		_ = decodeClosed(raw, &arguments, maxArgumentsBytes)
		_, err := a.client.RestartSpace(ctx, space, arguments.FactoryReboot)
		return err
	case "space.pause":
		_, err := a.client.PauseSpace(ctx, space)
		return err
	case "space.hardware.update":
		var arguments hardwareArguments
		_ = decodeClosed(raw, &arguments, maxArgumentsBytes)
		_, err := a.client.RequestSpaceHardware(ctx, space, arguments.Flavor, arguments.SleepTimeSeconds)
		return err
	case "space.sleep_time.update":
		var arguments sleepTimeArguments
		_ = decodeClosed(raw, &arguments, maxArgumentsBytes)
		_, err := a.client.SetSpaceSleepTime(ctx, space, arguments.Seconds)
		return err
	case "space.dev_mode.enable", "space.dev_mode.disable":
		_, err := a.client.SetSpaceDevMode(ctx, space, strings.HasSuffix(a.descriptor.Name, ".enable"))
		return err
	default:
		return errors.New("space operation is not implemented")
	}
}

func (a *spaceAdapter) executeVariableUpdate(ctx context.Context, space hubclient.SpaceRef, raw json.RawMessage) error {
	if a.descriptor.Name == "space.variable.set" {
		var arguments variableSetArguments
		_ = decodeClosed(raw, &arguments, maxArgumentsBytes)
		return a.client.SetSpaceVariable(ctx, space, arguments.Key, arguments.Value, arguments.Description)
	}
	var arguments variableDeleteArguments
	_ = decodeClosed(raw, &arguments, maxArgumentsBytes)
	return a.client.DeleteSpaceVariable(ctx, space, arguments.Key)
}

func (a *spaceAdapter) Reconcile(ctx context.Context, plan Plan) (Outcome, error) {
	target, _, err := a.decodePlan(plan)
	if err != nil {
		return Outcome{}, err
	}
	if a.descriptor.Name == "space.restart" {
		// A later read cannot distinguish this restart from an existing running state.
		return Outcome{Proven: false}, nil
	}
	proven, err := a.reconcileUpdate(ctx, target.ref(), plan.Arguments)
	return Outcome{Proven: proven, Result: json.RawMessage(`{"updated":true}`)}, err
}

func (a *spaceAdapter) reconcileUpdate(ctx context.Context, space hubclient.SpaceRef, raw json.RawMessage) (bool, error) {
	if strings.Contains(a.descriptor.Name, ".variable.") {
		return a.reconcileVariableUpdate(ctx, space, raw)
	}
	if a.descriptor.Name == "space.pause" {
		return a.reconcileSpacePause(ctx, space)
	}
	if strings.HasPrefix(a.descriptor.Name, "space.dev_mode.") {
		return a.reconcileSpaceDevMode(ctx, space)
	}
	return a.reconcileSpaceConfiguration(ctx, space, raw)
}

func (a *spaceAdapter) reconcileSpaceConfiguration(ctx context.Context, space hubclient.SpaceRef, raw json.RawMessage) (bool, error) {
	switch a.descriptor.Name {
	case "space.hardware.update":
		return a.reconcileSpaceHardware(ctx, space, raw)
	case "space.sleep_time.update":
		return a.reconcileSpaceSleepTime(ctx, space, raw)
	default:
		return false, errors.New("space operation is not implemented")
	}
}

func (a *spaceAdapter) reconcileSpacePause(ctx context.Context, space hubclient.SpaceRef) (bool, error) {
	runtime, err := a.client.SpaceRuntime(ctx, space)
	return err == nil && runtime.Stage == "PAUSED", err
}

func (a *spaceAdapter) reconcileSpaceHardware(ctx context.Context, space hubclient.SpaceRef, raw json.RawMessage) (bool, error) {
	var arguments hardwareArguments
	_ = decodeClosed(raw, &arguments, maxArgumentsBytes)
	runtime, err := a.client.SpaceRuntime(ctx, space)
	return err == nil && (runtime.RequestedHardware == arguments.Flavor || runtime.Hardware == arguments.Flavor), err
}

func (a *spaceAdapter) reconcileSpaceSleepTime(ctx context.Context, space hubclient.SpaceRef, raw json.RawMessage) (bool, error) {
	var arguments sleepTimeArguments
	_ = decodeClosed(raw, &arguments, maxArgumentsBytes)
	runtime, err := a.client.SpaceRuntime(ctx, space)
	return err == nil && runtime.SleepTimeSeconds != nil && *runtime.SleepTimeSeconds == arguments.Seconds, err
}

func (a *spaceAdapter) reconcileSpaceDevMode(ctx context.Context, space hubclient.SpaceRef) (bool, error) {
	runtime, err := a.client.SpaceRuntime(ctx, space)
	return err == nil && runtime.DevMode == strings.HasSuffix(a.descriptor.Name, ".enable"), err
}

func (a *spaceAdapter) reconcileVariableUpdate(ctx context.Context, space hubclient.SpaceRef, raw json.RawMessage) (bool, error) {
	variables, readErr := a.client.SpaceVariables(ctx, space)
	if readErr != nil {
		return false, readErr
	}
	if a.descriptor.Name == "space.variable.set" {
		var arguments variableSetArguments
		_ = decodeClosed(raw, &arguments, maxArgumentsBytes)
		value, found := variables[arguments.Key]
		return found && value.Value == arguments.Value && value.Description == arguments.Description, nil
	}
	var arguments variableDeleteArguments
	_ = decodeClosed(raw, &arguments, maxArgumentsBytes)
	_, found := variables[arguments.Key]
	return !found, nil
}

func (a *spaceAdapter) observe(ctx context.Context, target spaceTarget) (json.RawMessage, error) {
	if strings.Contains(a.descriptor.Name, ".variable.") {
		variables, err := a.client.SpaceVariables(ctx, target.ref())
		if err != nil {
			return nil, err
		}
		return canonical(variables)
	}
	runtime, err := a.client.SpaceRuntime(ctx, target.ref())
	if err != nil {
		return nil, err
	}
	return canonical(runtime)
}

func (a *spaceAdapter) decodePlan(plan Plan) (spaceTarget, spacePreconditions, error) {
	return decodePlanState(plan, decodeSpaceTarget, maxTargetBytes, validSpacePreconditions, "operation plan preconditions are invalid")
}

func validSpacePreconditions(value spacePreconditions) bool { return value.ObservedDigest != "" }

func (a *spaceAdapter) presentationAndPolicy(target spaceTarget, raw json.RawMessage) (agentv1.Presentation, hfpolicy.Request) {
	request := hfpolicy.Request{Operation: hfpolicy.Operation(a.descriptor.Name), Target: hfpolicy.Target{Kind: hfpolicy.TargetKind("space"), Owner: target.Owner, Name: target.Name}, Attrs: map[string]any{}}
	summary := strings.ReplaceAll(a.descriptor.Name, ".", " ") + " for " + target.Owner + "/" + target.Name
	switch a.descriptor.Name {
	case "space.restart":
		var arguments restartArguments
		_ = decodeClosed(raw, &arguments, maxArgumentsBytes)
		request.Attrs["factory_reboot"] = fmt.Sprint(arguments.FactoryReboot)
	case "space.hardware.update":
		var arguments hardwareArguments
		_ = decodeClosed(raw, &arguments, maxArgumentsBytes)
		request.Attrs["hardware"] = arguments.Flavor
	case "space.sleep_time.update":
		var arguments sleepTimeArguments
		_ = decodeClosed(raw, &arguments, maxArgumentsBytes)
		request.Attrs["sleep_time_seconds"] = int64(arguments.Seconds)
	case "space.variable.set":
		var arguments variableSetArguments
		_ = decodeClosed(raw, &arguments, maxArgumentsBytes)
		request.Attrs["key"] = arguments.Key
		summary = fmt.Sprintf("Set variable %s on %s/%s (value digest %s)", arguments.Key, target.Owner, target.Name, digest([]byte(arguments.Value))[:12])
	case "space.variable.delete":
		var arguments variableDeleteArguments
		_ = decodeClosed(raw, &arguments, maxArgumentsBytes)
		request.Attrs["key"] = arguments.Key
		summary = fmt.Sprintf("Delete variable %s from %s/%s", arguments.Key, target.Owner, target.Name)
	}
	return agentv1.Presentation{Title: strings.ReplaceAll(a.descriptor.Name, ".", " "), Summary: summary}, request
}

func decodeSpaceTarget(raw json.RawMessage) (spaceTarget, error) {
	var target spaceTarget
	if err := decodeClosed(raw, &target, maxTargetBytes); err != nil || target.Kind != "space" || !hubclient.ValidNamespaceSegment(target.Owner) || !hubclient.ValidNamespaceSegment(target.Name) {
		return spaceTarget{}, errors.New("space target is invalid")
	}
	return target, nil
}

func (target spaceTarget) ref() hubclient.SpaceRef {
	return hubclient.SpaceRef{Owner: target.Owner, Name: target.Name}
}
