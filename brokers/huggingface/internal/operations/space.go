package operations

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	"github.com/osolmaz/brokerkit/agentv1"
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
		return nil, errors.New("Hugging Face Space client is required")
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
		return Input{}, errors.New("Space target is invalid")
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
	switch a.descriptor.Name {
	case "space.restart":
		var value restartArguments
		if err := decodeClosed(raw, &value, maxArgumentsBytes); err != nil {
			return nil, errors.New("Space restart arguments are invalid")
		}
		return value, nil
	case "space.hardware.update":
		var value hardwareArguments
		if err := decodeClosed(raw, &value, maxArgumentsBytes); err != nil || !hubclient.ValidHardwareFlavor(value.Flavor) || value.SleepTimeSeconds != nil && *value.SleepTimeSeconds < -1 {
			return nil, errors.New("Space hardware arguments are invalid")
		}
		return value, nil
	case "space.sleep_time.update":
		var value sleepTimeArguments
		if err := decodeClosed(raw, &value, maxArgumentsBytes); err != nil || value.Seconds < -1 {
			return nil, errors.New("Space sleep-time arguments are invalid")
		}
		return value, nil
	case "space.variable.set":
		var value variableSetArguments
		if err := decodeClosed(raw, &value, maxArgumentsBytes); err != nil || !hubclient.ValidVariableKey(value.Key) || len(value.Value) > 16*1024 || len(value.Description) > 1000 {
			return nil, errors.New("Space variable arguments are invalid")
		}
		return value, nil
	case "space.variable.delete":
		var value variableDeleteArguments
		if err := decodeClosed(raw, &value, maxArgumentsBytes); err != nil || !hubclient.ValidVariableKey(value.Key) {
			return nil, errors.New("Space variable arguments are invalid")
		}
		return value, nil
	case "space.pause", "space.dev_mode.enable", "space.dev_mode.disable":
		var value emptyArguments
		if err := decodeClosed(raw, &value, maxArgumentsBytes); err != nil {
			return nil, errors.New("Space operation arguments must be empty")
		}
		return value, nil
	default:
		return nil, errors.New("Space operation is not implemented")
	}
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
	if plan.Policy.Operation != "" {
		return plan.Policy
	}
	target, err := decodeSpaceTarget(plan.Target)
	if err != nil {
		return hfpolicy.Request{}
	}
	_, request := a.presentationAndPolicy(target, plan.Arguments)
	return request
}

func (a *spaceAdapter) Present(plan Plan) agentv1.Presentation {
	if plan.Presentation.Title != "" {
		return plan.Presentation
	}
	target, err := decodeSpaceTarget(plan.Target)
	if err != nil {
		return agentv1.Presentation{}
	}
	presentation, _ := a.presentationAndPolicy(target, plan.Arguments)
	return presentation
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
	space := target.ref()
	switch a.descriptor.Name {
	case "space.restart":
		var arguments restartArguments
		_ = decodeClosed(plan.Arguments, &arguments, maxArgumentsBytes)
		_, err = a.client.RestartSpace(ctx, space, arguments.FactoryReboot)
	case "space.pause":
		_, err = a.client.PauseSpace(ctx, space)
	case "space.hardware.update":
		var arguments hardwareArguments
		_ = decodeClosed(plan.Arguments, &arguments, maxArgumentsBytes)
		_, err = a.client.RequestSpaceHardware(ctx, space, arguments.Flavor, arguments.SleepTimeSeconds)
	case "space.sleep_time.update":
		var arguments sleepTimeArguments
		_ = decodeClosed(plan.Arguments, &arguments, maxArgumentsBytes)
		_, err = a.client.SetSpaceSleepTime(ctx, space, arguments.Seconds)
	case "space.dev_mode.enable", "space.dev_mode.disable":
		_, err = a.client.SetSpaceDevMode(ctx, space, strings.HasSuffix(a.descriptor.Name, ".enable"))
	case "space.variable.set":
		var arguments variableSetArguments
		_ = decodeClosed(plan.Arguments, &arguments, maxArgumentsBytes)
		err = a.client.SetSpaceVariable(ctx, space, arguments.Key, arguments.Value, arguments.Description)
	case "space.variable.delete":
		var arguments variableDeleteArguments
		_ = decodeClosed(plan.Arguments, &arguments, maxArgumentsBytes)
		err = a.client.DeleteSpaceVariable(ctx, space, arguments.Key)
	}
	if err != nil {
		return Outcome{}, err
	}
	return Outcome{Result: json.RawMessage(`{"updated":true}`)}, nil
}

func (a *spaceAdapter) Reconcile(ctx context.Context, plan Plan) (Outcome, error) {
	target, _, err := a.decodePlan(plan)
	if err != nil {
		return Outcome{}, err
	}
	space := target.ref()
	proven := false
	switch a.descriptor.Name {
	case "space.restart":
		runtime, readErr := a.client.SpaceRuntime(ctx, space)
		err, proven = readErr, readErr == nil && runtime.Stage != "PAUSED"
	case "space.pause":
		runtime, readErr := a.client.SpaceRuntime(ctx, space)
		err, proven = readErr, readErr == nil && runtime.Stage == "PAUSED"
	case "space.hardware.update":
		var arguments hardwareArguments
		_ = decodeClosed(plan.Arguments, &arguments, maxArgumentsBytes)
		runtime, readErr := a.client.SpaceRuntime(ctx, space)
		err, proven = readErr, readErr == nil && (runtime.RequestedHardware == arguments.Flavor || runtime.Hardware == arguments.Flavor)
	case "space.sleep_time.update":
		var arguments sleepTimeArguments
		_ = decodeClosed(plan.Arguments, &arguments, maxArgumentsBytes)
		runtime, readErr := a.client.SpaceRuntime(ctx, space)
		err, proven = readErr, readErr == nil && runtime.SleepTimeSeconds != nil && *runtime.SleepTimeSeconds == arguments.Seconds
	case "space.dev_mode.enable", "space.dev_mode.disable":
		runtime, readErr := a.client.SpaceRuntime(ctx, space)
		want := strings.HasSuffix(a.descriptor.Name, ".enable")
		err, proven = readErr, readErr == nil && runtime.DevMode == want
	case "space.variable.set":
		var arguments variableSetArguments
		_ = decodeClosed(plan.Arguments, &arguments, maxArgumentsBytes)
		variables, readErr := a.client.SpaceVariables(ctx, space)
		value, found := variables[arguments.Key]
		err, proven = readErr, readErr == nil && found && value.Value == arguments.Value && value.Description == arguments.Description
	case "space.variable.delete":
		var arguments variableDeleteArguments
		_ = decodeClosed(plan.Arguments, &arguments, maxArgumentsBytes)
		variables, readErr := a.client.SpaceVariables(ctx, space)
		_, found := variables[arguments.Key]
		err, proven = readErr, readErr == nil && !found
	}
	return Outcome{Proven: proven, Result: json.RawMessage(`{"updated":true}`)}, err
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
	target, err := decodeSpaceTarget(plan.Target)
	if err != nil {
		return spaceTarget{}, spacePreconditions{}, err
	}
	var preconditions spacePreconditions
	if err := decodeClosed(plan.Preconditions, &preconditions, maxTargetBytes); err != nil || preconditions.ObservedDigest == "" {
		return spaceTarget{}, spacePreconditions{}, errors.New("operation plan preconditions are invalid")
	}
	return target, preconditions, nil
}

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
		return spaceTarget{}, errors.New("Space target is invalid")
	}
	return target, nil
}

func (target spaceTarget) ref() hubclient.SpaceRef {
	return hubclient.SpaceRef{Owner: target.Owner, Name: target.Name}
}
