package operations

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"slices"

	"github.com/osolmaz/brokerkit/agentv1"
	"github.com/osolmaz/brokerkit/brokers/huggingface/internal/hubclient"
	hfpolicy "github.com/osolmaz/brokerkit/brokers/huggingface/internal/policy"
)

func (a *sandboxAdapter) Resolve(ctx context.Context, input Input) (Plan, error) {
	target, err := a.decodeTarget(input.Target)
	if err != nil {
		return Plan{}, err
	}
	identity, err := a.client.WhoAmI(ctx)
	if err != nil {
		return Plan{}, err
	}
	preconditions := sandboxPreconditions{CredentialIdentity: identity.Name}
	switch a.descriptor.Name {
	case "sandbox.create":
		if _, _, err = a.materializeSandboxCreate(input.Arguments, false); err != nil {
			return Plan{}, err
		}
		preconditions.OperationID, err = newOperationMarker()
		if err != nil {
			return Plan{}, err
		}
		if target.Pool == "" {
			var existing []hubclient.SandboxState
			existing, err = a.client.ListSandboxesByOperation(ctx, target.Namespace, preconditions.OperationID)
			if err != nil || len(existing) != 0 {
				if err != nil {
					return Plan{}, err
				}
				return Plan{}, errors.New("sandbox operation marker already exists")
			}
			preconditions.ResourceAbsent = true
		} else {
			var hosts []hubclient.SandboxState
			hosts, err = a.client.ListSandboxPool(ctx, target.poolRef())
			if err != nil {
				return Plan{}, err
			}
			host := firstRunningSandboxHost(hosts)
			if host == nil {
				return Plan{}, errors.New("sandbox pool has no running host")
			}
			preconditions.Host = &host.Ref
			preconditions.PoolDigest = sandboxStatesDigest(hosts)
		}
	case "sandbox.pool.create":
		if _, err = a.materializeSandboxPoolCreate(input.Arguments); err != nil {
			return Plan{}, err
		}
		preconditions.OperationID, err = newOperationMarker()
		if err != nil {
			return Plan{}, err
		}
		var hosts []hubclient.SandboxState
		hosts, err = a.client.ListSandboxPool(ctx, target.poolRef())
		if err != nil {
			return Plan{}, err
		}
		if len(hosts) != 0 {
			return Plan{}, errors.New("sandbox pool already exists")
		}
		var arguments sandboxPoolCreatePublic
		arguments, _ = a.materializeSandboxPoolCreate(input.Arguments)
		preconditions.ResourceAbsent = true
		preconditions.CreatedHosts = arguments.WarmUp
	case "sandbox.pool.warm", "sandbox.pool.delete":
		var hosts []hubclient.SandboxState
		hosts, err = a.client.ListSandboxPool(ctx, target.poolRef())
		if err != nil {
			return Plan{}, err
		}
		if len(hosts) == 0 {
			return Plan{}, errors.New("sandbox pool has no active hosts")
		}
		preconditions.PoolDigest = sandboxStatesDigest(hosts)
		if a.descriptor.Name == "sandbox.pool.warm" {
			config, configErr := sandboxConfigFromStates(hosts)
			if configErr != nil {
				return Plan{}, configErr
			}
			var arguments sandboxPoolWarmArguments
			_ = decodeClosed(input.Arguments, &arguments, maxArgumentsBytes)
			if arguments.NumHosts < len(hosts) {
				return Plan{}, errors.New("sandbox pool already has more hosts than requested")
			}
			if arguments.NumHosts > config.MaxHosts {
				return Plan{}, errors.New("sandbox pool warm count exceeds its cost ceiling")
			}
			preconditions.OperationID, err = newOperationMarker()
			if err != nil {
				return Plan{}, err
			}
			preconditions.PoolConfig = &config
			preconditions.ExpectedHosts = arguments.NumHosts
			preconditions.CreatedHosts = max(0, arguments.NumHosts-len(hosts))
		}
	default:
		var state hubclient.SandboxState
		state, err = a.client.SandboxState(ctx, target.ref())
		if err != nil {
			return Plan{}, err
		}
		if a.descriptor.Name != "sandbox.delete" && state.Stage != "RUNNING" {
			return Plan{}, errors.New("sandbox is not running")
		}
		preconditions.StateDigest = sandboxStateDigest(state)
		if err = a.resolveSandboxResource(ctx, target, input.Arguments, &preconditions); err != nil {
			return Plan{}, err
		}
	}
	encoded, _ := canonical(preconditions)
	publicArguments := a.publicArguments(input.Arguments)
	presentation, request := a.presentationAndPolicy(target, publicArguments)
	return Plan{Operation: a.descriptor.Name, OperationRevision: a.descriptor.OperationRevision, Target: input.Target,
		Arguments: input.Arguments, Preconditions: encoded, Presentation: presentation, Policy: request}, nil
}

func (a *sandboxAdapter) Authorize(plan Plan) hfpolicy.Request {
	return authorizeReconstructed(plan, reconstructPlan(plan.Target, a.publicArguments(plan.Arguments), a.decodeTarget, a.presentationAndPolicy))
}

func (a *sandboxAdapter) Present(plan Plan) agentv1.Presentation {
	return presentReconstructed(plan, reconstructPlan(plan.Target, a.publicArguments(plan.Arguments), a.decodeTarget, a.presentationAndPolicy))
}

func (a *sandboxAdapter) Execute(ctx context.Context, plan Plan) (Outcome, error) {
	target, preconditions, err := a.decodeSandboxPlan(plan)
	if err != nil {
		return Outcome{}, err
	}
	if err = a.checkSandboxIdentity(ctx, preconditions); err != nil {
		return Outcome{}, err
	}
	switch a.descriptor.Name {
	case "sandbox.create":
		return a.executeSandboxCreate(ctx, target, plan.Arguments, preconditions)
	case "sandbox.pool.create":
		return a.executeSandboxPoolCreate(ctx, target, plan.Arguments, preconditions)
	case "sandbox.pool.warm":
		return a.executeSandboxPoolWarm(ctx, target, plan.Arguments, preconditions)
	case "sandbox.pool.delete":
		return a.executeSandboxPoolDelete(ctx, target, preconditions)
	default:
		if err = a.checkSandboxState(ctx, target, plan.Arguments, preconditions); err != nil {
			return Outcome{}, err
		}
		return a.executeSandboxAction(ctx, target, plan.Arguments, preconditions)
	}
}

func (a *sandboxAdapter) Reconcile(ctx context.Context, plan Plan) (Outcome, error) {
	target, preconditions, err := a.decodeSandboxPlan(plan)
	if err != nil {
		return Outcome{}, err
	}
	switch a.descriptor.Name {
	case "sandbox.create":
		if target.Pool != "" {
			return Outcome{Proven: false}, nil
		}
		states, listErr := a.client.ListSandboxesByOperation(ctx, target.Namespace, preconditions.OperationID)
		return Outcome{Proven: listErr == nil && len(states) == 1, Result: json.RawMessage(`{"created":true}`)}, listErr
	case "sandbox.pool.create", "sandbox.pool.warm":
		if preconditions.CreatedHosts == 0 {
			return Outcome{Proven: true, Result: json.RawMessage(`{"warmed":true}`)}, nil
		}
		states, listErr := a.client.ListSandboxesByOperation(ctx, target.Namespace, preconditions.OperationID)
		return Outcome{Proven: listErr == nil && len(states) == preconditions.CreatedHosts, Result: json.RawMessage(`{"warmed":true}`)}, listErr
	case "sandbox.pool.delete":
		hosts, listErr := a.client.ListSandboxPool(ctx, target.poolRef())
		return Outcome{Proven: listErr == nil && len(hosts) == 0, Result: json.RawMessage(`{"deleted":true}`)}, listErr
	case "sandbox.delete":
		state, stateErr := a.client.SandboxState(ctx, target.ref())
		if hubclient.IsNotFound(stateErr) {
			return Outcome{Proven: true, Result: json.RawMessage(`{"deleted":true}`)}, nil
		}
		if stateErr != nil {
			return Outcome{}, stateErr
		}
		return Outcome{Proven: terminalSandboxStage(state.Stage), Result: json.RawMessage(`{"deleted":true}`)}, nil
	case "sandbox.file.delete":
		var arguments sandboxFileDeleteArguments
		_ = decodeClosed(plan.Arguments, &arguments, maxArgumentsBytes)
		_, statErr := a.client.SandboxFileStat(ctx, target.ref(), arguments.Path)
		return Outcome{Proven: hubclient.IsNotFound(statErr), Result: json.RawMessage(`{"deleted":true}`)}, nonNotFound(statErr)
	case "sandbox.file.mkdir":
		var arguments sandboxFileMkdirArguments
		_ = decodeClosed(plan.Arguments, &arguments, maxArgumentsBytes)
		info, statErr := a.client.SandboxFileStat(ctx, target.ref(), arguments.Path)
		return Outcome{Proven: statErr == nil && info.Type == "dir", Result: json.RawMessage(`{"created":true}`)}, nonNotFound(statErr)
	case "sandbox.process.kill":
		var arguments sandboxProcessKillArguments
		_ = decodeClosed(plan.Arguments, &arguments, maxArgumentsBytes)
		processes, listErr := a.client.SandboxProcesses(ctx, target.ref())
		proven := listErr == nil && !slices.ContainsFunc(processes, func(process hubclient.SandboxProcess) bool {
			return process.PID == arguments.PID && process.Running
		})
		return Outcome{Proven: proven, Result: json.RawMessage(`{"killed":true}`)}, listErr
	default:
		return Outcome{Proven: false}, nil
	}
}

func (a *sandboxAdapter) Cleanup(plan Plan) error {
	if !a.descriptor.Sealed {
		return nil
	}
	arguments, err := decodeSealedArguments(plan.Arguments)
	if err != nil || arguments.SealedPayload == nil {
		return err
	}
	return a.store.Delete(*arguments.SealedPayload)
}

func (a *sandboxAdapter) resolveSandboxResource(ctx context.Context, target sandboxTarget, raw json.RawMessage, preconditions *sandboxPreconditions) error {
	switch a.descriptor.Name {
	case "sandbox.file.write":
		var arguments sandboxFileWriteArguments
		_ = decodeClosed(raw, &arguments, maxArgumentsBytes)
		info, err := a.client.SandboxFileStat(ctx, target.ref(), arguments.Path)
		if hubclient.IsNotFound(err) {
			preconditions.ResourceAbsent = true
			return nil
		}
		if err != nil {
			return err
		}
		preconditions.ResourceDigest = sandboxResourceDigest(info)
	case "sandbox.file.mkdir":
		var arguments sandboxFileMkdirArguments
		_ = decodeClosed(raw, &arguments, maxArgumentsBytes)
		_, err := a.client.SandboxFileStat(ctx, target.ref(), arguments.Path)
		if hubclient.IsNotFound(err) {
			preconditions.ResourceAbsent = true
			return nil
		}
		if err != nil {
			return err
		}
		return errors.New("sandbox directory already exists")
	case "sandbox.file.delete":
		var arguments sandboxFileDeleteArguments
		_ = decodeClosed(raw, &arguments, maxArgumentsBytes)
		info, err := a.client.SandboxFileStat(ctx, target.ref(), arguments.Path)
		if err != nil {
			return err
		}
		preconditions.ResourceDigest = sandboxResourceDigest(info)
	case "sandbox.process.kill":
		var arguments sandboxProcessKillArguments
		_ = decodeClosed(raw, &arguments, maxArgumentsBytes)
		processes, err := a.client.SandboxProcesses(ctx, target.ref())
		if err != nil {
			return err
		}
		index := slices.IndexFunc(processes, func(process hubclient.SandboxProcess) bool { return process.PID == arguments.PID && process.Running })
		if index < 0 {
			return errors.New("sandbox process is not running")
		}
		preconditions.ResourceDigest = sandboxResourceDigest(processes[index])
	}
	return nil
}

func (a *sandboxAdapter) decodeSandboxPlan(plan Plan) (sandboxTarget, sandboxPreconditions, error) {
	target, err := a.decodeTarget(plan.Target)
	if err != nil {
		return sandboxTarget{}, sandboxPreconditions{}, err
	}
	var preconditions sandboxPreconditions
	if err := decodeClosed(plan.Preconditions, &preconditions, maxArgumentsBytes); err != nil || preconditions.CredentialIdentity == "" {
		return sandboxTarget{}, sandboxPreconditions{}, errors.New("sandbox operation preconditions are invalid")
	}
	return target, preconditions, nil
}

func (a *sandboxAdapter) checkSandboxIdentity(ctx context.Context, expected sandboxPreconditions) error {
	identity, err := a.client.WhoAmI(ctx)
	if err != nil {
		return err
	}
	if identity.Name != expected.CredentialIdentity {
		return errors.New("operation_precondition_failed")
	}
	return nil
}

func (a *sandboxAdapter) checkSandboxState(ctx context.Context, target sandboxTarget, raw json.RawMessage, expected sandboxPreconditions) error {
	state, err := a.client.SandboxState(ctx, target.ref())
	if err != nil {
		return err
	}
	if sandboxStateDigest(state) != expected.StateDigest {
		return errors.New("operation_precondition_failed")
	}
	return a.checkSandboxResource(ctx, target, raw, expected)
}

func (a *sandboxAdapter) checkSandboxResource(ctx context.Context, target sandboxTarget, raw json.RawMessage, expected sandboxPreconditions) error {
	var path string
	switch a.descriptor.Name {
	case "sandbox.file.write":
		var arguments sandboxFileWriteArguments
		_ = decodeClosed(raw, &arguments, maxArgumentsBytes)
		path = arguments.Path
	case "sandbox.file.mkdir":
		var arguments sandboxFileMkdirArguments
		_ = decodeClosed(raw, &arguments, maxArgumentsBytes)
		path = arguments.Path
	case "sandbox.file.delete":
		var arguments sandboxFileDeleteArguments
		_ = decodeClosed(raw, &arguments, maxArgumentsBytes)
		path = arguments.Path
	case "sandbox.process.kill":
		var arguments sandboxProcessKillArguments
		_ = decodeClosed(raw, &arguments, maxArgumentsBytes)
		processes, err := a.client.SandboxProcesses(ctx, target.ref())
		if err != nil {
			return err
		}
		index := slices.IndexFunc(processes, func(process hubclient.SandboxProcess) bool {
			return process.PID == arguments.PID && process.Running
		})
		if index < 0 || sandboxResourceDigest(processes[index]) != expected.ResourceDigest {
			return errors.New("operation_precondition_failed")
		}
		return nil
	default:
		return nil
	}
	info, err := a.client.SandboxFileStat(ctx, target.ref(), path)
	if expected.ResourceAbsent && hubclient.IsNotFound(err) {
		return nil
	}
	if err != nil || expected.ResourceAbsent || sandboxResourceDigest(info) != expected.ResourceDigest {
		if err != nil {
			return err
		}
		return errors.New("operation_precondition_failed")
	}
	return nil
}

func (a *sandboxAdapter) publicArguments(raw json.RawMessage) json.RawMessage {
	if !a.descriptor.Sealed {
		return raw
	}
	arguments, err := decodeSealedArguments(raw)
	if err != nil {
		return nil
	}
	return arguments.Public
}

func sandboxStateDigest(state hubclient.SandboxState) string { return sandboxResourceDigest(state) }

func sandboxStatesDigest(states []hubclient.SandboxState) string {
	return sandboxResourceDigest(states)
}

func sandboxResourceDigest(value any) string {
	encoded, _ := canonical(value)
	return digest(encoded)
}

func firstRunningSandboxHost(states []hubclient.SandboxState) *hubclient.SandboxState {
	for index := range states {
		if states[index].Stage == "RUNNING" {
			return &states[index]
		}
	}
	return nil
}

func sandboxConfigFromStates(states []hubclient.SandboxState) (sandboxPoolConfig, error) {
	if len(states) == 0 {
		return sandboxPoolConfig{}, errors.New("sandbox pool has no hosts")
	}
	config := sandboxPoolConfig{Image: states[0].Image, Flavor: states[0].Flavor, SandboxesPerHost: states[0].Capacity,
		MaxHosts: states[0].MaxHosts, IdleTimeoutSeconds: states[0].IdleTimeoutSeconds}
	if config.MaxHosts == 0 {
		return sandboxPoolConfig{}, errors.New("sandbox pool has no bounded host ceiling")
	}
	for _, state := range states[1:] {
		candidate := sandboxPoolConfig{Image: state.Image, Flavor: state.Flavor, SandboxesPerHost: state.Capacity,
			MaxHosts: state.MaxHosts, IdleTimeoutSeconds: state.IdleTimeoutSeconds}
		if sandboxResourceDigest(candidate) != sandboxResourceDigest(config) {
			return sandboxPoolConfig{}, errors.New("sandbox pool hosts have inconsistent configuration")
		}
	}
	return config, nil
}

func terminalSandboxStage(stage string) bool {
	return stage == "COMPLETED" || stage == "CANCELED" || stage == "ERROR" || stage == "DELETED"
}

func nonNotFound(err error) error {
	if hubclient.IsNotFound(err) {
		return nil
	}
	return err
}

func mergeSandboxEnvironment(public, secret map[string]string) (map[string]string, error) {
	merged := make(map[string]string, len(public)+len(secret))
	for key, value := range public {
		merged[key] = value
	}
	for key, value := range secret {
		if _, exists := merged[key]; exists {
			return nil, errors.New("sealed sandbox environment overlaps public environment")
		}
		merged[key] = value
	}
	return merged, nil
}

func decodeSandboxContent(value string) []byte {
	decoded, _ := base64.StdEncoding.Strict().DecodeString(value)
	return decoded
}
