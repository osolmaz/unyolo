package operations

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"slices"

	"github.com/osolmaz/unyolo/agent/v1"
	"github.com/osolmaz/unyolo/brokers/huggingface/internal/hubclient"
	hfpolicy "github.com/osolmaz/unyolo/brokers/huggingface/internal/policy"
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
	if err := a.resolveSandboxPreconditions(ctx, target, input.Arguments, &preconditions); err != nil {
		return Plan{}, err
	}
	encoded, _ := canonical(preconditions)
	publicArguments := a.publicArguments(input.Arguments)
	presentation, request := a.presentationAndPolicy(target, publicArguments)
	return Plan{Operation: a.descriptor.Name, OperationRevision: a.descriptor.OperationRevision, Target: input.Target,
		Arguments: input.Arguments, Preconditions: encoded, Presentation: presentation, Policy: request}, nil
}

func (a *sandboxAdapter) resolveSandboxPreconditions(ctx context.Context, target sandboxTarget, arguments json.RawMessage, preconditions *sandboxPreconditions) error {
	switch a.descriptor.Name {
	case "sandbox.create":
		return a.resolveSandboxCreate(ctx, target, arguments, preconditions)
	case "sandbox.pool.create":
		return a.resolveSandboxPoolCreate(ctx, target, arguments, preconditions)
	case "sandbox.pool.warm", "sandbox.pool.delete":
		return a.resolveSandboxPoolOperation(ctx, target, arguments, preconditions)
	default:
		return a.resolveExistingSandbox(ctx, target, arguments, preconditions)
	}
}

func (a *sandboxAdapter) resolveSandboxCreate(ctx context.Context, target sandboxTarget, raw json.RawMessage, preconditions *sandboxPreconditions) error {
	if _, err := decodeSandboxCreatePublic(raw); err != nil {
		return err
	}
	operationID, err := newOperationMarker()
	if err != nil {
		return err
	}
	preconditions.OperationID = operationID
	if target.Pool == "" {
		return a.resolveDedicatedSandboxCreate(ctx, target, preconditions)
	}
	return a.resolvePooledSandboxCreate(ctx, target, preconditions)
}

func (a *sandboxAdapter) resolveDedicatedSandboxCreate(ctx context.Context, target sandboxTarget, preconditions *sandboxPreconditions) error {
	existing, err := a.client.ListSandboxesByOperation(ctx, target.Namespace, preconditions.OperationID)
	if err != nil {
		return err
	}
	if len(existing) != 0 {
		return errors.New("sandbox operation marker already exists")
	}
	preconditions.ResourceAbsent = true
	return nil
}

func (a *sandboxAdapter) resolvePooledSandboxCreate(ctx context.Context, target sandboxTarget, preconditions *sandboxPreconditions) error {
	hosts, err := a.client.ListSandboxPool(ctx, target.poolRef())
	if err != nil {
		return err
	}
	host := firstRunningSandboxHost(hosts)
	if host == nil {
		return errors.New("sandbox pool has no running host")
	}
	preconditions.Host = &host.Ref
	preconditions.PoolDigest = sandboxStatesDigest(hosts)
	return nil
}

func (a *sandboxAdapter) resolveSandboxPoolCreate(ctx context.Context, target sandboxTarget, raw json.RawMessage, preconditions *sandboxPreconditions) error {
	arguments, err := a.materializeSandboxPoolCreate(raw)
	if err != nil {
		return err
	}
	operationID, err := newOperationMarker()
	if err != nil {
		return err
	}
	hosts, err := a.client.ListSandboxPool(ctx, target.poolRef())
	if err != nil {
		return err
	}
	if len(hosts) != 0 {
		return errors.New("sandbox pool already exists")
	}
	preconditions.OperationID = operationID
	preconditions.ResourceAbsent = true
	preconditions.CreatedHosts = arguments.WarmUp
	return nil
}

func (a *sandboxAdapter) resolveSandboxPoolOperation(ctx context.Context, target sandboxTarget, raw json.RawMessage, preconditions *sandboxPreconditions) error {
	hosts, err := a.client.ListSandboxPool(ctx, target.poolRef())
	if err != nil {
		return err
	}
	if len(hosts) == 0 {
		return errors.New("sandbox pool has no active hosts")
	}
	preconditions.PoolDigest = sandboxStatesDigest(hosts)
	if a.descriptor.Name != "sandbox.pool.warm" {
		return nil
	}
	return resolveSandboxPoolWarm(raw, hosts, preconditions)
}

func resolveSandboxPoolWarm(raw json.RawMessage, hosts []hubclient.SandboxState, preconditions *sandboxPreconditions) error {
	config, err := sandboxConfigFromStates(hosts)
	if err != nil {
		return err
	}
	var arguments sandboxPoolWarmArguments
	_ = decodeClosed(raw, &arguments, maxArgumentsBytes)
	if arguments.NumHosts < len(hosts) {
		return errors.New("sandbox pool already has more hosts than requested")
	}
	if arguments.NumHosts > config.MaxHosts {
		return errors.New("sandbox pool warm count exceeds its cost ceiling")
	}
	operationID, err := newOperationMarker()
	if err != nil {
		return err
	}
	preconditions.OperationID = operationID
	preconditions.PoolConfig = &config
	preconditions.ExpectedHosts = arguments.NumHosts
	preconditions.CreatedHosts = max(0, arguments.NumHosts-len(hosts))
	return nil
}

func (a *sandboxAdapter) resolveExistingSandbox(ctx context.Context, target sandboxTarget, raw json.RawMessage, preconditions *sandboxPreconditions) error {
	state, err := a.client.SandboxState(ctx, target.ref())
	if err != nil {
		return err
	}
	if a.descriptor.Name != "sandbox.delete" && state.Stage != "RUNNING" {
		return errors.New("sandbox is not running")
	}
	preconditions.StateDigest = sandboxStateDigest(state)
	return a.resolveSandboxResource(ctx, target, raw, preconditions)
}

func decodeSandboxCreatePublic(raw json.RawMessage) (sandboxCreatePublic, error) {
	arguments, err := decodeSealedArguments(raw)
	if err != nil {
		return sandboxCreatePublic{}, err
	}
	var public sandboxCreatePublic
	err = decodeClosed(arguments.Public, &public, maxArgumentsBytes)
	return public, err
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
	execute, found := sandboxExecutors[a.descriptor.Name]
	if !found {
		return a.executeExistingSandboxAction(ctx, target, plan.Arguments, preconditions)
	}
	return execute(a, ctx, target, plan.Arguments, preconditions)
}

var sandboxExecutors = map[string]func(*sandboxAdapter, context.Context, sandboxTarget, json.RawMessage, sandboxPreconditions) (Outcome, error){
	"sandbox.create":      executeSandboxCreateOperation,
	"sandbox.pool.create": executeSandboxPoolCreateOperation,
	"sandbox.pool.warm":   executeSandboxPoolWarmOperation,
	"sandbox.pool.delete": executeSandboxPoolDeleteOperation,
}

func executeSandboxCreateOperation(a *sandboxAdapter, ctx context.Context, target sandboxTarget, raw json.RawMessage, expected sandboxPreconditions) (Outcome, error) {
	return a.executeSandboxCreate(ctx, target, raw, expected)
}

func executeSandboxPoolCreateOperation(a *sandboxAdapter, ctx context.Context, target sandboxTarget, raw json.RawMessage, expected sandboxPreconditions) (Outcome, error) {
	return a.executeSandboxPoolCreate(ctx, target, raw, expected)
}

func executeSandboxPoolWarmOperation(a *sandboxAdapter, ctx context.Context, target sandboxTarget, raw json.RawMessage, expected sandboxPreconditions) (Outcome, error) {
	return a.executeSandboxPoolWarm(ctx, target, raw, expected)
}

func executeSandboxPoolDeleteOperation(a *sandboxAdapter, ctx context.Context, target sandboxTarget, _ json.RawMessage, expected sandboxPreconditions) (Outcome, error) {
	return a.executeSandboxPoolDelete(ctx, target, expected)
}

func (a *sandboxAdapter) executeExistingSandboxAction(ctx context.Context, target sandboxTarget, arguments json.RawMessage, preconditions sandboxPreconditions) (Outcome, error) {
	if err := a.checkSandboxState(ctx, target, arguments, preconditions); err != nil {
		return Outcome{}, err
	}
	return a.executeSandboxAction(ctx, target, arguments, preconditions)
}

func (a *sandboxAdapter) Reconcile(ctx context.Context, plan Plan) (Outcome, error) {
	target, preconditions, err := a.decodeSandboxPlan(plan)
	if err != nil {
		return Outcome{}, err
	}
	reconcile, found := sandboxReconcilers[a.descriptor.Name]
	if !found {
		return Outcome{Proven: false}, nil
	}
	return reconcile(a, ctx, target, plan.Arguments, preconditions)
}

var sandboxReconcilers = map[string]func(*sandboxAdapter, context.Context, sandboxTarget, json.RawMessage, sandboxPreconditions) (Outcome, error){
	"sandbox.create":       reconcileSandboxCreate,
	"sandbox.pool.create":  reconcileSandboxPoolOperation,
	"sandbox.pool.warm":    reconcileSandboxPoolOperation,
	"sandbox.pool.delete":  reconcileSandboxPoolDelete,
	"sandbox.delete":       reconcileSandboxDelete,
	"sandbox.file.delete":  reconcileSandboxFileDelete,
	"sandbox.file.mkdir":   reconcileSandboxFileMkdir,
	"sandbox.process.kill": reconcileSandboxProcessKill,
}

func reconcileSandboxCreate(a *sandboxAdapter, ctx context.Context, target sandboxTarget, _ json.RawMessage, preconditions sandboxPreconditions) (Outcome, error) {
	if target.Pool != "" {
		return Outcome{Proven: false}, nil
	}
	states, err := a.client.ListSandboxesByOperation(ctx, target.Namespace, preconditions.OperationID)
	return Outcome{Proven: err == nil && len(states) == 1, Result: json.RawMessage(`{"created":true}`)}, err
}

func reconcileSandboxPoolOperation(a *sandboxAdapter, ctx context.Context, target sandboxTarget, _ json.RawMessage, preconditions sandboxPreconditions) (Outcome, error) {
	return a.reconcileSandboxPool(ctx, target, preconditions)
}

func reconcileSandboxPoolDelete(a *sandboxAdapter, ctx context.Context, target sandboxTarget, _ json.RawMessage, _ sandboxPreconditions) (Outcome, error) {
	hosts, err := a.client.ListSandboxPool(ctx, target.poolRef())
	return Outcome{Proven: err == nil && len(hosts) == 0, Result: json.RawMessage(`{"deleted":true}`)}, err
}

func reconcileSandboxDelete(a *sandboxAdapter, ctx context.Context, target sandboxTarget, _ json.RawMessage, _ sandboxPreconditions) (Outcome, error) {
	state, err := a.client.SandboxState(ctx, target.ref())
	if hubclient.IsNotFound(err) {
		return Outcome{Proven: true, Result: json.RawMessage(`{"deleted":true}`)}, nil
	}
	if err != nil {
		return Outcome{}, err
	}
	return Outcome{Proven: terminalSandboxStage(state.Stage), Result: json.RawMessage(`{"deleted":true}`)}, nil
}

func reconcileSandboxFileDelete(a *sandboxAdapter, ctx context.Context, target sandboxTarget, raw json.RawMessage, _ sandboxPreconditions) (Outcome, error) {
	var arguments sandboxFileDeleteArguments
	_ = decodeClosed(raw, &arguments, maxArgumentsBytes)
	_, err := a.client.SandboxFileStat(ctx, target.ref(), arguments.Path)
	return Outcome{Proven: hubclient.IsNotFound(err), Result: json.RawMessage(`{"deleted":true}`)}, nonNotFound(err)
}

func reconcileSandboxFileMkdir(a *sandboxAdapter, ctx context.Context, target sandboxTarget, raw json.RawMessage, _ sandboxPreconditions) (Outcome, error) {
	var arguments sandboxFileMkdirArguments
	_ = decodeClosed(raw, &arguments, maxArgumentsBytes)
	info, err := a.client.SandboxFileStat(ctx, target.ref(), arguments.Path)
	return Outcome{Proven: err == nil && info.Type == "dir", Result: json.RawMessage(`{"created":true}`)}, nonNotFound(err)
}

func reconcileSandboxProcessKill(a *sandboxAdapter, ctx context.Context, target sandboxTarget, raw json.RawMessage, _ sandboxPreconditions) (Outcome, error) {
	var arguments sandboxProcessKillArguments
	_ = decodeClosed(raw, &arguments, maxArgumentsBytes)
	processes, err := a.client.SandboxProcesses(ctx, target.ref())
	proven := err == nil && !slices.ContainsFunc(processes, func(process hubclient.SandboxProcess) bool {
		return process.PID == arguments.PID && process.Running
	})
	return Outcome{Proven: proven, Result: json.RawMessage(`{"killed":true}`)}, err
}

func (a *sandboxAdapter) reconcileSandboxPool(ctx context.Context, target sandboxTarget, preconditions sandboxPreconditions) (Outcome, error) {
	if preconditions.CreatedHosts > 0 {
		states, err := a.client.ListSandboxesByOperation(ctx, target.Namespace, preconditions.OperationID)
		return Outcome{Proven: err == nil && len(states) == preconditions.CreatedHosts, Result: json.RawMessage(`{"warmed":true}`)}, err
	}
	hosts, err := a.client.ListSandboxPool(ctx, target.poolRef())
	proven := err == nil && len(hosts) == preconditions.ExpectedHosts && preconditions.PoolDigest != "" &&
		sandboxStatesDigest(hosts) == preconditions.PoolDigest
	return Outcome{Proven: proven, Result: json.RawMessage(`{"warmed":true}`)}, err
}

func (a *sandboxAdapter) Cleanup(plan Plan) error {
	if !a.descriptor.Sealed {
		return nil
	}
	return cleanupSealedPayload(a.store, plan.Arguments)
}

func (a *sandboxAdapter) resolveSandboxResource(ctx context.Context, target sandboxTarget, raw json.RawMessage, preconditions *sandboxPreconditions) error {
	return dispatchSandboxResource(a.descriptor.Name, sandboxResourceResolvers, a, ctx, target, raw, preconditions)
}

var sandboxResourceResolvers = map[string]func(*sandboxAdapter, context.Context, sandboxTarget, json.RawMessage, *sandboxPreconditions) error{
	"sandbox.file.write":   resolveSandboxFileWrite,
	"sandbox.file.mkdir":   resolveSandboxFileMkdir,
	"sandbox.file.delete":  resolveSandboxFileDelete,
	"sandbox.process.kill": resolveSandboxProcessKill,
}

func resolveSandboxFileWrite(a *sandboxAdapter, ctx context.Context, target sandboxTarget, raw json.RawMessage, preconditions *sandboxPreconditions) error {
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
	preconditions.ResourceDigest = digestValue(info)
	return nil
}

func resolveSandboxFileMkdir(a *sandboxAdapter, ctx context.Context, target sandboxTarget, raw json.RawMessage, preconditions *sandboxPreconditions) error {
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
}

func resolveSandboxFileDelete(a *sandboxAdapter, ctx context.Context, target sandboxTarget, raw json.RawMessage, preconditions *sandboxPreconditions) error {
	var arguments sandboxFileDeleteArguments
	_ = decodeClosed(raw, &arguments, maxArgumentsBytes)
	info, err := a.client.SandboxFileStat(ctx, target.ref(), arguments.Path)
	if err != nil {
		return err
	}
	preconditions.ResourceDigest = digestValue(info)
	return nil
}

func resolveSandboxProcessKill(a *sandboxAdapter, ctx context.Context, target sandboxTarget, raw json.RawMessage, preconditions *sandboxPreconditions) error {
	process, err := a.runningSandboxProcess(ctx, target, raw)
	if err != nil {
		return err
	}
	preconditions.ResourceDigest = digestValue(process)
	return nil
}

func (a *sandboxAdapter) decodeSandboxPlan(plan Plan) (sandboxTarget, sandboxPreconditions, error) {
	return decodePlanState(plan, a.decodeTarget, maxArgumentsBytes,
		func(value sandboxPreconditions) bool { return value.CredentialIdentity != "" },
		"sandbox operation preconditions are invalid")
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
	return dispatchSandboxResource(a.descriptor.Name, sandboxResourceCheckers, a, ctx, target, raw, expected)
}

func dispatchSandboxResource[T any](name string,
	handlers map[string]func(*sandboxAdapter, context.Context, sandboxTarget, json.RawMessage, T) error,
	adapter *sandboxAdapter, ctx context.Context, target sandboxTarget, raw json.RawMessage, state T) error {
	handle, found := handlers[name]
	if !found {
		return nil
	}
	return handle(adapter, ctx, target, raw, state)
}

var sandboxResourceCheckers = map[string]func(*sandboxAdapter, context.Context, sandboxTarget, json.RawMessage, sandboxPreconditions) error{
	"sandbox.file.write":   checkSandboxFileResource[sandboxFileWriteArguments],
	"sandbox.file.mkdir":   checkSandboxFileResource[sandboxFileMkdirArguments],
	"sandbox.file.delete":  checkSandboxFileResource[sandboxFileDeleteArguments],
	"sandbox.process.kill": checkSandboxProcessResource,
}

type sandboxPathArgument interface {
	sandboxPath() string
}

func (value sandboxFileWriteArguments) sandboxPath() string  { return value.Path }
func (value sandboxFileMkdirArguments) sandboxPath() string  { return value.Path }
func (value sandboxFileDeleteArguments) sandboxPath() string { return value.Path }

func checkSandboxFileResource[T sandboxPathArgument](a *sandboxAdapter, ctx context.Context, target sandboxTarget, raw json.RawMessage, expected sandboxPreconditions) error {
	var arguments T
	_ = decodeClosed(raw, &arguments, maxArgumentsBytes)
	return a.checkSandboxFileStat(ctx, target, arguments.sandboxPath(), expected)
}

func (a *sandboxAdapter) checkSandboxFileStat(ctx context.Context, target sandboxTarget, path string, expected sandboxPreconditions) error {
	info, err := a.client.SandboxFileStat(ctx, target.ref(), path)
	if sandboxFileStatMatches(info, err, expected) {
		return nil
	}
	if err != nil {
		return err
	}
	return errors.New("operation_precondition_failed")
}

func sandboxFileStatMatches(info hubclient.SandboxFileInfo, err error, expected sandboxPreconditions) bool {
	if expected.ResourceAbsent {
		return hubclient.IsNotFound(err)
	}
	return err == nil && digestValue(info) == expected.ResourceDigest
}

func checkSandboxProcessResource(a *sandboxAdapter, ctx context.Context, target sandboxTarget, raw json.RawMessage, expected sandboxPreconditions) error {
	process, err := a.runningSandboxProcess(ctx, target, raw)
	if err != nil {
		return err
	}
	if digestValue(process) != expected.ResourceDigest {
		return errors.New("operation_precondition_failed")
	}
	return nil
}

func (a *sandboxAdapter) runningSandboxProcess(ctx context.Context, target sandboxTarget, raw json.RawMessage) (hubclient.SandboxProcess, error) {
	var arguments sandboxProcessKillArguments
	_ = decodeClosed(raw, &arguments, maxArgumentsBytes)
	processes, err := a.client.SandboxProcesses(ctx, target.ref())
	if err != nil {
		return hubclient.SandboxProcess{}, err
	}
	index := slices.IndexFunc(processes, func(process hubclient.SandboxProcess) bool {
		return process.PID == arguments.PID && process.Running
	})
	if index < 0 {
		return hubclient.SandboxProcess{}, errors.New("sandbox process is not running")
	}
	return processes[index], nil
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

func sandboxStateDigest(state hubclient.SandboxState) string { return digestValue(state) }

func sandboxStatesDigest(states []hubclient.SandboxState) string {
	return digestValue(states)
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
		if digestValue(candidate) != digestValue(config) {
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
	if err := validateDistinctSandboxEnvironment(public, secret); err != nil {
		return nil, err
	}
	merged := make(map[string]string, len(public)+len(secret))
	for key, value := range public {
		merged[key] = value
	}
	for key, value := range secret {
		merged[key] = value
	}
	return merged, nil
}

func validateDistinctSandboxEnvironment(public, secret map[string]string) error {
	for key := range secret {
		if _, exists := public[key]; exists {
			return errors.New("sealed sandbox environment overlaps public environment")
		}
	}
	return nil
}

func decodeSandboxContent(value string) []byte {
	decoded, _ := base64.StdEncoding.Strict().DecodeString(value)
	return decoded
}
