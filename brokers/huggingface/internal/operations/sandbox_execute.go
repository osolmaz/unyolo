package operations

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/osolmaz/brokerkit/brokers/huggingface/internal/hubclient"
	"github.com/osolmaz/brokerkit/sealedstore"
)

func (a *sandboxAdapter) executeSandboxCreate(ctx context.Context, target sandboxTarget, raw json.RawMessage, expected sandboxPreconditions) (Outcome, error) {
	public, secret, err := a.materializeValidatedSandboxCreate(raw)
	if err != nil {
		return Outcome{}, err
	}
	if target.Pool == "" {
		return a.executeDedicatedSandboxCreate(ctx, target, public, secret, expected)
	}
	return a.executePooledSandboxCreate(ctx, target, public, secret, expected)
}

func (a *sandboxAdapter) executeDedicatedSandboxCreate(ctx context.Context, target sandboxTarget, public sandboxCreatePublic, secret sandboxCreateSecret, expected sandboxPreconditions) (Outcome, error) {
	if err := a.checkDedicatedSandboxCreate(ctx, expected, target.Namespace); err != nil {
		return Outcome{}, err
	}
	state, err := a.client.CreateSandbox(ctx, hubclient.SandboxCreateSpec{Namespace: target.Namespace, Name: target.Name,
		OperationID: expected.OperationID, Image: public.Image, Flavor: public.Flavor, IdleTimeoutSeconds: public.IdleTimeoutSeconds,
		Environment: public.Environment, Secrets: secret.Secrets, Volumes: public.hubVolumes()})
	if err != nil {
		return Outcome{}, err
	}
	result, _ := canonical(map[string]any{"sandbox_id": state.Ref.ID(), "stage": state.Stage})
	return Outcome{Proven: true, Result: result}, nil
}

func (a *sandboxAdapter) checkDedicatedSandboxCreate(ctx context.Context, expected sandboxPreconditions, namespace string) error {
	existing, err := a.client.ListSandboxesByOperation(ctx, namespace, expected.OperationID)
	if err != nil {
		return err
	}
	if !expected.ResourceAbsent || len(existing) != 0 {
		return errors.New("operation_precondition_failed")
	}
	return nil
}

func (a *sandboxAdapter) executePooledSandboxCreate(ctx context.Context, target sandboxTarget, public sandboxCreatePublic, secret sandboxCreateSecret, expected sandboxPreconditions) (Outcome, error) {
	if err := a.checkSandboxPool(ctx, target.poolRef(), expected.PoolDigest); err != nil {
		return Outcome{}, err
	}
	if expected.Host == nil {
		return Outcome{}, errors.New("sandbox pool host precondition is missing")
	}
	environment, err := mergeSandboxEnvironment(public.Environment, secret.Secrets)
	if err != nil {
		return Outcome{}, err
	}
	ref, err := a.client.CreateSandboxInPool(ctx, *expected.Host, environment, public.IdleTimeoutSeconds)
	if err != nil {
		return Outcome{}, err
	}
	result, _ := canonical(map[string]any{"sandbox_id": ref.ID(), "host_id": ref.JobID})
	return Outcome{Proven: true, Result: result}, nil
}

func (a *sandboxAdapter) materializeValidatedSandboxCreate(raw json.RawMessage) (sandboxCreatePublic, sandboxCreateSecret, error) {
	public, secret, err := a.materializeSandboxCreate(raw)
	if err != nil {
		return sandboxCreatePublic{}, sandboxCreateSecret{}, err
	}
	if err := validateDistinctSandboxEnvironment(public.Environment, secret.Secrets); err != nil {
		return sandboxCreatePublic{}, sandboxCreateSecret{}, err
	}
	return public, secret, nil
}

func (a *sandboxAdapter) executeSandboxPoolCreate(ctx context.Context, target sandboxTarget, raw json.RawMessage, expected sandboxPreconditions) (Outcome, error) {
	if err := a.checkSandboxPoolCreate(ctx, target, expected); err != nil {
		return Outcome{}, err
	}
	arguments, err := a.materializeSandboxPoolCreate(raw)
	if err != nil {
		return Outcome{}, err
	}
	if expected.CreatedHosts != arguments.WarmUp {
		return Outcome{}, errors.New("operation_precondition_failed")
	}
	config := hubclient.SandboxPoolSpec{Ref: target.poolRef(), OperationID: expected.OperationID, Image: arguments.Image,
		Flavor: arguments.Flavor, SandboxesPerHost: arguments.SandboxesPerHost, MaxHosts: arguments.MaxHosts,
		IdleTimeoutSeconds: arguments.IdleTimeoutSeconds}
	created, err := a.createSandboxHosts(ctx, config, arguments.WarmUp)
	if err != nil {
		return Outcome{}, err
	}
	result, _ := canonical(map[string]any{"host_ids": sandboxStateIDs(created), "pool": target.Name})
	return Outcome{Proven: true, Result: result}, nil
}

func (a *sandboxAdapter) checkSandboxPoolCreate(ctx context.Context, target sandboxTarget, expected sandboxPreconditions) error {
	hosts, err := a.client.ListSandboxPool(ctx, target.poolRef())
	if err != nil {
		return err
	}
	if !expected.ResourceAbsent || len(hosts) != 0 {
		return errors.New("operation_precondition_failed")
	}
	return nil
}

func (a *sandboxAdapter) executeSandboxPoolWarm(ctx context.Context, target sandboxTarget, raw json.RawMessage, expected sandboxPreconditions) (Outcome, error) {
	if expected.PoolConfig == nil {
		return Outcome{}, errors.New("sandbox pool configuration precondition is missing")
	}
	hosts, err := a.client.ListSandboxPool(ctx, target.poolRef())
	if err != nil {
		return Outcome{}, err
	}
	if sandboxStatesDigest(hosts) != expected.PoolDigest {
		return Outcome{}, errors.New("operation_precondition_failed")
	}
	_, err = validatedSandboxPoolWarm(raw, expected, len(hosts))
	if err != nil {
		return Outcome{}, errors.New("operation_precondition_failed")
	}
	config := hubclient.SandboxPoolSpec{Ref: target.poolRef(), OperationID: expected.OperationID, Image: expected.PoolConfig.Image,
		Flavor: expected.PoolConfig.Flavor, SandboxesPerHost: expected.PoolConfig.SandboxesPerHost,
		MaxHosts: expected.PoolConfig.MaxHosts, IdleTimeoutSeconds: expected.PoolConfig.IdleTimeoutSeconds}
	created, err := a.createSandboxHosts(ctx, config, expected.CreatedHosts)
	if err != nil {
		return Outcome{}, err
	}
	result, _ := canonical(map[string]any{"created_host_ids": sandboxStateIDs(created), "num_hosts": len(hosts) + len(created)})
	return Outcome{Proven: true, Result: result}, nil
}

func validatedSandboxPoolWarm(raw json.RawMessage, expected sandboxPreconditions, currentHosts int) (sandboxPoolWarmArguments, error) {
	var arguments sandboxPoolWarmArguments
	if err := decodeClosed(raw, &arguments, maxArgumentsBytes); err != nil {
		return arguments, err
	}
	if arguments.NumHosts != expected.ExpectedHosts || expected.CreatedHosts != max(0, arguments.NumHosts-currentHosts) {
		return arguments, errors.New("operation_precondition_failed")
	}
	return arguments, nil
}

func (a *sandboxAdapter) executeSandboxPoolDelete(ctx context.Context, target sandboxTarget, expected sandboxPreconditions) (Outcome, error) {
	hosts, err := a.client.ListSandboxPool(ctx, target.poolRef())
	if err != nil {
		return Outcome{}, err
	}
	if sandboxStatesDigest(hosts) != expected.PoolDigest {
		return Outcome{}, errors.New("operation_precondition_failed")
	}
	for _, host := range hosts {
		if err := a.client.CancelSandboxJob(ctx, host.Ref); err != nil {
			return Outcome{}, &PossiblePartialError{Err: err}
		}
	}
	result, _ := canonical(map[string]any{"canceled_host_ids": sandboxStateIDs(hosts), "pool": target.Name})
	return Outcome{Proven: true, Result: result}, nil
}

func (a *sandboxAdapter) executeSandboxAction(ctx context.Context, target sandboxTarget, raw json.RawMessage, expected sandboxPreconditions) (Outcome, error) {
	execute, found := sandboxActionExecutors[a.descriptor.Name]
	if !found {
		return Outcome{}, errors.New("sandbox operation is not implemented")
	}
	return execute(a, ctx, target.ref(), raw, expected)
}

var sandboxActionExecutors = map[string]func(*sandboxAdapter, context.Context, hubclient.SandboxRef, json.RawMessage, sandboxPreconditions) (Outcome, error){
	"sandbox.delete":       executeSandboxDelete,
	"sandbox.file.write":   executeSandboxFileWrite,
	"sandbox.file.mkdir":   executeSandboxFileMkdir,
	"sandbox.file.delete":  executeSandboxFileDelete,
	"sandbox.process.kill": executeSandboxProcessKill,
}

func executeSandboxDelete(a *sandboxAdapter, ctx context.Context, ref hubclient.SandboxRef, _ json.RawMessage, _ sandboxPreconditions) (Outcome, error) {
	if err := a.client.DeleteSandbox(ctx, ref); err != nil {
		return Outcome{}, err
	}
	return Outcome{Proven: true, Result: json.RawMessage(`{"deleted":true}`)}, nil
}

func executeSandboxFileWrite(a *sandboxAdapter, ctx context.Context, ref hubclient.SandboxRef, raw json.RawMessage, _ sandboxPreconditions) (Outcome, error) {
	var arguments sandboxFileWriteArguments
	_ = decodeClosed(raw, &arguments, maxArgumentsBytes)
	content := decodeSandboxContent(arguments.ContentBase64)
	if err := a.client.WriteSandboxFile(ctx, ref, arguments.Path, arguments.Mode, content); err != nil {
		return Outcome{}, err
	}
	result, _ := canonical(map[string]any{"path": arguments.Path, "content_digest": digest(content), "size": len(content)})
	return Outcome{Proven: true, Result: result}, nil
}

func executeSandboxFileMkdir(a *sandboxAdapter, ctx context.Context, ref hubclient.SandboxRef, raw json.RawMessage, _ sandboxPreconditions) (Outcome, error) {
	var arguments sandboxFileMkdirArguments
	_ = decodeClosed(raw, &arguments, maxArgumentsBytes)
	if err := a.client.MakeSandboxDirectory(ctx, ref, arguments.Path); err != nil {
		return Outcome{}, err
	}
	return Outcome{Proven: true, Result: json.RawMessage(`{"created":true}`)}, nil
}

func executeSandboxFileDelete(a *sandboxAdapter, ctx context.Context, ref hubclient.SandboxRef, raw json.RawMessage, _ sandboxPreconditions) (Outcome, error) {
	var arguments sandboxFileDeleteArguments
	_ = decodeClosed(raw, &arguments, maxArgumentsBytes)
	if err := a.client.DeleteSandboxFile(ctx, ref, arguments.Path, arguments.Recursive); err != nil {
		return Outcome{}, err
	}
	return Outcome{Proven: true, Result: json.RawMessage(`{"deleted":true}`)}, nil
}

func executeSandboxProcessKill(a *sandboxAdapter, ctx context.Context, ref hubclient.SandboxRef, raw json.RawMessage, _ sandboxPreconditions) (Outcome, error) {
	var arguments sandboxProcessKillArguments
	_ = decodeClosed(raw, &arguments, maxArgumentsBytes)
	if err := a.client.KillSandboxProcess(ctx, ref, arguments.PID); err != nil {
		return Outcome{}, err
	}
	result, _ := canonical(map[string]any{"killed": true, "pid": arguments.PID})
	return Outcome{Proven: true, Result: result}, nil
}

func (a *sandboxAdapter) materializeSandboxCreate(raw json.RawMessage) (sandboxCreatePublic, sandboxCreateSecret, error) {
	arguments, err := decodeSealedArguments(raw)
	if err != nil {
		return sandboxCreatePublic{}, sandboxCreateSecret{}, err
	}
	var public sandboxCreatePublic
	if err := decodeClosed(arguments.Public, &public, maxArgumentsBytes); err != nil {
		return sandboxCreatePublic{}, sandboxCreateSecret{}, err
	}
	secret := sandboxCreateSecret{Secrets: map[string]string{}}
	if arguments.SealedPayload == nil {
		return public, secret, nil
	}
	secret, err = a.consumeSandboxCreateSecret(*arguments.SealedPayload)
	return public, secret, err
}

func (a *sandboxAdapter) consumeSandboxCreateSecret(reference sealedstore.Reference) (sandboxCreateSecret, error) {
	secret := sandboxCreateSecret{Secrets: map[string]string{}}
	payload, err := a.store.Consume(reference)
	if err != nil {
		return secret, err
	}
	defer zero(payload)
	if err := decodeClosed(payload, &secret, maxArgumentsBytes); err != nil || len(secret.Secrets) == 0 || len(secret.Secrets) > 128 {
		return sandboxCreateSecret{}, errors.New("sealed sandbox secrets are invalid")
	}
	for key, value := range secret.Secrets {
		if !validEnvironmentEntry(key, value) {
			return sandboxCreateSecret{}, errors.New("sealed sandbox secrets are invalid")
		}
	}
	return secret, nil
}

func (a *sandboxAdapter) materializeSandboxPoolCreate(raw json.RawMessage) (sandboxPoolCreatePublic, error) {
	var public sandboxPoolCreatePublic
	if err := decodeClosed(raw, &public, maxArgumentsBytes); err != nil {
		return sandboxPoolCreatePublic{}, err
	}
	return public, nil
}

func (a *sandboxAdapter) checkSandboxPool(ctx context.Context, ref hubclient.SandboxPoolRef, expectedDigest string) error {
	hosts, err := a.client.ListSandboxPool(ctx, ref)
	if err != nil {
		return err
	}
	if sandboxStatesDigest(hosts) != expectedDigest {
		return errors.New("operation_precondition_failed")
	}
	return nil
}

func (a *sandboxAdapter) createSandboxHosts(ctx context.Context, config hubclient.SandboxPoolSpec, count int) ([]hubclient.SandboxState, error) {
	created := make([]hubclient.SandboxState, 0, count)
	for range count {
		state, err := a.client.CreateSandboxPoolHost(ctx, config)
		if err != nil {
			wrapped := fmt.Errorf("create sandbox pool host: %w", err)
			if len(created) > 0 {
				return nil, &PossiblePartialError{Err: wrapped}
			}
			return nil, wrapped
		}
		created = append(created, state)
	}
	return created, nil
}

func sandboxStateIDs(states []hubclient.SandboxState) []string {
	ids := make([]string, len(states))
	for index := range states {
		ids[index] = states[index].Ref.JobID
	}
	return ids
}
