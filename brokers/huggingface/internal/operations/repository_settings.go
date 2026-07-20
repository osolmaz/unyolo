package operations

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/osolmaz/brokerkit/agent/v1"
	"github.com/osolmaz/brokerkit/brokers/huggingface/internal/hubclient"
	"github.com/osolmaz/brokerkit/brokers/huggingface/internal/opcatalog"
	hfpolicy "github.com/osolmaz/brokerkit/brokers/huggingface/internal/policy"
)

type repositorySettingsClient interface {
	RepoInfo(context.Context, hubclient.RepoRef) (hubclient.RepoInfo, error)
	MoveRepo(context.Context, hubclient.RepoRef, string, string) error
	UpdateRepoVisibility(context.Context, hubclient.RepoRef, hubclient.Visibility) (hubclient.RepoSettings, error)
	UpdateRepoGating(context.Context, hubclient.RepoRef, hubclient.GatedMode) error
}

type repositorySettingsAdapter struct {
	descriptor opcatalog.Descriptor
	client     repositorySettingsClient
}

type moveArguments struct {
	Owner string `json:"owner"`
	Name  string `json:"name"`
}

type visibilityArguments struct {
	Visibility string `json:"visibility"`
}

type gatingArguments struct {
	Mode string `json:"mode"`
}

type repositorySettingsPreconditions struct {
	SourceDigest      string `json:"source_digest"`
	DestinationAbsent bool   `json:"destination_absent,omitempty"`
}

func NewRepositorySettingsAdapters(client repositorySettingsClient) ([]Adapter, error) {
	if client == nil {
		return nil, errors.New("hugging face repository settings client is required")
	}
	names := []string{"repo.gating.update", "repo.move", "repo.visibility.update"}
	adapters := make([]Adapter, 0, len(names))
	for _, name := range names {
		descriptor, found := opcatalog.ByName(name)
		if !found {
			return nil, fmt.Errorf("operation %q is absent from the catalog", name)
		}
		adapters = append(adapters, &repositorySettingsAdapter{descriptor: descriptor, client: client})
	}
	return adapters, nil
}

func (a *repositorySettingsAdapter) Descriptor() opcatalog.Descriptor { return a.descriptor }

func (a *repositorySettingsAdapter) Decode(targetRaw, argumentsRaw json.RawMessage) (Input, error) {
	return decodeInput(targetRaw, argumentsRaw, decodeRepositorySettingsTarget, a.decodeArguments)
}

func decodeRepositorySettingsTarget(raw json.RawMessage) (repositoryTarget, error) {
	return decodeValidated(raw, maxTargetBytes,
		func(target repositoryTarget) bool { return validRepositoryTarget(target) && target.Type != "kernel" },
		"repository target is invalid")
}

func (a *repositorySettingsAdapter) decodeArguments(target repositoryTarget, raw json.RawMessage) (any, error) {
	switch a.descriptor.Name {
	case "repo.move":
		return decodeMoveArguments(target, raw)
	case "repo.visibility.update":
		return decodeVisibilityArguments(target, raw)
	case "repo.gating.update":
		return decodeGatingArguments(target, raw)
	default:
		return nil, errors.New("repository settings operation is not implemented")
	}
}

func decodeMoveArguments(target repositoryTarget, raw json.RawMessage) (any, error) {
	var value moveArguments
	if err := decodeClosed(raw, &value, maxArgumentsBytes); err != nil || !hubclient.ValidNamespaceSegment(value.Owner) || !hubclient.ValidNamespaceSegment(value.Name) || value.Owner == target.Owner && value.Name == target.Name {
		return nil, errors.New("repository move destination is invalid")
	}
	return value, nil
}

func decodeVisibilityArguments(target repositoryTarget, raw json.RawMessage) (any, error) {
	var value visibilityArguments
	if err := decodeClosed(raw, &value, maxArgumentsBytes); err != nil || !validVisibility(target.Type, value.Visibility) {
		return nil, errors.New("repository visibility is invalid")
	}
	return value, nil
}

func decodeGatingArguments(target repositoryTarget, raw json.RawMessage) (any, error) {
	var value gatingArguments
	if err := decodeClosed(raw, &value, maxArgumentsBytes); err != nil || (value.Mode != "auto" && value.Mode != "manual" && value.Mode != "disabled") || target.Type == "space" {
		return nil, errors.New("repository gating mode is invalid")
	}
	return value, nil
}

func (a *repositorySettingsAdapter) Resolve(ctx context.Context, input Input) (Plan, error) {
	target, err := decodeRepositoryTarget(input.Target)
	if err != nil {
		return Plan{}, err
	}
	info, err := a.client.RepoInfo(ctx, target.repoRef())
	if err != nil {
		return Plan{}, err
	}
	preconditions := repositorySettingsPreconditions{SourceDigest: repoInfoDigest(info)}
	if a.descriptor.Name == "repo.move" {
		if err := a.checkMoveDestinationAbsent(ctx, target, input.Arguments, "operation target already exists"); err != nil {
			return Plan{}, err
		}
		preconditions.DestinationAbsent = true
	}
	encodedPreconditions, _ := canonical(preconditions)
	presentation, request, err := a.presentationAndPolicy(target, input.Arguments)
	if err != nil {
		return Plan{}, err
	}
	return Plan{Operation: a.descriptor.Name, OperationRevision: a.descriptor.OperationRevision, Target: input.Target,
		Arguments: input.Arguments, Preconditions: encodedPreconditions, Presentation: presentation, Policy: request}, nil
}

func (a *repositorySettingsAdapter) checkMoveDestinationAbsent(ctx context.Context, target repositoryTarget, raw json.RawMessage, conflictMessage string) error {
	var arguments moveArguments
	_ = decodeClosed(raw, &arguments, maxArgumentsBytes)
	_, err := a.client.RepoInfo(ctx, hubclient.RepoRef{Type: target.repoRef().Type, Owner: arguments.Owner, Name: arguments.Name})
	if hubclient.IsNotFound(err) {
		return nil
	}
	if err != nil {
		return err
	}
	return errors.New(conflictMessage)
}

func (a *repositorySettingsAdapter) Authorize(plan Plan) hfpolicy.Request {
	return authorizeReconstructed(plan, a.reconstruct(plan))
}

func (a *repositorySettingsAdapter) Present(plan Plan) agentv1.Presentation {
	return presentReconstructed(plan, a.reconstruct(plan))
}

func (a *repositorySettingsAdapter) reconstruct(plan Plan) reconstructedPlan {
	return reconstructPlanWithError(plan, decodeRepositoryTarget, a.presentationAndPolicy)
}

func (a *repositorySettingsAdapter) Execute(ctx context.Context, plan Plan) (Outcome, error) {
	target, preconditions, err := a.decodePlan(plan)
	if err != nil {
		return Outcome{}, err
	}
	if err := a.checkPreconditions(ctx, target, plan.Arguments, preconditions); err != nil {
		return Outcome{}, err
	}
	execute, found := repositorySettingsExecutors[a.descriptor.Name]
	if !found {
		return Outcome{}, errors.New("repository settings operation is not implemented")
	}
	return execute(a, ctx, target, plan.Arguments)
}

var repositorySettingsExecutors = map[string]func(*repositorySettingsAdapter, context.Context, repositoryTarget, json.RawMessage) (Outcome, error){
	"repo.move":              executeRepoMove,
	"repo.visibility.update": executeRepoVisibilityUpdate,
	"repo.gating.update":     executeRepoGatingUpdate,
}

func executeRepoMove(a *repositorySettingsAdapter, ctx context.Context, target repositoryTarget, raw json.RawMessage) (Outcome, error) {
	var arguments moveArguments
	_ = decodeClosed(raw, &arguments, maxArgumentsBytes)
	if err := a.client.MoveRepo(ctx, target.repoRef(), arguments.Owner, arguments.Name); err != nil {
		return Outcome{}, err
	}
	return Outcome{Result: json.RawMessage(`{"updated":true}`)}, nil
}

func executeRepoVisibilityUpdate(a *repositorySettingsAdapter, ctx context.Context, target repositoryTarget, raw json.RawMessage) (Outcome, error) {
	var arguments visibilityArguments
	_ = decodeClosed(raw, &arguments, maxArgumentsBytes)
	settings, err := a.client.UpdateRepoVisibility(ctx, target.repoRef(), hubclient.Visibility(arguments.Visibility))
	if err != nil {
		return Outcome{}, err
	}
	proven := settings.Visibility == hubclient.Visibility(arguments.Visibility)
	return Outcome{Proven: proven, Result: json.RawMessage(`{"updated":true}`)}, nil
}

func executeRepoGatingUpdate(a *repositorySettingsAdapter, ctx context.Context, target repositoryTarget, raw json.RawMessage) (Outcome, error) {
	var arguments gatingArguments
	_ = decodeClosed(raw, &arguments, maxArgumentsBytes)
	if err := a.client.UpdateRepoGating(ctx, target.repoRef(), hubclient.GatedMode(arguments.Mode)); err != nil {
		return Outcome{}, err
	}
	return Outcome{Result: json.RawMessage(`{"updated":true}`)}, nil
}

func (a *repositorySettingsAdapter) Reconcile(ctx context.Context, plan Plan) (Outcome, error) {
	target, _, err := a.decodePlan(plan)
	if err != nil {
		return Outcome{}, err
	}
	reconcile, found := repositorySettingsReconcilers[a.descriptor.Name]
	if !found {
		return Outcome{}, errors.New("repository settings operation is not implemented")
	}
	return reconcile(a, ctx, target, plan.Arguments)
}

var repositorySettingsReconcilers = map[string]func(*repositorySettingsAdapter, context.Context, repositoryTarget, json.RawMessage) (Outcome, error){
	"repo.move":              reconcileRepoMove,
	"repo.visibility.update": reconcileRepoVisibilityUpdate,
	"repo.gating.update":     reconcileRepoGatingUpdate,
}

func reconcileRepoMove(a *repositorySettingsAdapter, ctx context.Context, target repositoryTarget, raw json.RawMessage) (Outcome, error) {
	var arguments moveArguments
	_ = decodeClosed(raw, &arguments, maxArgumentsBytes)
	_, sourceErr := a.client.RepoInfo(ctx, target.repoRef())
	destination, destinationErr := a.client.RepoInfo(ctx, hubclient.RepoRef{Type: target.repoRef().Type, Owner: arguments.Owner, Name: arguments.Name})
	if hubclient.IsNotFound(sourceErr) && destinationErr == nil && destination.ID == arguments.Owner+"/"+arguments.Name {
		result, _ := canonical(map[string]any{"moved": true, "repo_id": destination.ID})
		return Outcome{Proven: true, Result: result}, nil
	}
	return Outcome{Proven: false}, errors.Join(sourceErr, destinationErr)
}

func reconcileRepoVisibilityUpdate(a *repositorySettingsAdapter, ctx context.Context, target repositoryTarget, raw json.RawMessage) (Outcome, error) {
	var arguments visibilityArguments
	_ = decodeClosed(raw, &arguments, maxArgumentsBytes)
	info, err := a.client.RepoInfo(ctx, target.repoRef())
	if err != nil {
		return Outcome{}, err
	}
	matches := arguments.Visibility == "private" && info.Private || arguments.Visibility == "public" && !info.Private
	return Outcome{Proven: matches, Result: json.RawMessage(`{"updated":true}`)}, nil
}

func reconcileRepoGatingUpdate(a *repositorySettingsAdapter, ctx context.Context, target repositoryTarget, raw json.RawMessage) (Outcome, error) {
	var arguments gatingArguments
	_ = decodeClosed(raw, &arguments, maxArgumentsBytes)
	info, err := a.client.RepoInfo(ctx, target.repoRef())
	if err != nil {
		return Outcome{}, err
	}
	return Outcome{Proven: string(info.Gated) == arguments.Mode, Result: json.RawMessage(`{"updated":true}`)}, nil
}

func (a *repositorySettingsAdapter) decodePlan(plan Plan) (repositoryTarget, repositorySettingsPreconditions, error) {
	return decodePlanState(plan, decodeRepositoryTarget, maxTargetBytes, validRepositorySettingsPreconditions, "operation plan preconditions are invalid")
}

func validRepositorySettingsPreconditions(value repositorySettingsPreconditions) bool {
	return value.SourceDigest != ""
}

func (a *repositorySettingsAdapter) checkPreconditions(ctx context.Context, target repositoryTarget, raw json.RawMessage, expected repositorySettingsPreconditions) error {
	info, err := a.client.RepoInfo(ctx, target.repoRef())
	if err != nil {
		return err
	}
	if repoInfoDigest(info) != expected.SourceDigest {
		return errors.New("operation_precondition_failed")
	}
	if a.descriptor.Name == "repo.move" && expected.DestinationAbsent {
		return a.checkMoveDestinationAbsent(ctx, target, raw, "operation_precondition_failed")
	}
	return nil
}

func (a *repositorySettingsAdapter) presentationAndPolicy(target repositoryTarget, raw json.RawMessage) (agentv1.Presentation, hfpolicy.Request, error) {
	request := hfpolicy.Request{Operation: hfpolicy.Operation(a.descriptor.Name), Target: hfpolicy.Target{Kind: hfpolicy.KindRepo, Type: hfpolicy.RepoType(target.Type), Owner: target.Owner, Name: target.Name}, Attrs: map[string]any{}}
	present, found := repositorySettingsPresenters[a.descriptor.Name]
	if !found {
		return agentv1.Presentation{}, hfpolicy.Request{}, errors.New("repository settings operation is not implemented")
	}
	presentation, err := present(target, raw, request.Attrs)
	return presentation, request, err
}

var repositorySettingsPresenters = map[string]func(repositoryTarget, json.RawMessage, map[string]any) (agentv1.Presentation, error){
	"repo.move":              presentRepoMove,
	"repo.visibility.update": repositorySettingPresenter[visibilityArguments]("visibility", "Change repository visibility", func(arguments visibilityArguments) string { return arguments.Visibility }),
	"repo.gating.update":     repositorySettingPresenter[gatingArguments]("gating", "Change repository gating", func(arguments gatingArguments) string { return arguments.Mode }),
}

func presentRepoMove(target repositoryTarget, raw json.RawMessage, attrs map[string]any) (agentv1.Presentation, error) {
	var arguments moveArguments
	if err := decodeClosed(raw, &arguments, maxArgumentsBytes); err != nil {
		return agentv1.Presentation{}, err
	}
	destination := arguments.Owner + "/" + arguments.Name
	attrs["destination"] = destination
	return agentv1.Presentation{Title: "Move Hugging Face repository", Summary: fmt.Sprintf("Move %s/%s to %s", target.Owner, target.Name, destination)}, nil
}

func repositorySettingPresenter[T any](key, title string, setting func(T) string) func(repositoryTarget, json.RawMessage, map[string]any) (agentv1.Presentation, error) {
	return func(target repositoryTarget, raw json.RawMessage, attrs map[string]any) (agentv1.Presentation, error) {
		var arguments T
		if err := decodeClosed(raw, &arguments, maxArgumentsBytes); err != nil {
			return agentv1.Presentation{}, err
		}
		value := setting(arguments)
		attrs[key] = value
		return agentv1.Presentation{Title: title, Summary: fmt.Sprintf("Set %s/%s %s to %s", target.Owner, target.Name, key, value)}, nil
	}
}

func decodeRepositoryTarget(raw json.RawMessage) (repositoryTarget, error) {
	return decodeValidated(raw, maxTargetBytes, validRepositoryTarget, "repository target is invalid")
}

func validVisibility(repoType, visibility string) bool {
	return visibility == "public" || visibility == "private" || repoType == "space" && visibility == "protected"
}

func repoInfoDigest(info hubclient.RepoInfo) string {
	return digestValue(info)
}
