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

type repositorySettingsClient interface {
	RepoInfo(context.Context, hubclient.RepoRef) (hubclient.RepoInfo, error)
	MoveRepo(context.Context, hubclient.RepoRef, string, string) error
	UpdateRepoVisibility(context.Context, hubclient.RepoRef, hubclient.Visibility) error
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
		return nil, errors.New("Hugging Face repository settings client is required")
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
	var target repositoryTarget
	if err := decodeClosed(targetRaw, &target, maxTargetBytes); err != nil || !validRepositoryTarget(target) || target.Type == "kernel" {
		return Input{}, errors.New("repository target is invalid")
	}
	canonicalTarget, _ := canonical(target)
	var arguments any
	switch a.descriptor.Name {
	case "repo.move":
		var value moveArguments
		if err := decodeClosed(argumentsRaw, &value, maxArgumentsBytes); err != nil || !hubclient.ValidNamespaceSegment(value.Owner) || !hubclient.ValidNamespaceSegment(value.Name) || value.Owner == target.Owner && value.Name == target.Name {
			return Input{}, errors.New("repository move destination is invalid")
		}
		arguments = value
	case "repo.visibility.update":
		var value visibilityArguments
		if err := decodeClosed(argumentsRaw, &value, maxArgumentsBytes); err != nil || !validVisibility(target.Type, value.Visibility) {
			return Input{}, errors.New("repository visibility is invalid")
		}
		arguments = value
	case "repo.gating.update":
		var value gatingArguments
		if err := decodeClosed(argumentsRaw, &value, maxArgumentsBytes); err != nil || (value.Mode != "auto" && value.Mode != "manual" && value.Mode != "disabled") || target.Type == "space" {
			return Input{}, errors.New("repository gating mode is invalid")
		}
		arguments = value
	default:
		return Input{}, errors.New("repository settings operation is not implemented")
	}
	canonicalArguments, _ := canonical(arguments)
	return Input{Target: canonicalTarget, Arguments: canonicalArguments}, nil
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
		var arguments moveArguments
		_ = decodeClosed(input.Arguments, &arguments, maxArgumentsBytes)
		_, destinationErr := a.client.RepoInfo(ctx, hubclient.RepoRef{Type: target.repoRef().Type, Owner: arguments.Owner, Name: arguments.Name})
		if !hubclient.IsNotFound(destinationErr) {
			if destinationErr != nil {
				return Plan{}, destinationErr
			}
			return Plan{}, errors.New("operation target already exists")
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

func (a *repositorySettingsAdapter) Authorize(plan Plan) hfpolicy.Request {
	if plan.Policy.Operation != "" {
		return plan.Policy
	}
	target, err := decodeRepositoryTarget(plan.Target)
	if err != nil {
		return hfpolicy.Request{}
	}
	_, request, _ := a.presentationAndPolicy(target, plan.Arguments)
	return request
}

func (a *repositorySettingsAdapter) Present(plan Plan) agentv1.Presentation {
	if plan.Presentation.Title != "" {
		return plan.Presentation
	}
	target, err := decodeRepositoryTarget(plan.Target)
	if err != nil {
		return agentv1.Presentation{}
	}
	presentation, _, _ := a.presentationAndPolicy(target, plan.Arguments)
	return presentation
}

func (a *repositorySettingsAdapter) Execute(ctx context.Context, plan Plan) (json.RawMessage, error) {
	target, preconditions, err := a.decodePlan(plan)
	if err != nil {
		return nil, err
	}
	if err := a.checkPreconditions(ctx, target, plan.Arguments, preconditions); err != nil {
		return nil, err
	}
	switch a.descriptor.Name {
	case "repo.move":
		var arguments moveArguments
		_ = decodeClosed(plan.Arguments, &arguments, maxArgumentsBytes)
		err = a.client.MoveRepo(ctx, target.repoRef(), arguments.Owner, arguments.Name)
	case "repo.visibility.update":
		var arguments visibilityArguments
		_ = decodeClosed(plan.Arguments, &arguments, maxArgumentsBytes)
		err = a.client.UpdateRepoVisibility(ctx, target.repoRef(), hubclient.Visibility(arguments.Visibility))
	case "repo.gating.update":
		var arguments gatingArguments
		_ = decodeClosed(plan.Arguments, &arguments, maxArgumentsBytes)
		err = a.client.UpdateRepoGating(ctx, target.repoRef(), hubclient.GatedMode(arguments.Mode))
	}
	if err != nil {
		return nil, err
	}
	return json.RawMessage(`{"updated":true}`), nil
}

func (a *repositorySettingsAdapter) Reconcile(ctx context.Context, plan Plan) (Outcome, error) {
	target, _, err := a.decodePlan(plan)
	if err != nil {
		return Outcome{}, err
	}
	switch a.descriptor.Name {
	case "repo.move":
		var arguments moveArguments
		_ = decodeClosed(plan.Arguments, &arguments, maxArgumentsBytes)
		_, sourceErr := a.client.RepoInfo(ctx, target.repoRef())
		destination, destinationErr := a.client.RepoInfo(ctx, hubclient.RepoRef{Type: target.repoRef().Type, Owner: arguments.Owner, Name: arguments.Name})
		if hubclient.IsNotFound(sourceErr) && destinationErr == nil && destination.ID == arguments.Owner+"/"+arguments.Name {
			result, _ := canonical(map[string]any{"moved": true, "repo_id": destination.ID})
			return Outcome{Proven: true, Result: result}, nil
		}
		return Outcome{Proven: false}, errors.Join(sourceErr, destinationErr)
	case "repo.visibility.update":
		var arguments visibilityArguments
		_ = decodeClosed(plan.Arguments, &arguments, maxArgumentsBytes)
		info, readErr := a.client.RepoInfo(ctx, target.repoRef())
		if readErr != nil {
			return Outcome{}, readErr
		}
		matches := arguments.Visibility == "private" && info.Private || arguments.Visibility == "public" && !info.Private
		return Outcome{Proven: matches, Result: json.RawMessage(`{"updated":true}`)}, nil
	case "repo.gating.update":
		var arguments gatingArguments
		_ = decodeClosed(plan.Arguments, &arguments, maxArgumentsBytes)
		info, readErr := a.client.RepoInfo(ctx, target.repoRef())
		if readErr != nil {
			return Outcome{}, readErr
		}
		return Outcome{Proven: string(info.Gated) == arguments.Mode, Result: json.RawMessage(`{"updated":true}`)}, nil
	default:
		return Outcome{}, errors.New("repository settings operation is not implemented")
	}
}

func (a *repositorySettingsAdapter) decodePlan(plan Plan) (repositoryTarget, repositorySettingsPreconditions, error) {
	target, err := decodeRepositoryTarget(plan.Target)
	if err != nil {
		return repositoryTarget{}, repositorySettingsPreconditions{}, err
	}
	var preconditions repositorySettingsPreconditions
	if err := decodeClosed(plan.Preconditions, &preconditions, maxTargetBytes); err != nil || preconditions.SourceDigest == "" {
		return repositoryTarget{}, repositorySettingsPreconditions{}, errors.New("operation plan preconditions are invalid")
	}
	return target, preconditions, nil
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
		var arguments moveArguments
		_ = decodeClosed(raw, &arguments, maxArgumentsBytes)
		_, destinationErr := a.client.RepoInfo(ctx, hubclient.RepoRef{Type: target.repoRef().Type, Owner: arguments.Owner, Name: arguments.Name})
		if !hubclient.IsNotFound(destinationErr) {
			if destinationErr != nil {
				return destinationErr
			}
			return errors.New("operation_precondition_failed")
		}
	}
	return nil
}

func (a *repositorySettingsAdapter) presentationAndPolicy(target repositoryTarget, raw json.RawMessage) (agentv1.Presentation, hfpolicy.Request, error) {
	request := hfpolicy.Request{Operation: hfpolicy.Operation(a.descriptor.Name), Target: hfpolicy.Target{Kind: hfpolicy.KindRepo, Type: hfpolicy.RepoType(target.Type), Owner: target.Owner, Name: target.Name}, Attrs: map[string]any{}}
	switch a.descriptor.Name {
	case "repo.move":
		var arguments moveArguments
		if err := decodeClosed(raw, &arguments, maxArgumentsBytes); err != nil {
			return agentv1.Presentation{}, hfpolicy.Request{}, err
		}
		destination := arguments.Owner + "/" + arguments.Name
		request.Attrs["destination"] = destination
		return agentv1.Presentation{Title: "Move Hugging Face repository", Summary: fmt.Sprintf("Move %s/%s to %s", target.Owner, target.Name, destination)}, request, nil
	case "repo.visibility.update":
		var arguments visibilityArguments
		if err := decodeClosed(raw, &arguments, maxArgumentsBytes); err != nil {
			return agentv1.Presentation{}, hfpolicy.Request{}, err
		}
		request.Attrs["visibility"] = arguments.Visibility
		return agentv1.Presentation{Title: "Change repository visibility", Summary: fmt.Sprintf("Set %s/%s visibility to %s", target.Owner, target.Name, arguments.Visibility)}, request, nil
	case "repo.gating.update":
		var arguments gatingArguments
		if err := decodeClosed(raw, &arguments, maxArgumentsBytes); err != nil {
			return agentv1.Presentation{}, hfpolicy.Request{}, err
		}
		request.Attrs["gating"] = arguments.Mode
		return agentv1.Presentation{Title: "Change repository gating", Summary: fmt.Sprintf("Set %s/%s gating to %s", target.Owner, target.Name, arguments.Mode)}, request, nil
	default:
		return agentv1.Presentation{}, hfpolicy.Request{}, errors.New("repository settings operation is not implemented")
	}
}

func decodeRepositoryTarget(raw json.RawMessage) (repositoryTarget, error) {
	var target repositoryTarget
	if err := decodeClosed(raw, &target, maxTargetBytes); err != nil || !validRepositoryTarget(target) {
		return repositoryTarget{}, errors.New("repository target is invalid")
	}
	return target, nil
}

func validVisibility(repoType, visibility string) bool {
	return visibility == "public" || visibility == "private" || repoType == "space" && visibility == "protected"
}

func repoInfoDigest(info hubclient.RepoInfo) string {
	value, _ := canonical(info)
	return digest(value)
}

func policyText(value string) string { return strings.TrimSpace(value) }
