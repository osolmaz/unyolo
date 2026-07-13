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

type refsClient interface {
	ListRefs(context.Context, hubclient.RepoRef) (hubclient.Refs, error)
	CreateBranch(context.Context, hubclient.RepoRef, string, string) error
	DeleteBranch(context.Context, hubclient.RepoRef, string) error
	CreateTag(context.Context, hubclient.RepoRef, string, string, string) error
	DeleteTag(context.Context, hubclient.RepoRef, string) error
}

type refsAdapter struct {
	descriptor opcatalog.Descriptor
	client     refsClient
}

type refTarget struct {
	Kind  string `json:"kind"`
	Type  string `json:"type"`
	Owner string `json:"owner"`
	Name  string `json:"name"`
	Ref   string `json:"ref"`
}

type branchCreateArguments struct {
	StartingPoint string `json:"starting_point"`
}

type tagCreateArguments struct {
	Revision string `json:"revision"`
	Message  string `json:"message,omitempty"`
}

type refsPreconditions struct {
	ObservedDigest string `json:"observed_digest"`
	ExpectedAbsent bool   `json:"expected_absent,omitempty"`
	ExpectedCommit string `json:"expected_commit,omitempty"`
}

func NewRefsAdapters(client refsClient) ([]Adapter, error) {
	if client == nil {
		return nil, errors.New("Hugging Face refs client is required")
	}
	names := []string{"repo.branch.create", "repo.branch.delete", "repo.tag.create", "repo.tag.delete"}
	adapters := make([]Adapter, 0, len(names))
	for _, name := range names {
		descriptor, found := opcatalog.ByName(name)
		if !found {
			return nil, fmt.Errorf("operation %q is absent from the catalog", name)
		}
		adapters = append(adapters, &refsAdapter{descriptor: descriptor, client: client})
	}
	return adapters, nil
}

func (a *refsAdapter) Descriptor() opcatalog.Descriptor { return a.descriptor }

func (a *refsAdapter) Decode(targetRaw, argumentsRaw json.RawMessage) (Input, error) {
	var target refTarget
	if err := decodeClosed(targetRaw, &target, maxTargetBytes); err != nil || !validRefTarget(target) {
		return Input{}, errors.New("repository ref target is invalid")
	}
	canonicalTarget, _ := canonical(target)
	var arguments any
	switch a.descriptor.Name {
	case "repo.branch.create":
		var value branchCreateArguments
		if err := decodeClosed(argumentsRaw, &value, maxArgumentsBytes); err != nil || !hubclient.ValidGitRefComponent(value.StartingPoint) {
			return Input{}, errors.New("branch starting point is invalid")
		}
		arguments = value
	case "repo.tag.create":
		var value tagCreateArguments
		if err := decodeClosed(argumentsRaw, &value, maxArgumentsBytes); err != nil || !hubclient.ValidGitRefComponent(value.Revision) || len(value.Message) > 1000 {
			return Input{}, errors.New("tag creation arguments are invalid")
		}
		arguments = value
	case "repo.branch.delete", "repo.tag.delete":
		var value emptyArguments
		if err := decodeClosed(argumentsRaw, &value, maxArgumentsBytes); err != nil {
			return Input{}, errors.New("ref deletion arguments must be empty")
		}
		arguments = value
	default:
		return Input{}, errors.New("repository ref operation is not implemented")
	}
	canonicalArguments, _ := canonical(arguments)
	return Input{Target: canonicalTarget, Arguments: canonicalArguments}, nil
}

func (a *refsAdapter) Resolve(ctx context.Context, input Input) (Plan, error) {
	target, err := decodeRefTarget(input.Target)
	if err != nil {
		return Plan{}, err
	}
	refs, err := a.client.ListRefs(ctx, target.repoRef())
	if err != nil {
		return Plan{}, err
	}
	preconditions := refsPreconditions{ObservedDigest: refsDigest(refs)}
	value, found := a.find(refs, target.Ref)
	if strings.HasSuffix(a.descriptor.Name, ".create") {
		if found {
			return Plan{}, errors.New("operation target already exists")
		}
		preconditions.ExpectedAbsent = true
	} else {
		if !found {
			return Plan{}, &hubclient.Error{Code: hubclient.CodeNotFound}
		}
		preconditions.ExpectedCommit = value.TargetCommit
	}
	encodedPreconditions, _ := canonical(preconditions)
	presentation, request := a.presentationAndPolicy(target)
	return Plan{Operation: a.descriptor.Name, OperationRevision: a.descriptor.OperationRevision, Target: input.Target,
		Arguments: input.Arguments, Preconditions: encodedPreconditions, Presentation: presentation, Policy: request}, nil
}

func (a *refsAdapter) Authorize(plan Plan) hfpolicy.Request {
	if plan.Policy.Operation != "" {
		return plan.Policy
	}
	target, err := decodeRefTarget(plan.Target)
	if err != nil {
		return hfpolicy.Request{}
	}
	_, request := a.presentationAndPolicy(target)
	return request
}

func (a *refsAdapter) Present(plan Plan) agentv1.Presentation {
	if plan.Presentation.Title != "" {
		return plan.Presentation
	}
	target, err := decodeRefTarget(plan.Target)
	if err != nil {
		return agentv1.Presentation{}
	}
	presentation, _ := a.presentationAndPolicy(target)
	return presentation
}

func (a *refsAdapter) Execute(ctx context.Context, plan Plan) (json.RawMessage, error) {
	target, preconditions, err := a.decodePlan(plan)
	if err != nil {
		return nil, err
	}
	refs, err := a.client.ListRefs(ctx, target.repoRef())
	if err != nil || refsDigest(refs) != preconditions.ObservedDigest {
		if err != nil {
			return nil, err
		}
		return nil, errors.New("operation_precondition_failed")
	}
	switch a.descriptor.Name {
	case "repo.branch.create":
		var arguments branchCreateArguments
		_ = decodeClosed(plan.Arguments, &arguments, maxArgumentsBytes)
		err = a.client.CreateBranch(ctx, target.repoRef(), target.Ref, arguments.StartingPoint)
	case "repo.branch.delete":
		err = a.client.DeleteBranch(ctx, target.repoRef(), target.Ref)
	case "repo.tag.create":
		var arguments tagCreateArguments
		_ = decodeClosed(plan.Arguments, &arguments, maxArgumentsBytes)
		err = a.client.CreateTag(ctx, target.repoRef(), target.Ref, arguments.Message, arguments.Revision)
	case "repo.tag.delete":
		err = a.client.DeleteTag(ctx, target.repoRef(), target.Ref)
	}
	if err != nil {
		return nil, err
	}
	return json.RawMessage(`{"updated":true}`), nil
}

func (a *refsAdapter) Reconcile(ctx context.Context, plan Plan) (Outcome, error) {
	target, preconditions, err := a.decodePlan(plan)
	if err != nil {
		return Outcome{}, err
	}
	refs, err := a.client.ListRefs(ctx, target.repoRef())
	if err != nil {
		return Outcome{}, err
	}
	value, found := a.find(refs, target.Ref)
	if strings.HasSuffix(a.descriptor.Name, ".create") {
		return Outcome{Proven: found, Result: json.RawMessage(`{"updated":true}`)}, nil
	}
	return Outcome{Proven: !found && preconditions.ExpectedCommit != value.TargetCommit, Result: json.RawMessage(`{"updated":true}`)}, nil
}

func (a *refsAdapter) decodePlan(plan Plan) (refTarget, refsPreconditions, error) {
	target, err := decodeRefTarget(plan.Target)
	if err != nil {
		return refTarget{}, refsPreconditions{}, err
	}
	var preconditions refsPreconditions
	if err := decodeClosed(plan.Preconditions, &preconditions, maxTargetBytes); err != nil || preconditions.ObservedDigest == "" {
		return refTarget{}, refsPreconditions{}, errors.New("operation plan preconditions are invalid")
	}
	return target, preconditions, nil
}

func (a *refsAdapter) find(refs hubclient.Refs, name string) (hubclient.GitRef, bool) {
	if strings.Contains(a.descriptor.Name, ".branch.") {
		return refs.Branch(name)
	}
	return refs.Tag(name)
}

func (a *refsAdapter) presentationAndPolicy(target refTarget) (agentv1.Presentation, hfpolicy.Request) {
	kind := "tag"
	prefix := "refs/tags/"
	if strings.Contains(a.descriptor.Name, ".branch.") {
		kind = "branch"
		prefix = "refs/heads/"
	}
	action := "Create"
	if strings.HasSuffix(a.descriptor.Name, ".delete") {
		action = "Delete"
	}
	presentation := agentv1.Presentation{Title: action + " repository " + kind, Summary: fmt.Sprintf("%s %s %s in %s/%s", action, kind, target.Ref, target.Owner, target.Name)}
	request := hfpolicy.Request{Operation: hfpolicy.Operation(a.descriptor.Name), Target: hfpolicy.Target{Kind: hfpolicy.KindRepo, Type: hfpolicy.RepoType(target.Type), Owner: target.Owner, Name: target.Name, Refs: []string{prefix + target.Ref}}, Attrs: map[string]any{}}
	return presentation, request
}

func validRefTarget(target refTarget) bool {
	return target.Kind == "repo" && target.Type != "kernel" && validRepositoryTarget(repositoryTarget{Kind: target.Kind, Type: target.Type, Owner: target.Owner, Name: target.Name}) && hubclient.ValidGitRefComponent(target.Ref)
}

func decodeRefTarget(raw json.RawMessage) (refTarget, error) {
	var target refTarget
	if err := decodeClosed(raw, &target, maxTargetBytes); err != nil || !validRefTarget(target) {
		return refTarget{}, errors.New("repository ref target is invalid")
	}
	return target, nil
}

func (target refTarget) repoRef() hubclient.RepoRef {
	return hubclient.RepoRef{Type: hubclient.RepoType(target.Type), Owner: target.Owner, Name: target.Name}
}

func refsDigest(refs hubclient.Refs) string {
	value, _ := canonical(refs)
	return digest(value)
}
