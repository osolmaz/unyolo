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

var refsAdapterNames = []string{"repo.branch.create", "repo.branch.delete", "repo.tag.create", "repo.tag.delete"}

func NewRefsAdapters(client refsClient) ([]Adapter, error) {
	return adaptersForClient(client == nil, "Hugging Face refs client is required", refsAdapterNames, newRefsAdapter(client))
}

func newRefsAdapter(client refsClient) func(opcatalog.Descriptor) Adapter {
	return func(descriptor opcatalog.Descriptor) Adapter {
		return &refsAdapter{descriptor: descriptor, client: client}
	}
}

func (a *refsAdapter) Descriptor() opcatalog.Descriptor { return a.descriptor }

//nolint:cyclop // Ref-operation decoding is explicit and tracked by the exact HF CRAP baseline.
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
		preconditions.ExpectedCommit, err = a.resolveCreateCommit(refs, input.Arguments)
		if err != nil {
			return Plan{}, err
		}
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
	return authorizeReconstructed(plan, a.reconstruct(plan))
}

func (a *refsAdapter) Present(plan Plan) agentv1.Presentation {
	return presentReconstructed(plan, a.reconstruct(plan))
}

func (a *refsAdapter) reconstruct(plan Plan) reconstructedPlan {
	return reconstructPlan(plan.Target, plan.Arguments, decodeRefTarget,
		func(target refTarget, _ json.RawMessage) (agentv1.Presentation, hfpolicy.Request) {
			return a.presentationAndPolicy(target)
		})
}

func (a *refsAdapter) Execute(ctx context.Context, plan Plan) (Outcome, error) {
	target, preconditions, err := a.decodePlan(plan)
	if err != nil {
		return Outcome{}, err
	}
	refs, err := a.client.ListRefs(ctx, target.repoRef())
	if err != nil || refsDigest(refs) != preconditions.ObservedDigest {
		if err != nil {
			return Outcome{}, err
		}
		return Outcome{}, errors.New("operation_precondition_failed")
	}
	switch a.descriptor.Name {
	case "repo.branch.create":
		err = a.client.CreateBranch(ctx, target.repoRef(), target.Ref, preconditions.ExpectedCommit)
	case "repo.branch.delete":
		err = a.client.DeleteBranch(ctx, target.repoRef(), target.Ref)
	case "repo.tag.create":
		var arguments tagCreateArguments
		_ = decodeClosed(plan.Arguments, &arguments, maxArgumentsBytes)
		err = a.client.CreateTag(ctx, target.repoRef(), target.Ref, arguments.Message, preconditions.ExpectedCommit)
	case "repo.tag.delete":
		err = a.client.DeleteTag(ctx, target.repoRef(), target.Ref)
	}
	if err != nil {
		return Outcome{}, err
	}
	return Outcome{Result: json.RawMessage(`{"updated":true}`)}, nil
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
		return Outcome{Proven: found && value.TargetCommit == preconditions.ExpectedCommit, Result: json.RawMessage(`{"updated":true}`)}, nil
	}
	return Outcome{Proven: !found, Result: json.RawMessage(`{"updated":true}`)}, nil
}

func (a *refsAdapter) decodePlan(plan Plan) (refTarget, refsPreconditions, error) {
	return decodePlanState(plan, decodeRefTarget, maxTargetBytes, validRefsPreconditions, "operation plan preconditions are invalid")
}

func validRefsPreconditions(value refsPreconditions) bool {
	return value.ObservedDigest != "" && value.ExpectedCommit != ""
}

func (a *refsAdapter) resolveCreateCommit(refs hubclient.Refs, raw json.RawMessage) (string, error) {
	revision := ""
	if a.descriptor.Name == "repo.branch.create" {
		var arguments branchCreateArguments
		_ = decodeClosed(raw, &arguments, maxArgumentsBytes)
		revision = arguments.StartingPoint
	} else {
		var arguments tagCreateArguments
		_ = decodeClosed(raw, &arguments, maxArgumentsBytes)
		revision = arguments.Revision
	}
	if validCommitParent(revision) {
		return revision, nil
	}
	if value, found := refs.Branch(revision); found && validCommitParent(value.TargetCommit) {
		return value.TargetCommit, nil
	}
	if value, found := refs.Tag(revision); found && validCommitParent(value.TargetCommit) {
		return value.TargetCommit, nil
	}
	return "", errors.New("operation starting revision could not be resolved to an exact commit")
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
	return decodeValidated(raw, maxTargetBytes, validRefTarget, "repository ref target is invalid")
}

func (target refTarget) repoRef() hubclient.RepoRef {
	return hubclient.RepoRef{Type: hubclient.RepoType(target.Type), Owner: target.Owner, Name: target.Name}
}

func refsDigest(refs hubclient.Refs) string {
	return digestValue(refs)
}
