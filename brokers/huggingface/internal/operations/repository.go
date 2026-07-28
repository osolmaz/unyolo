package operations

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"strings"

	"github.com/osolmaz/unyolo/agent/v1"
	"github.com/osolmaz/unyolo/brokers/huggingface/internal/hubclient"
	"github.com/osolmaz/unyolo/brokers/huggingface/internal/opcatalog"
	hfpolicy "github.com/osolmaz/unyolo/brokers/huggingface/internal/policy"
)

var repoSegment = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,95}$`)

type repositoryAdapter struct {
	descriptor opcatalog.Descriptor
	client     repositoryClient
	endpoint   string
}

type repositoryClient interface {
	WhoAmI(context.Context) (hubclient.Identity, error)
	RepoInfo(context.Context, hubclient.RepoRef) (hubclient.RepoInfo, error)
	CreateRepo(context.Context, hubclient.CreateRepoInput) (hubclient.CreatedRepo, error)
	DeleteRepo(context.Context, hubclient.RepoRef) error
}

type repositoryTarget struct {
	Kind  string `json:"kind"`
	Type  string `json:"type"`
	Owner string `json:"owner"`
	Name  string `json:"name"`
}

type repoCreateArguments struct {
	Visibility string `json:"visibility"`
	SDK        string `json:"sdk,omitempty"`
}

type emptyArguments struct{}

type repoPreconditions struct {
	Absent             bool   `json:"absent,omitempty"`
	CredentialIdentity string `json:"credential_identity,omitempty"`
	ObservedDigest     string `json:"observed_digest,omitempty"`
}

func NewRepositoryAdapters(hub repositoryClient, endpoint string) ([]Adapter, error) {
	if hub == nil {
		return nil, errors.New("hugging face hub client is required")
	}
	adapters := make([]Adapter, 0, 2)
	for _, name := range []string{"repo.create", "repo.delete"} {
		descriptor, found := opcatalog.ByName(name)
		if !found {
			return nil, fmt.Errorf("operation %q is absent from the catalog", name)
		}
		adapters = append(adapters, &repositoryAdapter{descriptor: descriptor, client: hub, endpoint: strings.TrimRight(endpoint, "/")})
	}
	return adapters, nil
}

func (a *repositoryAdapter) Descriptor() opcatalog.Descriptor { return a.descriptor }

func (a *repositoryAdapter) Decode(targetRaw, argumentsRaw json.RawMessage) (Input, error) {
	return decodeInput(targetRaw, argumentsRaw, decodeRepositoryInputTarget, a.decodeArguments)
}

func decodeRepositoryInputTarget(raw json.RawMessage) (repositoryTarget, error) {
	return decodeValidated(raw, maxTargetBytes, validRepositoryTarget,
		"repository target must contain an exact kind, type, owner, and name")
}

func (a *repositoryAdapter) decodeArguments(target repositoryTarget, raw json.RawMessage) (any, error) {
	switch a.descriptor.Name {
	case "repo.create":
		return decodeRepoCreateArguments(target, raw)
	case "repo.delete":
		return decodeRepoDeleteArguments(raw)
	default:
		return nil, errors.New("repository operation is not implemented")
	}
}

func decodeRepoCreateArguments(target repositoryTarget, raw json.RawMessage) (any, error) {
	var arguments repoCreateArguments
	if err := decodeClosed(raw, &arguments, maxArgumentsBytes); err != nil || !validRepoCreateArguments(target, arguments) {
		return nil, errors.New("repository creation arguments are invalid")
	}
	return arguments, nil
}

func decodeRepoDeleteArguments(raw json.RawMessage) (any, error) {
	return decodeEmptyArguments(raw, "repository deletion arguments must be empty")
}

func (a *repositoryAdapter) Resolve(ctx context.Context, input Input) (Plan, error) {
	var target repositoryTarget
	if err := decodeClosed(input.Target, &target, maxTargetBytes); err != nil {
		return Plan{}, err
	}
	preconditions, err := a.resolvePreconditions(ctx, target)
	if err != nil {
		return Plan{}, err
	}
	presentation, policyRequest, err := a.presentationAndPolicy(target, input.Arguments)
	if err != nil {
		return Plan{}, err
	}
	encodedPreconditions, _ := canonical(preconditions)
	return Plan{Operation: a.descriptor.Name, OperationRevision: a.descriptor.OperationRevision, Target: input.Target,
		Arguments: input.Arguments, Preconditions: encodedPreconditions, Presentation: presentation, Policy: policyRequest}, nil
}

func (a *repositoryAdapter) Authorize(plan Plan) hfpolicy.Request {
	return authorizeReconstructed(plan, a.reconstruct(plan))
}

func (a *repositoryAdapter) Present(plan Plan) agentv1.Presentation {
	return presentReconstructed(plan, a.reconstruct(plan))
}

func (a *repositoryAdapter) reconstruct(plan Plan) reconstructedPlan {
	return reconstructPlanWithError(plan, decodeRepositoryOperationTarget, a.presentationAndPolicy)
}

func decodeRepositoryOperationTarget(raw json.RawMessage) (repositoryTarget, error) {
	var target repositoryTarget
	return target, decodeClosed(raw, &target, maxTargetBytes)
}

func (a *repositoryAdapter) Execute(ctx context.Context, plan Plan) (Outcome, error) {
	target, preconditions, err := decodeRepositoryExecutionPlan(plan)
	if err != nil {
		return Outcome{}, err
	}
	if err := a.checkPreconditions(ctx, target, preconditions); err != nil {
		return Outcome{}, err
	}
	if a.descriptor.Name == "repo.create" {
		return a.executeRepositoryCreate(ctx, target, preconditions, plan.Arguments)
	}
	if a.descriptor.Name == "repo.delete" {
		if err := a.client.DeleteRepo(ctx, target.repoRef()); err != nil {
			return Outcome{}, err
		}
		return Outcome{Result: json.RawMessage(`{"deleted":true}`)}, nil
	}
	return Outcome{}, errors.New("repository operation is not implemented")
}

func decodeRepositoryExecutionPlan(plan Plan) (repositoryTarget, repoPreconditions, error) {
	var target repositoryTarget
	var preconditions repoPreconditions
	if decodeClosed(plan.Target, &target, maxTargetBytes) != nil || decodeClosed(plan.Preconditions, &preconditions, maxTargetBytes) != nil {
		return target, preconditions, errors.New("operation plan is invalid")
	}
	return target, preconditions, nil
}

func (a *repositoryAdapter) executeRepositoryCreate(ctx context.Context, target repositoryTarget, preconditions repoPreconditions, raw json.RawMessage) (Outcome, error) {
	var arguments repoCreateArguments
	if decodeClosed(raw, &arguments, maxArgumentsBytes) != nil {
		return Outcome{}, errors.New("operation plan arguments are invalid")
	}
	if _, err := a.client.CreateRepo(ctx, hubclient.CreateRepoInput{Ref: target.repoRef(), Visibility: hubclient.Visibility(arguments.Visibility), SpaceSDK: arguments.SDK, PersonalNamespace: preconditions.CredentialIdentity == target.Owner}); err != nil {
		return Outcome{}, err
	}
	result, err := canonical(map[string]any{"repo_id": target.Owner + "/" + target.Name, "url": a.repoURL(target)})
	return Outcome{Result: result}, err
}

func (a *repositoryAdapter) Reconcile(ctx context.Context, plan Plan) (Outcome, error) {
	var target repositoryTarget
	if err := decodeClosed(plan.Target, &target, maxTargetBytes); err != nil {
		return Outcome{}, err
	}
	info, err := a.client.RepoInfo(ctx, target.repoRef())
	switch a.descriptor.Name {
	case "repo.create":
		return a.reconcileCreate(plan, target, info, err)
	case "repo.delete":
		return reconcileDelete(err)
	default:
		return Outcome{}, errors.New("repository operation is not implemented")
	}
}

func (a *repositoryAdapter) reconcileCreate(plan Plan, target repositoryTarget, info hubclient.RepoInfo, readErr error) (Outcome, error) {
	if readErr != nil {
		return Outcome{}, readErr
	}
	var arguments repoCreateArguments
	if err := decodeClosed(plan.Arguments, &arguments, maxArgumentsBytes); err != nil {
		return Outcome{}, err
	}
	if !repoCreationMatches(target, arguments, info) {
		return Outcome{Proven: false}, nil
	}
	result, _ := canonical(map[string]any{"repo_id": target.Owner + "/" + target.Name, "url": a.repoURL(target)})
	return Outcome{Proven: true, Result: result}, nil
}

func reconcileDelete(err error) (Outcome, error) {
	var upstream *hubclient.Error
	if errors.As(err, &upstream) && upstream.Code == hubclient.CodeNotFound {
		return Outcome{Proven: true, Result: json.RawMessage(`{"deleted":true}`)}, nil
	}
	if err != nil {
		return Outcome{}, err
	}
	return Outcome{Proven: false}, nil
}

func (a *repositoryAdapter) resolvePreconditions(ctx context.Context, target repositoryTarget) (repoPreconditions, error) {
	body, err := a.readRepository(ctx, target)
	if a.descriptor.Name == "repo.create" {
		return a.resolveRepositoryCreatePreconditions(ctx, err)
	}
	if err != nil {
		return repoPreconditions{}, err
	}
	return repoPreconditions{ObservedDigest: digest(body)}, nil
}

func (a *repositoryAdapter) resolveRepositoryCreatePreconditions(ctx context.Context, readErr error) (repoPreconditions, error) {
	if !hubclient.IsNotFound(readErr) {
		if readErr != nil {
			return repoPreconditions{}, readErr
		}
		return repoPreconditions{}, errors.New("operation target already exists")
	}
	identity, err := a.client.WhoAmI(ctx)
	if err != nil {
		return repoPreconditions{}, err
	}
	return repoPreconditions{Absent: true, CredentialIdentity: identity.Name}, nil
}

func (a *repositoryAdapter) checkPreconditions(ctx context.Context, target repositoryTarget, expected repoPreconditions) error {
	body, err := a.readRepository(ctx, target)
	if expected.Absent {
		return a.checkAbsentPreconditions(ctx, expected, err)
	}
	if err != nil || expected.ObservedDigest == "" || digest(body) != expected.ObservedDigest {
		if err != nil {
			return err
		}
		return errors.New("operation_precondition_failed")
	}
	return nil
}

func (a *repositoryAdapter) checkAbsentPreconditions(ctx context.Context, expected repoPreconditions, readErr error) error {
	if err := a.checkCredentialIdentity(ctx, expected.CredentialIdentity); err != nil {
		return err
	}
	if hubclient.IsNotFound(readErr) {
		return nil
	}
	if readErr != nil {
		return readErr
	}
	return errors.New("operation_precondition_failed")
}

func (a *repositoryAdapter) checkCredentialIdentity(ctx context.Context, expected string) error {
	identity, err := a.client.WhoAmI(ctx)
	if err != nil {
		return err
	}
	if identity.Name != expected {
		return errors.New("operation_precondition_failed")
	}
	return nil
}

func (a *repositoryAdapter) readRepository(ctx context.Context, target repositoryTarget) (json.RawMessage, error) {
	response, err := a.client.RepoInfo(ctx, target.repoRef())
	if err != nil {
		return nil, err
	}
	return canonical(response)
}

func (a *repositoryAdapter) presentationAndPolicy(target repositoryTarget, raw json.RawMessage) (agentv1.Presentation, hfpolicy.Request, error) {
	policyTarget := hfpolicy.Target{Kind: hfpolicy.KindRepo, Type: hfpolicy.RepoType(target.Type), Owner: target.Owner, Name: target.Name}
	request := hfpolicy.Request{Operation: hfpolicy.Operation(a.descriptor.Name), Target: policyTarget, Attrs: map[string]any{}}
	switch a.descriptor.Name {
	case "repo.create":
		var arguments repoCreateArguments
		if err := decodeClosed(raw, &arguments, maxArgumentsBytes); err != nil {
			return agentv1.Presentation{}, hfpolicy.Request{}, err
		}
		request.Attrs["visibility"] = arguments.Visibility
		if arguments.SDK != "" {
			request.Attrs["sdk"] = arguments.SDK
		}
		return agentv1.Presentation{Title: "Create Hugging Face repository", Summary: fmt.Sprintf("Create %s %s %s/%s", arguments.Visibility, target.Type, target.Owner, target.Name)}, request, nil
	case "repo.delete":
		return agentv1.Presentation{Title: "Delete Hugging Face repository", Summary: fmt.Sprintf("Permanently delete %s %s/%s", target.Type, target.Owner, target.Name)}, request, nil
	default:
		return agentv1.Presentation{}, hfpolicy.Request{}, errors.New("repository operation is not implemented")
	}
}

func validRepositoryTarget(target repositoryTarget) bool {
	return target.Kind == "repo" && repoSegment.MatchString(target.Owner) && repoSegment.MatchString(target.Name) &&
		(target.Type == "model" || target.Type == "dataset" || target.Type == "space" || target.Type == "kernel")
}

func validRepoCreateArguments(target repositoryTarget, arguments repoCreateArguments) bool {
	if arguments.Visibility != "public" && arguments.Visibility != "private" {
		return false
	}
	if target.Type == "space" {
		return arguments.SDK == "docker" || arguments.SDK == "gradio" || arguments.SDK == "static"
	}
	return arguments.SDK == ""
}

func repoCreationMatches(target repositoryTarget, arguments repoCreateArguments, info hubclient.RepoInfo) bool {
	if info.ID != target.Owner+"/"+target.Name || info.Private != (arguments.Visibility == "private") {
		return false
	}
	return target.Type != "space" || info.SDK == arguments.SDK
}

func (target repositoryTarget) repoRef() hubclient.RepoRef {
	return hubclient.RepoRef{Type: hubclient.RepoType(target.Type), Owner: target.Owner, Name: target.Name}
}

func (a *repositoryAdapter) repoURL(target repositoryTarget) string {
	prefix := ""
	if target.Type != "model" {
		prefix = target.Type + "s/"
	}
	return a.endpoint + "/" + prefix + target.Owner + "/" + target.Name
}

func digest(value []byte) string {
	sum := sha256.Sum256(value)
	return hex.EncodeToString(sum[:])
}
