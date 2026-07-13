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

	"github.com/osolmaz/brokerkit/agentv1"
	"github.com/osolmaz/brokerkit/brokers/huggingface/internal/hubclient"
	"github.com/osolmaz/brokerkit/brokers/huggingface/internal/opcatalog"
	hfpolicy "github.com/osolmaz/brokerkit/brokers/huggingface/internal/policy"
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
		return nil, errors.New("Hugging Face Hub client is required")
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
	var target repositoryTarget
	if err := decodeClosed(targetRaw, &target, maxTargetBytes); err != nil || !validRepositoryTarget(target) {
		return Input{}, errors.New("repository target must contain an exact kind, type, owner, and name")
	}
	canonicalTarget, _ := canonical(target)
	switch a.descriptor.Name {
	case "repo.create":
		var arguments repoCreateArguments
		if err := decodeClosed(argumentsRaw, &arguments, maxArgumentsBytes); err != nil || !validRepoCreateArguments(target, arguments) {
			return Input{}, errors.New("repository creation arguments are invalid")
		}
		canonicalArguments, _ := canonical(arguments)
		return Input{Target: canonicalTarget, Arguments: canonicalArguments}, nil
	case "repo.delete":
		var arguments emptyArguments
		if err := decodeClosed(argumentsRaw, &arguments, maxArgumentsBytes); err != nil {
			return Input{}, errors.New("repository deletion arguments must be empty")
		}
		return Input{Target: canonicalTarget, Arguments: json.RawMessage(`{}`)}, nil
	default:
		return Input{}, errors.New("repository operation is not implemented")
	}
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
	if plan.Policy.Operation != "" {
		return plan.Policy
	}
	var target repositoryTarget
	if decodeClosed(plan.Target, &target, maxTargetBytes) != nil {
		return hfpolicy.Request{}
	}
	_, request, _ := a.presentationAndPolicy(target, plan.Arguments)
	return request
}

func (a *repositoryAdapter) Present(plan Plan) agentv1.Presentation {
	if plan.Presentation.Title != "" {
		return plan.Presentation
	}
	var target repositoryTarget
	if decodeClosed(plan.Target, &target, maxTargetBytes) != nil {
		return agentv1.Presentation{}
	}
	presentation, _, _ := a.presentationAndPolicy(target, plan.Arguments)
	return presentation
}

func (a *repositoryAdapter) Execute(ctx context.Context, plan Plan) (Outcome, error) {
	var target repositoryTarget
	var preconditions repoPreconditions
	if decodeClosed(plan.Target, &target, maxTargetBytes) != nil || decodeClosed(plan.Preconditions, &preconditions, maxTargetBytes) != nil {
		return Outcome{}, errors.New("operation plan is invalid")
	}
	if err := a.checkPreconditions(ctx, target, preconditions); err != nil {
		return Outcome{}, err
	}
	switch a.descriptor.Name {
	case "repo.create":
		var arguments repoCreateArguments
		if decodeClosed(plan.Arguments, &arguments, maxArgumentsBytes) != nil {
			return Outcome{}, errors.New("operation plan arguments are invalid")
		}
		if _, err := a.client.CreateRepo(ctx, hubclient.CreateRepoInput{Ref: target.repoRef(), Visibility: hubclient.Visibility(arguments.Visibility), SpaceSDK: arguments.SDK, PersonalNamespace: preconditions.CredentialIdentity == target.Owner}); err != nil {
			return Outcome{}, err
		}
		result, err := canonical(map[string]any{"repo_id": target.Owner + "/" + target.Name, "url": a.repoURL(target)})
		return Outcome{Result: result}, err
	case "repo.delete":
		if err := a.client.DeleteRepo(ctx, target.repoRef()); err != nil {
			return Outcome{}, err
		}
		return Outcome{Result: json.RawMessage(`{"deleted":true}`)}, nil
	default:
		return Outcome{}, errors.New("repository operation is not implemented")
	}
}

func (a *repositoryAdapter) Reconcile(ctx context.Context, plan Plan) (Outcome, error) {
	var target repositoryTarget
	if err := decodeClosed(plan.Target, &target, maxTargetBytes); err != nil {
		return Outcome{}, err
	}
	_, err := a.readRepository(ctx, target)
	switch a.descriptor.Name {
	case "repo.create":
		if err != nil {
			return Outcome{}, err
		}
		result, _ := canonical(map[string]any{"repo_id": target.Owner + "/" + target.Name, "url": a.repoURL(target)})
		return Outcome{Proven: true, Result: result}, nil
	case "repo.delete":
		var upstream *hubclient.Error
		if errors.As(err, &upstream) && upstream.Code == hubclient.CodeNotFound {
			return Outcome{Proven: true, Result: json.RawMessage(`{"deleted":true}`)}, nil
		}
		if err != nil {
			return Outcome{}, err
		}
		return Outcome{Proven: false}, nil
	default:
		return Outcome{}, errors.New("repository operation is not implemented")
	}
}

func (a *repositoryAdapter) resolvePreconditions(ctx context.Context, target repositoryTarget) (repoPreconditions, error) {
	body, err := a.readRepository(ctx, target)
	var upstream *hubclient.Error
	if a.descriptor.Name == "repo.create" {
		if errors.As(err, &upstream) && upstream.Code == hubclient.CodeNotFound {
			identity, identityErr := a.client.WhoAmI(ctx)
			if identityErr != nil {
				return repoPreconditions{}, identityErr
			}
			return repoPreconditions{Absent: true, CredentialIdentity: identity.Name}, nil
		}
		if err != nil {
			return repoPreconditions{}, err
		}
		return repoPreconditions{}, errors.New("operation target already exists")
	}
	if err != nil {
		return repoPreconditions{}, err
	}
	return repoPreconditions{ObservedDigest: digest(body)}, nil
}

func (a *repositoryAdapter) checkPreconditions(ctx context.Context, target repositoryTarget, expected repoPreconditions) error {
	body, err := a.readRepository(ctx, target)
	var upstream *hubclient.Error
	if expected.Absent {
		identity, identityErr := a.client.WhoAmI(ctx)
		if identityErr != nil || identity.Name != expected.CredentialIdentity {
			if identityErr != nil {
				return identityErr
			}
			return errors.New("operation_precondition_failed")
		}
		if errors.As(err, &upstream) && upstream.Code == hubclient.CodeNotFound {
			return nil
		}
		if err != nil {
			return err
		}
		return errors.New("operation_precondition_failed")
	}
	if err != nil || expected.ObservedDigest == "" || digest(body) != expected.ObservedDigest {
		if err != nil {
			return err
		}
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
		request.Attrs["sdk"] = arguments.SDK
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
	if arguments.Visibility != "public" && arguments.Visibility != "private" && !(target.Type == "space" && arguments.Visibility == "protected") {
		return false
	}
	if target.Type == "space" {
		return arguments.SDK == "docker" || arguments.SDK == "gradio" || arguments.SDK == "static"
	}
	return arguments.SDK == ""
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
