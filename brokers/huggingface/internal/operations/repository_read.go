package operations

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	"github.com/osolmaz/brokerkit/agentv1"
	"github.com/osolmaz/brokerkit/brokers/huggingface/internal/hubclient"
	"github.com/osolmaz/brokerkit/brokers/huggingface/internal/opcatalog"
	hfpolicy "github.com/osolmaz/brokerkit/brokers/huggingface/internal/policy"
)

type repositoryReadClient interface {
	RepoInfo(context.Context, hubclient.RepoRef) (hubclient.RepoInfo, error)
	ListRepos(context.Context, hubclient.RepoType, string, int) ([]hubclient.RepoSummary, error)
	RepoTree(context.Context, hubclient.RepoRef, string, string, bool) ([]hubclient.RepoTreeEntry, error)
	RepoFile(context.Context, hubclient.RepoRef, string, string) (hubclient.RepoFile, error)
}

type repositoryReadAdapter struct {
	descriptor opcatalog.Descriptor
	client     repositoryReadClient
	disclose   RepositoryDisclosure
}

// RepositoryDisclosure applies one authenticated client's policy to a
// concrete repository returned by upstream discovery.
type RepositoryDisclosure func(client string, target hfpolicy.Target) bool

type repoListArguments struct {
	Limit int `json:"limit,omitempty"`
}

type repoTreeArguments struct {
	Revision  string `json:"revision,omitempty"`
	Path      string `json:"path,omitempty"`
	Recursive bool   `json:"recursive,omitempty"`
}

type repoContentsArguments struct {
	Revision string `json:"revision,omitempty"`
	Path     string `json:"path"`
}

func NewRepositoryReadAdapters(client repositoryReadClient, disclose RepositoryDisclosure) ([]Adapter, error) {
	if client == nil || disclose == nil {
		return nil, errors.New("hugging face repository read client is required")
	}
	return adaptersForNames([]string{"repo.contents.read", "repo.list", "repo.metadata.read", "repo.tree.list"}, func(descriptor opcatalog.Descriptor) Adapter {
		return &repositoryReadAdapter{descriptor: descriptor, client: client, disclose: disclose}
	})
}

func (a *repositoryReadAdapter) Descriptor() opcatalog.Descriptor { return a.descriptor }

func (a *repositoryReadAdapter) Decode(targetRaw, argumentsRaw json.RawMessage) (Input, error) {
	decodeTarget := decodeRepositoryInputTarget
	if a.descriptor.Name == "repo.list" {
		decodeTarget = decodeRepositoryListTarget
	}
	return decodeInput(targetRaw, argumentsRaw, decodeTarget, func(_ repositoryTarget, raw json.RawMessage) (any, error) {
		return a.decodeArguments(raw)
	})
}

func decodeRepositoryListTarget(raw json.RawMessage) (repositoryTarget, error) {
	return decodeValidated(raw, maxTargetBytes, func(target repositoryTarget) bool {
		return validRepositoryTarget(target) ||
			(target.Kind == "repo" && target.Name == "*" && repoSegment.MatchString(target.Owner) &&
				(target.Type == "model" || target.Type == "dataset" || target.Type == "space" || target.Type == "kernel"))
	}, "repository list target must contain an exact type and owner plus an exact name or *")
}

func (a *repositoryReadAdapter) decodeArguments(raw json.RawMessage) (any, error) {
	switch a.descriptor.Name {
	case "repo.metadata.read":
		return decodeEmptyArguments(raw, "repository metadata arguments must be empty")
	case "repo.list":
		arguments, err := decodeValidated(raw, maxArgumentsBytes, func(value repoListArguments) bool {
			return value.Limit >= 0 && value.Limit <= 100
		}, "repository list arguments are invalid")
		if arguments.Limit == 0 {
			arguments.Limit = 100
		}
		return arguments, err
	case "repo.tree.list":
		arguments, err := decodeValidated(raw, maxArgumentsBytes, validRepoTreeArguments, "repository tree arguments are invalid")
		if arguments.Revision == "" {
			arguments.Revision = "main"
		}
		return arguments, err
	case "repo.contents.read":
		arguments, err := decodeValidated(raw, maxArgumentsBytes, validRepoContentsArguments, "repository content arguments are invalid")
		if arguments.Revision == "" {
			arguments.Revision = "main"
		}
		return arguments, err
	default:
		return nil, errors.New("repository read operation is not implemented")
	}
}

func validRepoTreeArguments(value repoTreeArguments) bool {
	return (value.Revision == "" || hubclient.ValidGitRefComponent(value.Revision)) &&
		(value.Path == "" || hubclient.ValidRepoPath(value.Path+"/", true))
}

func validRepoContentsArguments(value repoContentsArguments) bool {
	return (value.Revision == "" || hubclient.ValidGitRefComponent(value.Revision)) && hubclient.ValidRepoPath(value.Path, false)
}

func (a *repositoryReadAdapter) Resolve(_ context.Context, input Input) (Plan, error) {
	target, err := decodeRepositoryOperationTarget(input.Target)
	if err != nil {
		return Plan{}, err
	}
	presentation, request := a.presentationAndPolicy(target, input.Arguments)
	return Plan{Operation: a.descriptor.Name, OperationRevision: a.descriptor.OperationRevision, Target: input.Target,
		Arguments: input.Arguments, Preconditions: json.RawMessage(`{}`), Presentation: presentation, Policy: request}, nil
}

func (a *repositoryReadAdapter) Authorize(plan Plan) hfpolicy.Request {
	target, err := decodeRepositoryOperationTarget(plan.Target)
	if err != nil {
		return hfpolicy.Request{}
	}
	_, request := a.presentationAndPolicy(target, plan.Arguments)
	return preferCached(plan.Policy, plan.Policy.Operation != "", request)
}

func (a *repositoryReadAdapter) Present(plan Plan) agentv1.Presentation {
	target, err := decodeRepositoryOperationTarget(plan.Target)
	if err != nil {
		return agentv1.Presentation{}
	}
	presentation, _ := a.presentationAndPolicy(target, plan.Arguments)
	return preferCached(plan.Presentation, plan.Presentation.Title != "", presentation)
}

func (a *repositoryReadAdapter) presentationAndPolicy(target repositoryTarget, raw json.RawMessage) (agentv1.Presentation, hfpolicy.Request) {
	request := hfpolicy.Request{Operation: hfpolicy.Operation(a.descriptor.Name), Target: target.policyTarget()}
	summary := fmt.Sprintf("Read %s %s/%s", target.Type, target.Owner, target.Name)
	if a.descriptor.Name == "repo.contents.read" {
		var arguments repoContentsArguments
		if decodeClosed(raw, &arguments, maxArgumentsBytes) == nil {
			request.Target.Paths = []string{arguments.Path}
			summary = fmt.Sprintf("Read %s from %s/%s", arguments.Path, target.Owner, target.Name)
		}
	}
	return agentv1.Presentation{Title: "Read Hugging Face repository", Summary: summary}, request
}

func (a *repositoryReadAdapter) Execute(ctx context.Context, plan Plan) (Outcome, error) {
	target, err := decodeRepositoryOperationTarget(plan.Target)
	if err != nil {
		return Outcome{}, err
	}
	var result any
	switch a.descriptor.Name {
	case "repo.metadata.read":
		info, readErr := a.client.RepoInfo(ctx, target.repoRef())
		err, result = readErr, map[string]any{"id": info.ID, "sha": info.SHA, "private": info.Private, "gated": info.Gated, "sdk": info.SDK}
	case "repo.list":
		var arguments repoListArguments
		if decodeClosed(plan.Arguments, &arguments, maxArgumentsBytes) != nil {
			return Outcome{}, errors.New("repository list plan is invalid")
		}
		var repos []hubclient.RepoSummary
		repos, err = a.client.ListRepos(ctx, hubclient.RepoType(target.Type), target.Owner, arguments.Limit)
		if err == nil {
			result = a.repoListResult(repos, target, plan.Policy.Client)
		}
	case "repo.tree.list":
		var arguments repoTreeArguments
		if decodeClosed(plan.Arguments, &arguments, maxArgumentsBytes) != nil {
			return Outcome{}, errors.New("repository tree plan is invalid")
		}
		result, err = a.client.RepoTree(ctx, target.repoRef(), arguments.Revision, arguments.Path, arguments.Recursive)
	case "repo.contents.read":
		var arguments repoContentsArguments
		if decodeClosed(plan.Arguments, &arguments, maxArgumentsBytes) != nil {
			return Outcome{}, errors.New("repository content plan is invalid")
		}
		var file hubclient.RepoFile
		file, err = a.client.RepoFile(ctx, target.repoRef(), arguments.Revision, arguments.Path)
		if err == nil {
			result = map[string]any{"path": arguments.Path, "revision": arguments.Revision, "encoding": "base64",
				"content": base64.StdEncoding.EncodeToString(file.Content), "content_type": file.ContentType, "commit": file.Commit}
		}
	default:
		return Outcome{}, errors.New("repository read operation is not implemented")
	}
	if err != nil {
		return Outcome{}, err
	}
	encoded, err := canonical(result)
	return Outcome{Proven: true, Result: encoded}, err
}

func (a *repositoryReadAdapter) repoListResult(repos []hubclient.RepoSummary, query repositoryTarget, client string) map[string]any {
	result := make([]hubclient.RepoSummary, 0, len(repos))
	for _, repo := range repos {
		parts := strings.Split(repo.ID, "/")
		if len(parts) != 2 || parts[0] != query.Owner || (query.Name != "*" && parts[1] != query.Name) {
			continue
		}
		target := hfpolicy.Target{Kind: hfpolicy.KindRepo, Type: hfpolicy.RepoType(query.Type), Owner: parts[0], Name: parts[1]}
		if a.disclose(client, target) {
			result = append(result, repo)
		}
	}
	return map[string]any{"repos": result, "next_cursor": nil}
}

func (a *repositoryReadAdapter) Reconcile(ctx context.Context, plan Plan) (Outcome, error) {
	return a.Execute(ctx, plan)
}

func (target repositoryTarget) policyTarget() hfpolicy.Target {
	return hfpolicy.Target{Kind: hfpolicy.KindRepo, Type: hfpolicy.RepoType(target.Type), Owner: target.Owner, Name: target.Name}
}
