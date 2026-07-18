package operations

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"unicode/utf8"

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
	authorize  RepositoryAuthorization
}

// RepositoryAuthorization applies one authenticated client's policy to a
// concrete repository operation returned by an upstream read.
type RepositoryAuthorization func(client string, operation hfpolicy.Operation, target hfpolicy.Target) bool

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

func NewRepositoryReadAdapters(client repositoryReadClient, authorize RepositoryAuthorization) ([]Adapter, error) {
	if client == nil || authorize == nil {
		return nil, errors.New("hugging face repository read client is required")
	}
	return adaptersForNames([]string{"repo.contents.read", "repo.list", "repo.metadata.read", "repo.tree.list"}, func(descriptor opcatalog.Descriptor) Adapter {
		return &repositoryReadAdapter{descriptor: descriptor, client: client, authorize: authorize}
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
		return decodeRepoListArguments(raw)
	case "repo.tree.list":
		arguments, err := decodeValidated(raw, maxArgumentsBytes, validRepoTreeArguments, "repository tree arguments are invalid")
		arguments.Revision = defaultRevision(arguments.Revision)
		return arguments, err
	case "repo.contents.read":
		return decodeRepoContentsArguments(raw)
	default:
		return nil, errors.New("repository read operation is not implemented")
	}
}

func decodeRepoListArguments(raw json.RawMessage) (repoListArguments, error) {
	arguments, err := decodeValidated(raw, maxArgumentsBytes, func(value repoListArguments) bool {
		return value.Limit >= 0 && value.Limit <= 100
	}, "repository list arguments are invalid")
	if arguments.Limit == 0 {
		arguments.Limit = 100
	}
	return arguments, err
}

func decodeRepoContentsArguments(raw json.RawMessage) (repoContentsArguments, error) {
	arguments, err := decodeValidated(raw, maxArgumentsBytes, validRepoContentsArguments, "repository content arguments are invalid")
	arguments.Revision = defaultRevision(arguments.Revision)
	return arguments, err
}

func defaultRevision(revision string) string {
	if revision == "" {
		return "main"
	}
	return revision
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
	return authorizeReconstructed(plan, a.reconstruct(plan))
}

func (a *repositoryReadAdapter) Present(plan Plan) agentv1.Presentation {
	return presentReconstructed(plan, a.reconstruct(plan))
}

func (a *repositoryReadAdapter) reconstruct(plan Plan) reconstructedPlan {
	return reconstructPlan(plan.Target, plan.Arguments, decodeRepositoryOperationTarget, a.presentationAndPolicy)
}

func (a *repositoryReadAdapter) presentationAndPolicy(target repositoryTarget, raw json.RawMessage) (agentv1.Presentation, hfpolicy.Request) {
	request := hfpolicy.Request{Operation: hfpolicy.Operation(a.descriptor.Name), Target: target.policyTarget()}
	summary := fmt.Sprintf("Read %s %s/%s", target.Type, target.Owner, target.Name)
	switch a.descriptor.Name {
	case "repo.contents.read":
		var arguments repoContentsArguments
		if decodeClosed(raw, &arguments, maxArgumentsBytes) == nil {
			request.Target.Paths = []string{arguments.Path}
			summary = fmt.Sprintf("Read %s from %s/%s", arguments.Path, target.Owner, target.Name)
		}
	case "repo.tree.list":
		var arguments repoTreeArguments
		if decodeClosed(raw, &arguments, maxArgumentsBytes) == nil && arguments.Path != "" {
			request.Target.Paths = []string{arguments.Path}
			summary = fmt.Sprintf("List %s in %s/%s", arguments.Path, target.Owner, target.Name)
		}
	}
	return agentv1.Presentation{Title: "Read Hugging Face repository", Summary: summary}, request
}

func (a *repositoryReadAdapter) Execute(ctx context.Context, plan Plan) (Outcome, error) {
	target, err := decodeRepositoryOperationTarget(plan.Target)
	if err != nil {
		return Outcome{}, err
	}
	result, err := a.executeResult(ctx, plan, target)
	if err != nil {
		return Outcome{}, err
	}
	encoded, err := canonical(result)
	return Outcome{Proven: true, Result: encoded}, err
}

func (a *repositoryReadAdapter) executeResult(ctx context.Context, plan Plan, target repositoryTarget) (any, error) {
	switch a.descriptor.Name {
	case "repo.metadata.read":
		return a.readMetadata(ctx, target)
	case "repo.list":
		return a.readList(ctx, plan, target)
	case "repo.tree.list":
		return a.readTree(ctx, plan, target)
	case "repo.contents.read":
		return a.readContent(ctx, plan, target)
	default:
		return nil, errors.New("repository read operation is not implemented")
	}
}

func (a *repositoryReadAdapter) readMetadata(ctx context.Context, target repositoryTarget) (any, error) {
	info, err := a.client.RepoInfo(ctx, target.repoRef())
	return map[string]any{"id": info.ID, "sha": info.SHA, "private": info.Private, "gated": info.Gated, "sdk": info.SDK}, err
}

func (a *repositoryReadAdapter) readList(ctx context.Context, plan Plan, target repositoryTarget) (any, error) {
	var arguments repoListArguments
	if decodeClosed(plan.Arguments, &arguments, maxArgumentsBytes) != nil {
		return nil, errors.New("repository list plan is invalid")
	}
	var repos []hubclient.RepoSummary
	var err error
	if target.Name == "*" {
		repos, err = a.client.ListRepos(ctx, hubclient.RepoType(target.Type), target.Owner, 100)
	} else {
		var info hubclient.RepoInfo
		info, err = a.client.RepoInfo(ctx, target.repoRef())
		repos = []hubclient.RepoSummary{{ID: info.ID, SHA: info.SHA, Private: info.Private}}
	}
	if err != nil {
		return nil, err
	}
	return a.repoListResult(repos, target, plan.Policy.Client, arguments.Limit), nil
}

func (a *repositoryReadAdapter) readTree(ctx context.Context, plan Plan, target repositoryTarget) (any, error) {
	var arguments repoTreeArguments
	if decodeClosed(plan.Arguments, &arguments, maxArgumentsBytes) != nil {
		return nil, errors.New("repository tree plan is invalid")
	}
	entries, err := a.client.RepoTree(ctx, target.repoRef(), arguments.Revision, arguments.Path, arguments.Recursive)
	if err != nil {
		return nil, err
	}
	return a.filterTree(entries, target, plan.Policy.Client), nil
}

func (a *repositoryReadAdapter) readContent(ctx context.Context, plan Plan, target repositoryTarget) (any, error) {
	var arguments repoContentsArguments
	if decodeClosed(plan.Arguments, &arguments, maxArgumentsBytes) != nil {
		return nil, errors.New("repository content plan is invalid")
	}
	file, err := a.client.RepoFile(ctx, target.repoRef(), arguments.Revision, arguments.Path)
	if err != nil {
		return nil, err
	}
	encoding, content := "base64", base64.StdEncoding.EncodeToString(file.Content)
	if utf8.Valid(file.Content) {
		encoding, content = "utf-8", string(file.Content)
	}
	return map[string]any{"path": arguments.Path, "revision": arguments.Revision, "encoding": encoding,
		"content": content, "content_type": file.ContentType, "commit": file.Commit}, nil
}

func (a *repositoryReadAdapter) repoListResult(repos []hubclient.RepoSummary, query repositoryTarget, client string, limit int) map[string]any {
	result := make([]hubclient.RepoSummary, 0, len(repos))
	for _, repo := range repos {
		summary, ok := a.disclosedRepoSummary(repo, query, client)
		if !ok {
			continue
		}
		result = append(result, summary)
		if len(result) == limit {
			break
		}
	}
	return map[string]any{"repos": result, "next_cursor": nil}
}

func (a *repositoryReadAdapter) disclosedRepoSummary(repo hubclient.RepoSummary, query repositoryTarget, client string) (hubclient.RepoSummary, bool) {
	target, ok := listedRepoTarget(repo.ID, query)
	if !ok || !a.authorize(client, hfpolicy.OpRepoList, target) || !a.authorize(client, hfpolicy.OpRepoMetadataRead, target) {
		return hubclient.RepoSummary{}, false
	}
	return hubclient.RepoSummary{ID: repo.ID, SHA: repo.SHA}, true
}

func listedRepoTarget(id string, query repositoryTarget) (hfpolicy.Target, bool) {
	parts := strings.Split(id, "/")
	if len(parts) != 2 || parts[0] != query.Owner || (query.Name != "*" && parts[1] != query.Name) {
		return hfpolicy.Target{}, false
	}
	return hfpolicy.Target{Kind: hfpolicy.KindRepo, Type: hfpolicy.RepoType(query.Type), Owner: parts[0], Name: parts[1]}, true
}

func (a *repositoryReadAdapter) filterTree(entries []hubclient.RepoTreeEntry, target repositoryTarget, client string) []hubclient.RepoTreeEntry {
	result := make([]hubclient.RepoTreeEntry, 0, len(entries))
	for _, entry := range entries {
		policyTarget := target.policyTarget()
		policyTarget.Paths = []string{entry.Path}
		if a.authorize(client, hfpolicy.OpRepoTreeList, policyTarget) {
			result = append(result, entry)
		}
	}
	return result
}

func (a *repositoryReadAdapter) Reconcile(ctx context.Context, plan Plan) (Outcome, error) {
	return a.Execute(ctx, plan)
}

func (target repositoryTarget) policyTarget() hfpolicy.Target {
	return hfpolicy.Target{Kind: hfpolicy.KindRepo, Type: hfpolicy.RepoType(target.Type), Owner: target.Owner, Name: target.Name}
}
