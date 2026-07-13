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

const maxInlineCommitContent = 700 * 1024

type repositoryContentClient interface {
	WhoAmI(context.Context) (hubclient.Identity, error)
	RepoInfoRevision(context.Context, hubclient.RepoRef, string) (hubclient.RepoInfo, error)
	RepoPathsInfo(context.Context, hubclient.RepoRef, string, []string) ([]hubclient.RepoPathInfo, error)
	ReadRepoFile(context.Context, hubclient.RepoRef, string, string) ([]byte, error)
	DuplicateLFSFile(context.Context, hubclient.RepoRef, hubclient.RepoRef, hubclient.RepoPathInfo) error
	CreateCommit(context.Context, hubclient.CommitRequest) (hubclient.CommitResult, error)
}

type repositoryContentAdapter struct {
	descriptor opcatalog.Descriptor
	client     repositoryContentClient
}

type repositoryContentTarget struct {
	Kind     string `json:"kind"`
	Type     string `json:"type"`
	Owner    string `json:"owner"`
	Name     string `json:"name"`
	Revision string `json:"revision"`
}

type normalizedCommitOperation struct {
	Kind          string  `json:"kind"`
	Path          string  `json:"path"`
	ContentBase64 *string `json:"content_base64,omitempty"`
	OID           *string `json:"oid,omitempty"`
	Size          *int64  `json:"size,omitempty"`
}

type commitCreateArguments struct {
	Summary      string                      `json:"summary"`
	Description  string                      `json:"description,omitempty"`
	ParentCommit string                      `json:"parent_commit,omitempty"`
	CreatePR     bool                        `json:"create_pr,omitempty"`
	Operations   []normalizedCommitOperation `json:"operations"`
}

type fileUploadArguments struct {
	Path          string  `json:"path"`
	ContentBase64 *string `json:"content_base64,omitempty"`
	OID           *string `json:"oid,omitempty"`
	Size          *int64  `json:"size,omitempty"`
	Summary       string  `json:"summary"`
	Description   string  `json:"description,omitempty"`
	ParentCommit  string  `json:"parent_commit,omitempty"`
	CreatePR      bool    `json:"create_pr,omitempty"`
}

type fileDeleteArguments struct {
	Path         string `json:"path"`
	Folder       bool   `json:"folder,omitempty"`
	Summary      string `json:"summary"`
	Description  string `json:"description,omitempty"`
	ParentCommit string `json:"parent_commit,omitempty"`
	CreatePR     bool   `json:"create_pr,omitempty"`
}

type fileCopyArguments struct {
	SourceType     string `json:"source_type"`
	SourceOwner    string `json:"source_owner"`
	SourceName     string `json:"source_name"`
	SourceRevision string `json:"source_revision"`
	SourcePath     string `json:"source_path"`
	Path           string `json:"path"`
	Summary        string `json:"summary"`
	Description    string `json:"description,omitempty"`
	ParentCommit   string `json:"parent_commit,omitempty"`
	CreatePR       bool   `json:"create_pr,omitempty"`
}

func (a fileUploadArguments) repositoryPath() string { return a.Path }
func (a fileDeleteArguments) repositoryPath() string { return a.Path }
func (a fileCopyArguments) repositoryPath() string   { return a.Path }

type contentPreconditions struct {
	CredentialIdentity string                  `json:"credential_identity"`
	TargetDigest       string                  `json:"target_digest"`
	Source             *contentSourceCondition `json:"source,omitempty"`
}

type contentSourceCondition struct {
	Type     string                 `json:"type"`
	Owner    string                 `json:"owner"`
	Name     string                 `json:"name"`
	Revision string                 `json:"revision"`
	Path     string                 `json:"path"`
	Info     hubclient.RepoPathInfo `json:"info"`
}

func NewRepositoryContentAdapters(client repositoryContentClient) ([]Adapter, error) {
	if client == nil {
		return nil, errors.New("hugging face repository content client is required")
	}
	names := []string{"repo.commit.create", "repo.file.copy", "repo.file.delete", "repo.file.upload", "space.hot_reload.apply"}
	adapters := make([]Adapter, 0, len(names))
	for _, name := range names {
		descriptor, found := opcatalog.ByName(name)
		if !found {
			return nil, fmt.Errorf("operation %q is absent from the catalog", name)
		}
		adapters = append(adapters, &repositoryContentAdapter{descriptor: descriptor, client: client})
	}
	return adapters, nil
}

func (a *repositoryContentAdapter) Descriptor() opcatalog.Descriptor { return a.descriptor }

func (a *repositoryContentAdapter) Decode(targetRaw, argumentsRaw json.RawMessage) (Input, error) {
	var target repositoryContentTarget
	if err := decodeClosed(targetRaw, &target, maxTargetBytes); err != nil || !validContentTarget(target, a.descriptor.Name) {
		return Input{}, errors.New("repository content target is invalid")
	}
	arguments, err := a.decodeArguments(argumentsRaw)
	if err != nil {
		return Input{}, err
	}
	canonicalTarget, _ := canonical(target)
	canonicalArguments, _ := canonical(arguments)
	return Input{Target: canonicalTarget, Arguments: canonicalArguments}, nil
}

//nolint:cyclop // Content-operation decoding is explicit and tracked by the exact HF CRAP baseline.
func (a *repositoryContentAdapter) decodeArguments(raw json.RawMessage) (any, error) {
	switch a.descriptor.Name {
	case "repo.commit.create", "space.hot_reload.apply":
		var value commitCreateArguments
		if err := decodeClosed(raw, &value, maxArgumentsBytes); err != nil || validateCommitMetadata(value.Summary, value.Description, value.ParentCommit) != nil {
			return nil, errors.New("commit arguments are invalid")
		}
		operations, err := normalizeCommitOperations(value.Operations)
		if err != nil {
			return nil, err
		}
		value.Operations = operations
		return value, nil
	case "repo.file.upload":
		var value fileUploadArguments
		if err := decodeClosed(raw, &value, maxArgumentsBytes); err != nil || validateCommitMetadata(value.Summary, value.Description, value.ParentCommit) != nil {
			return nil, errors.New("file upload arguments are invalid")
		}
		operation := normalizedCommitOperation{Kind: "file", Path: value.Path, ContentBase64: value.ContentBase64, OID: value.OID, Size: value.Size}
		if value.OID != nil || value.Size != nil {
			operation.Kind = "lfs_file"
		}
		normalized, err := normalizeCommitOperations([]normalizedCommitOperation{operation})
		if err != nil {
			return nil, err
		}
		value.Path, value.ContentBase64, value.OID, value.Size = normalized[0].Path, normalized[0].ContentBase64, normalized[0].OID, normalized[0].Size
		return value, nil
	case "repo.file.delete":
		var value fileDeleteArguments
		if err := decodeClosed(raw, &value, maxArgumentsBytes); err != nil || validateCommitMetadata(value.Summary, value.Description, value.ParentCommit) != nil {
			return nil, errors.New("file deletion arguments are invalid")
		}
		kind := "deleted_file"
		if value.Folder {
			kind = "deleted_folder"
		}
		if _, err := normalizeCommitOperations([]normalizedCommitOperation{{Kind: kind, Path: value.Path}}); err != nil {
			return nil, err
		}
		return value, nil
	case "repo.file.copy":
		var value fileCopyArguments
		if err := decodeClosed(raw, &value, maxArgumentsBytes); err != nil || validateCopyArguments(value) != nil {
			return nil, errors.New("file copy arguments are invalid")
		}
		return value, nil
	default:
		return nil, errors.New("repository content operation is not implemented")
	}
}

func (a *repositoryContentAdapter) Resolve(ctx context.Context, input Input) (Plan, error) {
	target, err := a.decodeTarget(input.Target)
	if err != nil {
		return Plan{}, err
	}
	identity, err := a.client.WhoAmI(ctx)
	if err != nil {
		return Plan{}, err
	}
	info, err := a.client.RepoInfoRevision(ctx, target.ref(), target.Revision)
	if err != nil {
		return Plan{}, err
	}
	preconditions := contentPreconditions{CredentialIdentity: identity.Name, TargetDigest: repoInfoDigest(info)}
	if a.descriptor.Name == "repo.file.copy" {
		var arguments fileCopyArguments
		if err := decodeClosed(input.Arguments, &arguments, maxArgumentsBytes); err != nil {
			return Plan{}, err
		}
		sourceRef := hubclient.RepoRef{Type: hubclient.RepoType(arguments.SourceType), Owner: arguments.SourceOwner, Name: arguments.SourceName}
		paths, pathsErr := a.client.RepoPathsInfo(ctx, sourceRef, arguments.SourceRevision, []string{arguments.SourcePath})
		if pathsErr != nil {
			return Plan{}, pathsErr
		}
		if len(paths) != 1 || paths[0].Path != arguments.SourcePath || paths[0].Type != "file" {
			return Plan{}, errors.New("copy source file does not exist")
		}
		preconditions.Source = &contentSourceCondition{Type: arguments.SourceType, Owner: arguments.SourceOwner, Name: arguments.SourceName, Revision: arguments.SourceRevision, Path: arguments.SourcePath, Info: paths[0]}
	}
	encoded, _ := canonical(preconditions)
	presentation, request := a.presentationAndPolicy(target, input.Arguments)
	return Plan{Operation: a.descriptor.Name, OperationRevision: a.descriptor.OperationRevision, Target: input.Target,
		Arguments: input.Arguments, Preconditions: encoded, Presentation: presentation, Policy: request}, nil
}

func (a *repositoryContentAdapter) Authorize(plan Plan) hfpolicy.Request {
	return authorizeReconstructed(plan, reconstructPlan(plan.Target, plan.Arguments, a.decodeTarget, a.presentationAndPolicy))
}

func (a *repositoryContentAdapter) Present(plan Plan) agentv1.Presentation {
	return presentReconstructed(plan, reconstructPlan(plan.Target, plan.Arguments, a.decodeTarget, a.presentationAndPolicy))
}

func (a *repositoryContentAdapter) Execute(ctx context.Context, plan Plan) (Outcome, error) {
	target, preconditions, err := a.decodePlan(plan)
	if err != nil {
		return Outcome{}, err
	}
	if err := a.checkPreconditions(ctx, target, preconditions); err != nil {
		return Outcome{}, err
	}
	request, err := a.commitRequest(ctx, target, plan.Arguments, preconditions)
	if err != nil {
		return Outcome{}, err
	}
	result, err := a.client.CreateCommit(ctx, request)
	if err != nil {
		return Outcome{}, err
	}
	encoded, _ := canonical(result)
	return Outcome{Proven: true, Result: encoded}, nil
}

func (a *repositoryContentAdapter) Reconcile(context.Context, Plan) (Outcome, error) {
	return Outcome{Proven: false}, nil
}

func (a *repositoryContentAdapter) commitRequest(ctx context.Context, target repositoryContentTarget, raw json.RawMessage, preconditions contentPreconditions) (hubclient.CommitRequest, error) {
	request := hubclient.CommitRequest{Ref: target.ref(), Revision: target.Revision, HotReload: a.descriptor.Name == "space.hot_reload.apply"}
	switch a.descriptor.Name {
	case "repo.commit.create", "space.hot_reload.apply":
		var arguments commitCreateArguments
		if err := decodeClosed(raw, &arguments, maxArgumentsBytes); err != nil {
			return request, err
		}
		request.Summary, request.Description, request.ParentCommit, request.CreatePR = arguments.Summary, arguments.Description, arguments.ParentCommit, arguments.CreatePR
		request.Operations, _ = toCommitOperations(arguments.Operations)
	case "repo.file.upload":
		var arguments fileUploadArguments
		if err := decodeClosed(raw, &arguments, maxArgumentsBytes); err != nil {
			return request, err
		}
		operation := normalizedCommitOperation{Kind: "file", Path: arguments.Path, ContentBase64: arguments.ContentBase64, OID: arguments.OID, Size: arguments.Size}
		if arguments.OID != nil {
			operation.Kind = "lfs_file"
		}
		request.Summary, request.Description, request.ParentCommit, request.CreatePR = arguments.Summary, arguments.Description, arguments.ParentCommit, arguments.CreatePR
		request.Operations, _ = toCommitOperations([]normalizedCommitOperation{operation})
	case "repo.file.delete":
		var arguments fileDeleteArguments
		if err := decodeClosed(raw, &arguments, maxArgumentsBytes); err != nil {
			return request, err
		}
		kind := hubclient.CommitDeletedFile
		if arguments.Folder {
			kind = hubclient.CommitDeletedFolder
		}
		request.Summary, request.Description, request.ParentCommit, request.CreatePR = arguments.Summary, arguments.Description, arguments.ParentCommit, arguments.CreatePR
		request.Operations = []hubclient.CommitOperation{{Kind: kind, Path: arguments.Path}}
	case "repo.file.copy":
		return a.copyCommitRequest(ctx, request, raw, preconditions)
	}
	return request, nil
}

func (a *repositoryContentAdapter) copyCommitRequest(ctx context.Context, request hubclient.CommitRequest, raw json.RawMessage, preconditions contentPreconditions) (hubclient.CommitRequest, error) {
	var arguments fileCopyArguments
	if err := decodeClosed(raw, &arguments, maxArgumentsBytes); err != nil || preconditions.Source == nil {
		return request, errors.New("copy plan is invalid")
	}
	source := preconditions.Source
	sourceRef := hubclient.RepoRef{Type: hubclient.RepoType(source.Type), Owner: source.Owner, Name: source.Name}
	request.Summary, request.Description, request.ParentCommit, request.CreatePR = arguments.Summary, arguments.Description, arguments.ParentCommit, arguments.CreatePR
	if source.Info.LFSSHA != "" {
		if sourceRef != request.Ref {
			if err := a.client.DuplicateLFSFile(ctx, sourceRef, request.Ref, source.Info); err != nil {
				return request, err
			}
		}
		request.Operations = []hubclient.CommitOperation{{Kind: hubclient.CommitLFSFile, Path: arguments.Path, OID: source.Info.LFSSHA, Size: source.Info.Size}}
		return request, nil
	}
	content, err := a.client.ReadRepoFile(ctx, sourceRef, source.Revision, source.Path)
	if err != nil {
		return request, err
	}
	request.Operations = []hubclient.CommitOperation{{Kind: hubclient.CommitFile, Path: arguments.Path, Content: content}}
	return request, nil
}

func (a *repositoryContentAdapter) decodePlan(plan Plan) (repositoryContentTarget, contentPreconditions, error) {
	return decodePlanState(plan, a.decodeTarget, maxTargetBytes,
		func(value contentPreconditions) bool {
			return value.CredentialIdentity != "" && value.TargetDigest != ""
		},
		"operation plan preconditions are invalid")
}

func (a *repositoryContentAdapter) checkPreconditions(ctx context.Context, target repositoryContentTarget, expected contentPreconditions) error {
	identity, err := a.client.WhoAmI(ctx)
	if err != nil {
		return err
	}
	info, err := a.client.RepoInfoRevision(ctx, target.ref(), target.Revision)
	if err != nil {
		return err
	}
	if identity.Name != expected.CredentialIdentity || repoInfoDigest(info) != expected.TargetDigest {
		return errors.New("operation_precondition_failed")
	}
	if expected.Source != nil {
		source := expected.Source
		ref := hubclient.RepoRef{Type: hubclient.RepoType(source.Type), Owner: source.Owner, Name: source.Name}
		paths, pathsErr := a.client.RepoPathsInfo(ctx, ref, source.Revision, []string{source.Path})
		if pathsErr != nil {
			return pathsErr
		}
		if len(paths) != 1 || paths[0] != source.Info {
			return errors.New("operation_precondition_failed")
		}
	}
	return nil
}

func (a *repositoryContentAdapter) presentationAndPolicy(target repositoryContentTarget, raw json.RawMessage) (agentv1.Presentation, hfpolicy.Request) {
	request := hfpolicy.Request{Operation: hfpolicy.Operation(a.descriptor.Name), Target: hfpolicy.Target{
		Kind: hfpolicy.KindRepo, Type: hfpolicy.RepoType(target.Type), Owner: target.Owner, Name: target.Name,
		Refs: []string{target.Revision}, Paths: repositoryContentPaths(a.descriptor.Name, raw),
	}, Attrs: map[string]any{}}
	summary := fmt.Sprintf("%s on %s %s/%s at %s", a.descriptor.Name, target.Type, target.Owner, target.Name, target.Revision)
	if a.descriptor.Name == "repo.file.copy" {
		var arguments fileCopyArguments
		if decodeClosed(raw, &arguments, maxArgumentsBytes) == nil {
			request.Attrs["source"] = arguments.SourceType + "/" + arguments.SourceOwner + "/" + arguments.SourceName
			request.Attrs["source_ref"] = arguments.SourceRevision
			request.Attrs["source_path"] = arguments.SourcePath
		}
	}
	return agentv1.Presentation{Title: a.descriptor.Name, Summary: summary}, request
}

func repositoryContentPaths(operation string, raw json.RawMessage) []string {
	extract, found := repositoryPathExtractors[operation]
	if !found {
		return nil
	}
	return extract(raw)
}

var repositoryPathExtractors = map[string]func(json.RawMessage) []string{
	"repo.commit.create":     commitOperationPaths,
	"space.hot_reload.apply": commitOperationPaths,
	"repo.file.upload":       oneRepositoryPath[fileUploadArguments],
	"repo.file.delete":       oneRepositoryPath[fileDeleteArguments],
	"repo.file.copy":         oneRepositoryPath[fileCopyArguments],
}

func commitOperationPaths(raw json.RawMessage) []string {
	var arguments commitCreateArguments
	if decodeClosed(raw, &arguments, maxArgumentsBytes) != nil {
		return nil
	}
	paths := make([]string, len(arguments.Operations))
	for index := range arguments.Operations {
		paths[index] = arguments.Operations[index].Path
	}
	return paths
}

func oneRepositoryPath[T interface{ repositoryPath() string }](raw json.RawMessage) []string {
	var arguments T
	if decodeClosed(raw, &arguments, maxArgumentsBytes) != nil {
		return nil
	}
	return []string{arguments.repositoryPath()}
}

func (a *repositoryContentAdapter) decodeTarget(raw json.RawMessage) (repositoryContentTarget, error) {
	var target repositoryContentTarget
	if err := decodeClosed(raw, &target, maxTargetBytes); err != nil || !validContentTarget(target, a.descriptor.Name) {
		return repositoryContentTarget{}, errors.New("repository content target is invalid")
	}
	return target, nil
}

func validContentTarget(target repositoryContentTarget, operation string) bool {
	expectedKind := "repo"
	if operation == "space.hot_reload.apply" {
		expectedKind = "space"
	}
	if target.Kind != expectedKind || target.ref().Validate() != nil || !hubclient.ValidGitRefComponent(target.Revision) {
		return false
	}
	return operation != "space.hot_reload.apply" || target.Type == "space"
}

func validateCommitMetadata(summary, description, parent string) error {
	if strings.TrimSpace(summary) == "" || len(summary) > 500 || len(description) > 10_000 || !validCommitParent(parent) {
		return errors.New("commit metadata is invalid")
	}
	return nil
}

func validCommitParent(value string) bool {
	if value == "" {
		return true
	}
	if len(value) < 7 || len(value) > 64 {
		return false
	}
	for _, char := range value {
		if !strings.ContainsRune("0123456789abcdefABCDEF", char) {
			return false
		}
	}
	return true
}

func normalizeCommitOperations(values []normalizedCommitOperation) ([]normalizedCommitOperation, error) {
	operations, err := toCommitOperations(values)
	if err != nil || hubclient.ValidateCommitOperations(operations) != nil {
		return nil, errors.New("commit operations are invalid")
	}
	normalized := values
	for len(operations) > 0 && len(values) > 0 {
		operation, value := operations[0], &values[0]
		value.Kind = string(operation.Kind)
		if operation.Kind == hubclient.CommitFile {
			encoded := base64.StdEncoding.EncodeToString(operation.Content)
			value.ContentBase64 = &encoded
		}
		operations, values = operations[1:], values[1:]
	}
	return normalized, nil
}

//nolint:cyclop // Commit-kind conversion is explicit and tracked by the exact HF CRAP baseline.
func toCommitOperations(values []normalizedCommitOperation) ([]hubclient.CommitOperation, error) {
	operations := make([]hubclient.CommitOperation, 0, len(values))
	for _, value := range values {
		operation := hubclient.CommitOperation{Kind: hubclient.CommitOperationKind(value.Kind), Path: value.Path}
		switch operation.Kind {
		case hubclient.CommitFile:
			if value.ContentBase64 == nil || value.OID != nil || value.Size != nil {
				return nil, errors.New("regular file content is invalid")
			}
			content, err := base64.StdEncoding.Strict().DecodeString(*value.ContentBase64)
			if err != nil || len(content) > maxInlineCommitContent {
				return nil, errors.New("regular file content is invalid")
			}
			operation.Content = content
		case hubclient.CommitLFSFile:
			if value.ContentBase64 != nil || value.OID == nil || value.Size == nil {
				return nil, errors.New("LFS file reference is invalid")
			}
			operation.OID, operation.Size = *value.OID, *value.Size
		case hubclient.CommitDeletedFile, hubclient.CommitDeletedFolder:
			if value.ContentBase64 != nil || value.OID != nil || value.Size != nil {
				return nil, errors.New("delete operation is invalid")
			}
		default:
			return nil, errors.New("commit operation kind is invalid")
		}
		operations = append(operations, operation)
	}
	return operations, nil
}

func validateCopyArguments(value fileCopyArguments) error {
	source := hubclient.RepoRef{Type: hubclient.RepoType(value.SourceType), Owner: value.SourceOwner, Name: value.SourceName}
	if source.Validate() != nil || !hubclient.ValidGitRefComponent(value.SourceRevision) || !hubclient.ValidRepoPath(value.SourcePath, false) || !hubclient.ValidRepoPath(value.Path, false) ||
		validateCommitMetadata(value.Summary, value.Description, value.ParentCommit) != nil {
		return errors.New("copy arguments are invalid")
	}
	return nil
}

func (target repositoryContentTarget) ref() hubclient.RepoRef {
	return hubclient.RepoRef{Type: hubclient.RepoType(target.Type), Owner: target.Owner, Name: target.Name}
}
