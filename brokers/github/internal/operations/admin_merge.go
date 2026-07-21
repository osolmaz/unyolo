package operations

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"

	"github.com/osolmaz/brokerkit/agent/v1"
	"github.com/osolmaz/brokerkit/brokers/github/internal/githubauth"
	"github.com/osolmaz/brokerkit/brokers/github/internal/graphqlmanifest"
	"github.com/osolmaz/brokerkit/brokers/github/internal/opcatalog"
	"github.com/osolmaz/brokerkit/brokers/github/internal/schemaregistry"
	"github.com/osolmaz/brokerkit/operation/capability"
)

const adminMergeOperation = "pull_request.merge_admin"

type adminMergeAdapter struct {
	descriptor opcatalog.Descriptor
	document   graphqlmanifest.Document
	manager    *githubauth.Manager
	userID     int64
}

type adminMergePreconditions struct {
	UserID            int64  `json:"user_id"`
	UserLogin         string `json:"user_login"`
	PullRequestNodeID string `json:"pull_request_node_id"`
	HeadSHA           string `json:"head_sha"`
	MergeableState    string `json:"mergeable_state,omitempty"`
}

type adminMergeArguments struct {
	MergeMethod   string `json:"merge_method"`
	CommitTitle   string `json:"commit_title,omitempty"`
	CommitMessage string `json:"commit_message,omitempty"`
}

func newAdminMergeAdapter(descriptor opcatalog.Descriptor, manager *githubauth.Manager, options Options) (Adapter, error) {
	document, found := graphqlmanifest.ByOperation(descriptor.Name)
	if !found || document.RootType != "mutation" || document.RootField != "mergePullRequest" || document.CredentialKind != string(githubauth.KindUser) {
		return nil, errors.New("GitHub admin merge document is unavailable")
	}
	return adminMergeAdapter{descriptor: descriptor, document: document, manager: manager, userID: options.RequestingUserID}, nil
}

func (a adminMergeAdapter) Descriptor() capability.Descriptor { return a.descriptor.Descriptor }

func (a adminMergeAdapter) Decode(target, arguments json.RawMessage) (Input, error) {
	if err := schemaregistry.ValidateSubmission(a.descriptor.Name, target, arguments); err != nil {
		return Input{}, err
	}
	targetMap, err := decodeObject(target)
	if err != nil || stringValue(targetMap, "kind") != "pull_request" || stringValue(targetMap, "owner") == "" ||
		stringValue(targetMap, "repo") == "" || integerString(targetMap, "number") == "" {
		return Input{}, errors.New("GitHub admin merge target must identify one pull request by owner, repository, and number")
	}
	return Input{Target: cloneRaw(target), Arguments: cloneRaw(arguments)}, nil
}

func (a adminMergeAdapter) Resolve(ctx context.Context, input Input) (Plan, error) {
	target, err := decodeObject(input.Target)
	if err != nil {
		return Plan{}, errors.New("GitHub admin merge target is invalid")
	}
	credential, err := a.manager.SelectMetadata(ctx, a.descriptor, target, a.userID)
	if err != nil {
		return Plan{}, err
	}
	if credential.Kind != githubauth.KindUser && credential.Kind != githubauth.KindDevelopmentToken {
		return Plan{}, errors.New("GitHub admin merge requires a user identity credential")
	}
	identity, err := a.manager.AuthenticatedUser(ctx, credential)
	if err != nil {
		return Plan{}, err
	}
	if credential.UserID > 0 && credential.UserID != identity.ID {
		return Plan{}, errors.New("GitHub admin merge user credential does not match its configured identity")
	}
	snapshot, err := a.pullRequest(ctx, credential, target)
	if err != nil {
		return Plan{}, err
	}
	if err := validateAdminMergeSnapshot(snapshot, target); err != nil {
		return Plan{}, err
	}
	preconditions := adminMergePreconditions{UserID: identity.ID, UserLogin: identity.Login, PullRequestNodeID: snapshot.NodeID,
		HeadSHA: snapshot.HeadSHA, MergeableState: snapshot.MergeableState}
	presentation := agentv1.Presentation{Title: "Admin merge a pull request",
		Summary: fmt.Sprintf("Admin merge %s/%s#%s at %s as @%s; this may bypass GitHub merge requirements",
			stringValue(target, "owner"), stringValue(target, "repo"), integerString(target, "number"), shortSHA(snapshot.HeadSHA), identity.Login)}
	return Plan{
		Operation: a.descriptor.Name, OperationRevision: a.descriptor.OperationRevision, Target: cloneRaw(input.Target), Arguments: cloneRaw(input.Arguments),
		Preconditions: encodePreconditions(credential, preconditions), Credential: credential, Presentation: presentation,
		Authorization: adminMergeAuthorization(a.descriptor, target, input.Arguments, credential),
	}, nil
}

func (a adminMergeAdapter) Authorize(plan Plan) Authorization {
	if plan.Authorization.Operation != "" {
		return plan.Authorization
	}
	target, _ := decodeObject(plan.Target)
	return adminMergeAuthorization(a.descriptor, target, plan.Arguments, plan.Credential)
}

func (a adminMergeAdapter) Present(plan Plan) agentv1.Presentation {
	if plan.Presentation.Title != "" {
		return plan.Presentation
	}
	return agentv1.Presentation{Title: "Admin merge a pull request", Summary: adminMergeOperation}
}

func (a adminMergeAdapter) Execute(ctx context.Context, plan Plan) (Outcome, error) {
	preconditions, arguments, target, err := decodeAdminMergePlan(plan)
	if err != nil {
		return Outcome{}, err
	}
	identity, err := a.manager.AuthenticatedUser(ctx, plan.Credential)
	if err != nil {
		return Outcome{}, err
	}
	if identity.ID != preconditions.UserID || !strings.EqualFold(identity.Login, preconditions.UserLogin) {
		return Outcome{}, githubauth.APIError{Code: "stale_github_user", StatusCode: http.StatusConflict, Message: "GitHub user identity changed after approval"}
	}
	current, err := a.pullRequest(ctx, plan.Credential, target)
	if err != nil {
		return Outcome{}, err
	}
	if err := validateAdminMergeExecution(current, preconditions); err != nil {
		return Outcome{}, err
	}
	variables := adminMergeVariables(plan.ExecutionID, preconditions, arguments)
	execution, err := a.manager.ExecuteGraphQL(ctx, plan.Credential, a.document, variables)
	if err != nil {
		return Outcome{}, classifyExecutionError(http.MethodPost, err)
	}
	return a.successOutcome(execution.StatusCode, preconditions, arguments)
}

func (a adminMergeAdapter) Reconcile(ctx context.Context, plan Plan) (Outcome, error) {
	preconditions, arguments, target, err := decodeAdminMergePlan(plan)
	if err != nil {
		return Outcome{}, err
	}
	current, err := a.pullRequest(ctx, plan.Credential, target)
	if err != nil {
		return Outcome{}, err
	}
	if !current.Merged || !strings.EqualFold(current.HeadSHA, preconditions.HeadSHA) {
		return Outcome{Proven: false}, nil
	}
	return a.successOutcome(http.StatusOK, preconditions, arguments)
}

func (adminMergeAdapter) Cleanup(Plan) error { return nil }

func (a adminMergeAdapter) pullRequest(ctx context.Context, credential githubauth.Metadata, target map[string]any) (githubauth.PullRequestSnapshot, error) {
	number, ok := integerValue(target["number"])
	if !ok {
		return githubauth.PullRequestSnapshot{}, errors.New("GitHub admin merge target is invalid")
	}
	return a.manager.PullRequest(ctx, credential, stringValue(target, "owner"), stringValue(target, "repo"), number)
}

func validateAdminMergeSnapshot(snapshot githubauth.PullRequestSnapshot, target map[string]any) error {
	if snapshot.Merged || !strings.EqualFold(snapshot.State, "open") {
		return errors.New("GitHub pull request is not open")
	}
	if snapshot.Draft {
		return errors.New("GitHub draft pull request cannot be admin merged")
	}
	if adminMergeConflict(snapshot) {
		return errors.New("GitHub pull request has merge conflicts that administrator privileges cannot bypass")
	}
	return validateAdminMergeIdentity(snapshot, target)
}

func adminMergeConflict(snapshot githubauth.PullRequestSnapshot) bool {
	return strings.EqualFold(snapshot.MergeableState, "dirty") || snapshot.Mergeable != nil && !*snapshot.Mergeable
}

func validateAdminMergeIdentity(snapshot githubauth.PullRequestSnapshot, target map[string]any) error {
	if nodeID := stringValue(target, "node_id"); nodeID != "" && nodeID != snapshot.NodeID {
		return errors.New("GitHub pull request node id does not match its repository path")
	}
	if id := integerString(target, "id"); id != "" && id != fmt.Sprint(snapshot.ID) {
		return errors.New("GitHub pull request id does not match its repository path")
	}
	return nil
}

func validateAdminMergeExecution(current githubauth.PullRequestSnapshot, approved adminMergePreconditions) error {
	if current.Merged || !strings.EqualFold(current.State, "open") {
		return githubauth.APIError{Code: "pull_request_not_open", StatusCode: http.StatusConflict, Message: "Pull request is no longer open"}
	}
	if !strings.EqualFold(current.HeadSHA, approved.HeadSHA) {
		return githubauth.APIError{Code: "stale_pull_request_head", StatusCode: http.StatusConflict, Message: "Pull request head changed after approval"}
	}
	if current.Draft {
		return githubauth.APIError{Code: "pull_request_draft", StatusCode: http.StatusConflict, Message: "Pull request became a draft after approval"}
	}
	if adminMergeConflict(current) {
		return githubauth.APIError{Code: "merge_conflict", StatusCode: http.StatusConflict, Message: "Pull request has merge conflicts that administrator privileges cannot bypass"}
	}
	return nil
}

func decodeAdminMergePlan(plan Plan) (adminMergePreconditions, adminMergeArguments, map[string]any, error) {
	var preconditions adminMergePreconditions
	if decodeOperationPreconditions(plan.Preconditions, &preconditions) != nil || !validAdminMergePreconditions(preconditions) {
		return adminMergePreconditions{}, adminMergeArguments{}, nil, errors.New("GitHub admin merge preconditions are invalid")
	}
	var arguments adminMergeArguments
	if err := json.Unmarshal(plan.Arguments, &arguments); err != nil || arguments.MergeMethod == "" {
		return adminMergePreconditions{}, adminMergeArguments{}, nil, errors.New("GitHub admin merge arguments are invalid")
	}
	target, err := decodeObject(plan.Target)
	if err != nil {
		return adminMergePreconditions{}, adminMergeArguments{}, nil, errors.New("GitHub admin merge target is invalid")
	}
	return preconditions, arguments, target, nil
}

func validAdminMergePreconditions(value adminMergePreconditions) bool {
	return value.UserID > 0 && value.UserLogin != "" && value.PullRequestNodeID != "" && value.HeadSHA != ""
}

func adminMergeVariables(executionID string, preconditions adminMergePreconditions, arguments adminMergeArguments) map[string]any {
	input := map[string]any{
		"pullRequestId":   preconditions.PullRequestNodeID,
		"expectedHeadOid": preconditions.HeadSHA,
		"mergeMethod":     strings.ToUpper(arguments.MergeMethod),
	}
	if executionID != "" {
		input["clientMutationId"] = executionID
	}
	if arguments.CommitTitle != "" {
		input["commitHeadline"] = arguments.CommitTitle
	}
	if arguments.CommitMessage != "" {
		input["commitBody"] = arguments.CommitMessage
	}
	return map[string]any{"input": input}
}

func adminMergeAuthorization(descriptor opcatalog.Descriptor, target map[string]any, rawArguments json.RawMessage, credential githubauth.Metadata) Authorization {
	arguments, _ := decodeObject(rawArguments)
	fields := map[string][]string{
		"owner": {stringValue(target, "owner")}, "repo": {stringValue(target, "repo")}, "number": {integerString(target, "number")},
	}
	attrs := map[string][]string{"merge_method": {stringValue(arguments, "merge_method")}}
	if credential.UserID > 0 {
		attrs["actor_id"] = []string{fmt.Sprint(credential.UserID)}
	}
	return Authorization{Operation: descriptor.Name, TargetKind: descriptor.TargetKind, TargetFields: fields, Attrs: attrs, CredentialKind: descriptor.CredentialKind}
}

func (a adminMergeAdapter) successOutcome(status int, preconditions adminMergePreconditions, arguments adminMergeArguments) (Outcome, error) {
	result, _ := json.Marshal(map[string]any{"merged": true, "head_sha": preconditions.HeadSHA, "merge_method": arguments.MergeMethod})
	if err := schemaregistry.ValidateResult(a.descriptor.Name, result); err != nil {
		return Outcome{}, err
	}
	return Outcome{Proven: true, Result: result, UpstreamStatus: status}, nil
}

func shortSHA(value string) string {
	if len(value) > 12 {
		return value[:12]
	}
	return value
}
