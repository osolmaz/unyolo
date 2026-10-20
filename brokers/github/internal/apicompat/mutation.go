package apicompat

import (
	"slices"
	"strings"

	"github.com/osolmaz/unyolo/brokers/github/internal/githubauth"
	"github.com/osolmaz/unyolo/brokers/github/internal/operations"
	"github.com/osolmaz/unyolo/brokers/github/internal/policy"
	"github.com/vektah/gqlparser/v2/ast"
)

// Mutation is one reviewed GraphQL mutation, classified as the REST catalog
// operation with the same effect. Its subject node still has to be resolved
// to a repository before policy can run.
type Mutation struct {
	Field     string
	Operation string
	NodeID    string
	nodeTypes []string
	arguments map[string]any
}

// mutationSpec maps one GraphQL mutation to its REST-equivalent operation.
// Input fields outside subject, fields, and renames are refused, so a new
// GitHub field cannot bypass a policy attribute. Renames name the REST field
// that carries the same policy attribute.
type mutationSpec struct {
	operation string
	subject   string
	types     []string
	fields    []string
	renames   map[string]string
}

var (
	repositorySubject  = []string{"Repository"}
	pullRequestSubject = []string{"PullRequest"}
	issueSubject       = []string{"Issue"}
	commentSubject     = []string{"Issue", "PullRequest"}
	mergeRenames       = map[string]string{"mergeMethod": "merge_method"}
	mergeFields        = []string{"commitHeadline", "commitBody", "expectedHeadOid", "authorEmail"}
)

func pullRequestUpdate(fields ...string) mutationSpec {
	return mutationSpec{operation: "pull_request.update", subject: "pullRequestId", types: pullRequestSubject, fields: fields}
}

func issueUpdate(subject string, fields ...string) mutationSpec {
	return mutationSpec{operation: "issue.issues_update", subject: subject, types: issueSubject, fields: fields}
}

var mutationSpecs = map[string]mutationSpec{
	"createPullRequest": {
		operation: "pull_request.create", subject: "repositoryId", types: repositorySubject,
		fields:  []string{"title", "body", "maintainerCanModify", "draft"},
		renames: map[string]string{"baseRefName": "base", "headRefName": "head"},
	},
	"updatePullRequest": {
		operation: "pull_request.update", subject: "pullRequestId", types: pullRequestSubject,
		fields:  []string{"title", "body", "state", "maintainerCanModify", "assigneeIds", "milestoneId"},
		renames: map[string]string{"baseRefName": "base"},
	},
	"closePullRequest":              pullRequestUpdate(),
	"reopenPullRequest":             pullRequestUpdate(),
	"markPullRequestReadyForReview": pullRequestUpdate(),
	"convertPullRequestToDraft":     pullRequestUpdate(),
	"disablePullRequestAutoMerge":   pullRequestUpdate(),
	"mergePullRequest": {
		operation: "pull_request.merge", subject: "pullRequestId", types: pullRequestSubject, fields: mergeFields, renames: mergeRenames,
	},
	"enablePullRequestAutoMerge": {
		operation: "pull_request.merge", subject: "pullRequestId", types: pullRequestSubject, fields: mergeFields, renames: mergeRenames,
	},
	"requestReviews": {
		operation: "pull_request.request_reviewers", subject: "pullRequestId", types: pullRequestSubject,
		fields: []string{"userIds", "botIds", "teamIds", "union"},
	},
	"addPullRequestReview": {
		operation: "review.pulls_create_review", subject: "pullRequestId", types: pullRequestSubject,
		fields: []string{"commitOID", "body", "event"},
	},
	"addComment": {operation: "comment.issues_create_comment", subject: "subjectId", types: commentSubject, fields: []string{"body"}},
	"createIssue": {
		operation: "issue.issues_create", subject: "repositoryId", types: repositorySubject,
		fields: []string{"title", "body", "assigneeIds", "milestoneId", "issueTemplate"},
	},
	"updateIssue": issueUpdate("id", "title", "body", "assigneeIds", "milestoneId", "state"),
	"closeIssue":  issueUpdate("issueId", "stateReason"),
	"reopenIssue": issueUpdate("issueId"),
}

// MutationFields returns the GraphQL mutations the GitHub-compatible API
// serves, sorted.
func MutationFields() []string {
	fields := make([]string, 0, len(mutationSpecs))
	for field := range mutationSpecs {
		fields = append(fields, field)
	}
	slices.Sort(fields)
	return fields
}

func classifyMutation(fields []*ast.Field, variables map[string]any) (GraphQLRequest, error) {
	if len(fields) != 1 {
		return GraphQLRequest{}, unsupported("send exactly one GraphQL mutation field per request")
	}
	field := fields[0]
	spec, found := mutationSpecs[field.Name]
	if !found {
		return GraphQLRequest{}, unsupported("GraphQL mutation %s is not served", field.Name)
	}
	input, err := mutationInput(field, variables)
	if err != nil {
		return GraphQLRequest{}, err
	}
	nodeID, _ := input[spec.subject].(string)
	if strings.TrimSpace(nodeID) == "" {
		return GraphQLRequest{}, malformed("GraphQL mutation %s needs input.%s", field.Name, spec.subject)
	}
	arguments, err := spec.restArguments(field.Name, input)
	if err != nil {
		return GraphQLRequest{}, err
	}
	return GraphQLRequest{Kind: GraphQLMutation, Mutation: Mutation{
		Field: field.Name, Operation: spec.operation, NodeID: nodeID, nodeTypes: spec.types, arguments: arguments,
	}}, nil
}

func mutationInput(field *ast.Field, variables map[string]any) (map[string]any, error) {
	arguments, err := fieldArguments(field, variables)
	if err != nil {
		return nil, err
	}
	input, isObject := arguments["input"].(map[string]any)
	if len(arguments) != 1 || !isObject {
		return nil, malformed("GraphQL mutation %s needs exactly one input object", field.Name)
	}
	return input, nil
}

func (s mutationSpec) restArguments(field string, input map[string]any) (map[string]any, error) {
	rest := map[string]any{}
	for name, value := range input {
		if name == "clientMutationId" || name == s.subject || slices.Contains(s.fields, name) {
			continue
		}
		restName, renamed := s.renames[name]
		if !renamed {
			return nil, unsupported("GraphQL input field %s of %s is not served", name, field)
		}
		rest[restName] = restValue(restName, value)
	}
	return map[string]any{"input": rest}, nil
}

func restValue(name string, value any) any {
	if text, isText := value.(string); isText && name == "merge_method" {
		return strings.ToLower(text)
	}
	return value
}

// Request builds the policy request of the mutation for its resolved
// subject. The client is added by the caller.
func (m Mutation) Request(node githubauth.Node) (policy.Request, error) {
	if !slices.Contains(m.nodeTypes, node.Type) {
		return policy.Request{}, unsupported("GraphQL mutation %s does not accept a %s subject", m.Field, node.Type)
	}
	descriptor, err := servableDescriptor(m.Operation)
	if err != nil {
		return policy.Request{}, err
	}
	target := policy.Target{Kind: descriptor.TargetKind, Owner: node.Owner, Repo: node.Repository, Number: node.Number}
	if descriptor.TargetKind == "repo" {
		target = policy.Target{Kind: "repo", Owner: node.Owner, Name: node.Repository}
	} else if node.Number <= 0 {
		return policy.Request{}, unsupported("GraphQL mutation %s needs a numbered subject", m.Field)
	}
	attrs, err := singleValues(operations.PolicyAttributes(m.Operation, nil, m.arguments))
	if err != nil {
		return policy.Request{}, err
	}
	return policy.Request{Operation: policy.Operation(m.Operation), Target: target, Attrs: attrs}, nil
}
