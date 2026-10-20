package apicompat

import (
	"slices"
	"strings"

	"github.com/osolmaz/unyolo/brokers/github/internal/githubauth"
	"github.com/osolmaz/unyolo/internal/strictjson"
	"github.com/vektah/gqlparser/v2/ast"
	"github.com/vektah/gqlparser/v2/parser"
)

// graphQLTokenLimit bounds parser work for one document. GitHub CLI documents
// stay far below it.
const graphQLTokenLimit = 20000

// GraphQLKind is the reviewed shape of one GraphQL request.
type GraphQLKind string

const (
	// GraphQLSchema is schema introspection only. GitHub CLI sends it to
	// every GitHub Enterprise host to detect features.
	GraphQLSchema GraphQLKind = "schema"
	// GraphQLRead reads named repositories and repository, issue, or pull
	// request nodes.
	GraphQLRead GraphQLKind = "read"
	// GraphQLMutation is one reviewed mutation.
	GraphQLMutation GraphQLKind = "mutation"
)

// GraphQLRequest is one classified GraphQL request.
type GraphQLRequest struct {
	Kind         GraphQLKind
	Repositories []githubauth.Repository
	// NodeIDs are node(id:) subjects. Each must be resolved to its repository
	// before policy can run.
	NodeIDs  []string
	Mutation Mutation
}

type graphQLEnvelope struct {
	Query         string         `json:"query"`
	Variables     map[string]any `json:"variables"`
	OperationName string         `json:"operationName"`
}

// ClassifyGraphQL parses one GraphQL HTTP request body and classifies the
// operation that GitHub would run.
func ClassifyGraphQL(body []byte) (GraphQLRequest, error) {
	var envelope graphQLEnvelope
	if err := strictjson.Decode(body, &envelope, true); err != nil || strings.TrimSpace(envelope.Query) == "" {
		return GraphQLRequest{}, malformed("the GraphQL request body is invalid")
	}
	operation, err := selectOperation(envelope)
	if err != nil {
		return GraphQLRequest{}, err
	}
	variables, err := effectiveVariables(operation, envelope.Variables)
	if err != nil {
		return GraphQLRequest{}, err
	}
	fields, err := rootFields(operation)
	if err != nil {
		return GraphQLRequest{}, err
	}
	switch operation.Operation {
	case ast.Query:
		return classifyQuery(fields, variables)
	case ast.Mutation:
		return classifyMutation(fields, variables)
	default:
		return GraphQLRequest{}, unsupported("GraphQL subscriptions are not served")
	}
}

func selectOperation(envelope graphQLEnvelope) (*ast.OperationDefinition, error) {
	document, err := parser.ParseQueryWithTokenLimit(&ast.Source{Input: envelope.Query}, graphQLTokenLimit)
	if err != nil {
		return nil, malformed("the GraphQL document does not parse")
	}
	if envelope.OperationName == "" {
		if len(document.Operations) != 1 {
			return nil, malformed("the GraphQL document has several operations; set operationName")
		}
		return document.Operations[0], nil
	}
	var selected []*ast.OperationDefinition
	for _, operation := range document.Operations {
		if operation.Name == envelope.OperationName {
			selected = append(selected, operation)
		}
	}
	if len(selected) != 1 {
		return nil, malformed("operationName does not name exactly one GraphQL operation")
	}
	return selected[0], nil
}

// effectiveVariables applies declared defaults the way GitHub does, so the
// classified values are the values GitHub executes.
func effectiveVariables(operation *ast.OperationDefinition, provided map[string]any) (map[string]any, error) {
	variables := make(map[string]any, len(operation.VariableDefinitions))
	for _, definition := range operation.VariableDefinitions {
		if value, found := provided[definition.Variable]; found {
			variables[definition.Variable] = value
			continue
		}
		if definition.DefaultValue == nil {
			continue
		}
		value, err := resolveValue(definition.DefaultValue, nil)
		if err != nil {
			return nil, err
		}
		variables[definition.Variable] = value
	}
	return variables, nil
}

func rootFields(operation *ast.OperationDefinition) ([]*ast.Field, error) {
	if len(operation.Directives) > 0 {
		return nil, unsupported("GraphQL operation directives are not served")
	}
	fields := make([]*ast.Field, 0, len(operation.SelectionSet))
	for _, selection := range operation.SelectionSet {
		field, isField := selection.(*ast.Field)
		if !isField || len(field.Directives) > 0 {
			return nil, unsupported("GraphQL root fragments and root directives are not served")
		}
		fields = append(fields, field)
	}
	return fields, nil
}

func classifyQuery(fields []*ast.Field, variables map[string]any) (GraphQLRequest, error) {
	request := GraphQLRequest{Kind: GraphQLSchema}
	viewer := false
	for _, field := range fields {
		isViewer, err := request.addQueryField(field, variables)
		if err != nil {
			return GraphQLRequest{}, err
		}
		viewer = viewer || isViewer
	}
	if len(request.Repositories) > 0 || len(request.NodeIDs) > 0 {
		request.Kind = GraphQLRead
	} else if viewer {
		return GraphQLRequest{}, unsupported("GraphQL viewer queries must also name a repository")
	}
	return request, nil
}

// addQueryField records one root query field and reports whether it is viewer.
func (r *GraphQLRequest) addQueryField(field *ast.Field, variables map[string]any) (bool, error) {
	switch field.Name {
	case "__typename", "__type", "__schema":
		return false, nil
	case "viewer":
		return true, nil
	case "repository":
		repository, err := repositoryArgument(field, variables)
		if err != nil {
			return false, err
		}
		r.Repositories = appendRepository(r.Repositories, repository)
		return false, nil
	case "node":
		id, err := nodeArgument(field, variables)
		if err != nil {
			return false, err
		}
		if !slices.Contains(r.NodeIDs, id) {
			r.NodeIDs = append(r.NodeIDs, id)
		}
		return false, nil
	default:
		return false, unsupported("GraphQL query field %s is not served; read through repository(owner:, name:) or node(id:)", field.Name)
	}
}

func repositoryArgument(field *ast.Field, variables map[string]any) (githubauth.Repository, error) {
	values, err := fieldArguments(field, variables)
	if err != nil {
		return githubauth.Repository{}, err
	}
	owner, ownerOK := values["owner"].(string)
	name, nameOK := values["name"].(string)
	delete(values, "owner")
	delete(values, "name")
	if renames, found := values["followRenames"]; found {
		if _, isBool := renames.(bool); !isBool {
			return githubauth.Repository{}, malformed("repository followRenames must be a boolean")
		}
		delete(values, "followRenames")
	}
	if !ownerOK || !nameOK || !validRepositoryPart(owner) || !validRepositoryPart(name) || len(values) > 0 {
		return githubauth.Repository{}, malformed("repository needs exactly the owner and name arguments")
	}
	return githubauth.Repository{Owner: owner, Name: name}, nil
}

func nodeArgument(field *ast.Field, variables map[string]any) (string, error) {
	values, err := fieldArguments(field, variables)
	if err != nil {
		return "", err
	}
	id, isText := values["id"].(string)
	if len(values) != 1 || !isText || strings.TrimSpace(id) == "" {
		return "", malformed("node needs exactly the id argument")
	}
	return id, nil
}

// ReadRepositories returns the named repositories plus the repositories of
// resolved node subjects, without duplicates.
func ReadRepositories(named []githubauth.Repository, nodes []githubauth.Node) []githubauth.Repository {
	repositories := slices.Clone(named)
	for _, node := range nodes {
		repositories = appendRepository(repositories, githubauth.Repository{Owner: node.Owner, Name: node.Repository})
	}
	return repositories
}

func validRepositoryPart(value string) bool {
	return value != "" && value != "." && value != ".." && len(value) <= 100 && !strings.ContainsAny(value, "/\\ \t\r\n")
}

func appendRepository(repositories []githubauth.Repository, repository githubauth.Repository) []githubauth.Repository {
	if slices.ContainsFunc(repositories, func(existing githubauth.Repository) bool {
		return strings.EqualFold(existing.Owner, repository.Owner) && strings.EqualFold(existing.Name, repository.Name)
	}) {
		return repositories
	}
	return append(repositories, repository)
}

// fieldArguments resolves the arguments of one field. Duplicate names are
// refused because GitHub rejects them and they could hide a second value.
func fieldArguments(field *ast.Field, variables map[string]any) (map[string]any, error) {
	values := make(map[string]any, len(field.Arguments))
	for _, argument := range field.Arguments {
		if _, duplicate := values[argument.Name]; duplicate {
			return nil, malformed("GraphQL argument %s is repeated", argument.Name)
		}
		value, err := resolveValue(argument.Value, variables)
		if err != nil {
			return nil, err
		}
		values[argument.Name] = value
	}
	return values, nil
}
