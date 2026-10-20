package githubauth

import (
	"bytes"
	"cmp"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"slices"
	"strings"

	github "github.com/google/go-github/v88/github"
	"github.com/osolmaz/unyolo/internal/strictjson"
)

// Node is one GitHub GraphQL node resolved to the repository it belongs to.
// Number is set for issues and pull requests.
type Node struct {
	ID         string
	Type       string
	Owner      string
	Repository string
	Number     int64
}

// Repository names one GitHub repository.
type Repository struct {
	Owner string
	Name  string
}

// ErrNodeNotFound means no configured credential can see the node.
var ErrNodeNotFound = errors.New("GitHub node is not visible to the broker")

// graphQLReadPermissions are the repository read permissions a GraphQL
// repository read may use. A token gets the subset its installation holds.
var graphQLReadPermissions = []string{
	"actions", "checks", "contents", "deployments", "discussions", "issues", "metadata", "pull_requests", "statuses",
}

// nodeLookupPermissions are enough to resolve repositories, issues, and pull
// requests to their repository.
var nodeLookupPermissions = []string{"issues", "metadata", "pull_requests"}

const nodeLookupQuery = `query NodeRepository($id: ID!) { node(id: $id) { __typename ` +
	`... on Repository { name owner { login } } ` +
	`... on PullRequest { number repository { name owner { login } } } ` +
	`... on Issue { number repository { name owner { login } } } } }`

const nodeLookupResponseLimit = 64 << 10

// GraphQLReadCredential returns one read-only credential narrowed to the named
// repositories, which must share one App installation.
func (m *Manager) GraphQLReadCredential(ctx context.Context, repositories []Repository) (*Credential, error) {
	if m == nil || len(repositories) == 0 {
		return nil, errors.New("GitHub credential provider is unavailable")
	}
	if m.development != nil {
		return m.development, nil
	}
	if m.installation == nil {
		return nil, errors.New("GitHub App credential is unavailable")
	}
	return m.installation.readCredential(ctx, repositories)
}

func (p *installationProvider) readCredential(ctx context.Context, repositories []Repository) (*Credential, error) {
	var installationID int64
	var installed map[string]string
	ids := make([]int64, 0, len(repositories))
	for _, repository := range repositories {
		resolution, err := p.resolveRepository(ctx, repository.Owner, repository.Name, map[string]string{"metadata": "read"})
		if err != nil {
			return nil, err
		}
		if installationID != 0 && resolution.InstallationID != installationID {
			return nil, errors.New("GitHub GraphQL reads must stay within one App installation")
		}
		installationID, installed = resolution.InstallationID, resolution.Permissions
		ids = append(ids, resolution.ID)
	}
	return p.credential(ctx, installationID, ids, readSubset(installed, graphQLReadPermissions), false)
}

// readSubset downgrades the named installation permissions to read and keeps
// only the ones the installation holds. Metadata is always readable.
func readSubset(installed map[string]string, names []string) map[string]string {
	result := map[string]string{"metadata": "read"}
	for _, name := range names {
		if level := installed[name]; level == "read" || level == "write" {
			result[name] = "read"
		}
	}
	return result
}

// SchemaCredential returns a metadata-only credential for GraphQL schema
// introspection, which reads no repository data.
func (m *Manager) SchemaCredential(ctx context.Context) (*Credential, error) {
	if m == nil {
		return nil, errors.New("GitHub credential provider is unavailable")
	}
	if m.development != nil {
		return m.development, nil
	}
	installations, err := m.sortedInstallations(ctx)
	if err != nil {
		return nil, err
	}
	return m.installation.credential(ctx, installations[0].GetID(), nil, map[string]string{"metadata": "read"}, false)
}

func (m *Manager) sortedInstallations(ctx context.Context) ([]*github.Installation, error) {
	if m.app == nil || m.installation == nil {
		return nil, errors.New("GitHub App credential is unavailable")
	}
	installations, err := m.app.installations(ctx)
	if err != nil {
		return nil, err
	}
	if len(installations) == 0 {
		return nil, errors.New("GitHub App has no installation")
	}
	slices.SortFunc(installations, func(left, right *github.Installation) int {
		return cmp.Compare(left.GetID(), right.GetID())
	})
	return installations, nil
}

// ResolveNode resolves one repository, issue, or pull request node id to its
// repository with a broker-internal lookup credential.
func (m *Manager) ResolveNode(ctx context.Context, id string) (Node, error) {
	if m == nil || strings.TrimSpace(id) == "" {
		return Node{}, errors.New("GitHub node lookup is invalid")
	}
	if m.development != nil {
		return m.resolveNodeWith(ctx, m.development, id)
	}
	installations, err := m.sortedInstallations(ctx)
	if err != nil {
		return Node{}, err
	}
	for _, installation := range installations {
		permissions := readSubset(installationPermissionMap(installation.GetPermissions()), nodeLookupPermissions)
		credential, err := m.installation.credential(ctx, installation.GetID(), nil, permissions, false)
		if err != nil {
			return Node{}, err
		}
		node, err := m.resolveNodeWith(ctx, credential, id)
		if !errors.Is(err, ErrNodeNotFound) {
			return node, err
		}
	}
	return Node{}, ErrNodeNotFound
}

type nodeRepository struct {
	Name  string `json:"name"`
	Owner struct {
		Login string `json:"login"`
	} `json:"owner"`
}

type nodeLookupResponse struct {
	Data struct {
		Node *struct {
			Typename string `json:"__typename"`
			nodeRepository
			Number     int64          `json:"number"`
			Repository nodeRepository `json:"repository"`
		} `json:"node"`
	} `json:"data"`
}

func (m *Manager) resolveNodeWith(ctx context.Context, credential *Credential, id string) (Node, error) {
	body, err := m.postGraphQL(ctx, credential, nodeLookupQuery, map[string]any{"id": id})
	if err != nil {
		return Node{}, err
	}
	var response nodeLookupResponse
	if json.Unmarshal(body, &response) != nil {
		return Node{}, errors.New("GitHub node lookup response is invalid")
	}
	found := response.Data.Node
	if found == nil {
		return Node{}, ErrNodeNotFound
	}
	node := Node{ID: id, Type: found.Typename, Number: found.Number, Owner: found.Repository.Owner.Login, Repository: found.Repository.Name}
	if found.Typename == "Repository" {
		node.Owner, node.Repository, node.Number = found.Owner.Login, found.Name, 0
	}
	if node.Owner == "" || node.Repository == "" {
		return Node{}, ErrNodeNotFound
	}
	return node, nil
}

func (m *Manager) postGraphQL(ctx context.Context, credential *Credential, query string, variables map[string]any) ([]byte, error) {
	payload, err := json.Marshal(map[string]any{"query": query, "variables": variables})
	if err != nil {
		return nil, errors.New("encode GitHub GraphQL request")
	}
	requestURL, err := m.restURL("/graphql", nil)
	if err != nil {
		return nil, err
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, requestURL, bytes.NewReader(payload))
	if err != nil {
		return nil, errors.New("create GitHub GraphQL request")
	}
	if err := credential.AuthorizeAPI(request); err != nil {
		return nil, err
	}
	request.Header.Set("Content-Type", "application/json")
	response, err := m.client.Do(request)
	if err != nil {
		return nil, APIError{Code: "unavailable"}
	}
	defer func() { _ = response.Body.Close() }()
	if response.StatusCode != http.StatusOK {
		return nil, classifyHTTPError(response)
	}
	body, err := limitedBody(response.Body, nodeLookupResponseLimit)
	if err != nil || strictjson.RejectDuplicateKeys(body) != nil {
		return nil, errors.New("GitHub GraphQL response is invalid")
	}
	return body, nil
}
