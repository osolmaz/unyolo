package hubclient

import (
	"context"
	"errors"
	"net/http"
	"net/url"
	"strconv"
	"strings"
)

// RepoInfo reads bounded metadata for one exact repository.
//
// Spec: GET /api/{type}s/{owner}/{name}.
func (c *Client) RepoInfo(ctx context.Context, ref RepoRef) (RepoInfo, error) {
	if err := ref.Validate(); err != nil {
		return RepoInfo{}, err
	}
	var wire repoInfoWire
	if err := c.call(ctx, callSpec{method: http.MethodGet, path: ref.apiPath(), out: &wire}); err != nil {
		return RepoInfo{}, err
	}
	return wire.toRepoInfo(), nil
}

// ListRepos discovers a bounded page for one exact owner and repository type.
func (c *Client) ListRepos(ctx context.Context, repoType RepoType, owner string, limit int) ([]RepoSummary, error) {
	probe := RepoRef{Type: repoType, Owner: owner, Name: "probe"}
	if err := probe.Validate(); err != nil || limit < 1 || limit > 100 {
		return nil, errors.New("hubclient: repository list query is invalid")
	}
	var wire []repoInfoWire
	err := c.call(ctx, callSpec{method: http.MethodGet, path: "/api/" + string(repoType) + "s",
		query: url.Values{"author": {owner}, "limit": {strconv.Itoa(limit)}}, out: &wire})
	if err != nil {
		return nil, err
	}
	result := make([]RepoSummary, 0, len(wire))
	for _, item := range wire {
		if item.ID == "" || len(item.ID) > 193 {
			return nil, errors.New("hubclient: upstream repository list is invalid")
		}
		result = append(result, RepoSummary{ID: item.ID, SHA: item.SHA, Private: item.Private})
	}
	return result, nil
}

// RepoTree returns one bounded tree page for an exact repository and revision.
func (c *Client) RepoTree(ctx context.Context, ref RepoRef, revision, path string, recursive bool) ([]RepoTreeEntry, error) {
	if err := ref.Validate(); err != nil || !ValidGitRefComponent(revision) || (path != "" && !ValidRepoPath(path+"/", true)) {
		return nil, errors.New("hubclient: repository tree query is invalid")
	}
	endpoint := ref.apiPath("tree", url.PathEscape(revision))
	if path != "" {
		endpoint += "/" + escapeRepoPath(path)
	}
	var entries []RepoTreeEntry
	if err := c.call(ctx, callSpec{method: http.MethodGet, path: endpoint,
		query: url.Values{"recursive": {strconv.FormatBool(recursive)}, "expand": {"false"}}, out: &entries}); err != nil {
		return nil, err
	}
	if len(entries) > 1000 {
		return nil, errors.New("hubclient: repository tree page is too large")
	}
	for _, entry := range entries {
		if (entry.Type != "file" && entry.Type != "directory") || entry.Path == "" || entry.Size < 0 {
			return nil, errors.New("hubclient: upstream repository tree is invalid")
		}
	}
	return entries, nil
}

// RepoFile reads one bounded exact file. Redirects remain refused, so large
// content that requires a separate storage origin must use a stream operation.
func (c *Client) RepoFile(ctx context.Context, ref RepoRef, revision, path string) (RepoFile, error) {
	if err := ref.Validate(); err != nil || !ValidGitRefComponent(revision) || !ValidRepoPath(path, false) {
		return RepoFile{}, errors.New("hubclient: repository file query is invalid")
	}
	prefix := ""
	if ref.Type != RepoTypeModel {
		prefix = string(ref.Type) + "s/"
	}
	endpoint := "/" + prefix + url.PathEscape(ref.Owner) + "/" + url.PathEscape(ref.Name) + "/resolve/" +
		url.PathEscape(revision) + "/" + escapeRepoPath(path)
	payload, header, err := c.callBytes(ctx, callSpec{method: http.MethodGet, path: endpoint})
	if err != nil {
		return RepoFile{}, err
	}
	return RepoFile{Content: payload, ContentType: strings.TrimSpace(strings.Split(header.Get("Content-Type"), ";")[0]), Commit: header.Get("X-Repo-Commit")}, nil
}

type createRepoBody struct {
	Name         string  `json:"name"`
	Organization *string `json:"organization"`
	Type         string  `json:"type"`
	Visibility   string  `json:"visibility"`
	SDK          string  `json:"sdk,omitempty"`
}

// CreateRepo creates one exact repository.
//
// Spec: POST /api/repos/create.
func (c *Client) CreateRepo(ctx context.Context, input CreateRepoInput) (CreatedRepo, error) {
	if err := input.validate(); err != nil {
		return CreatedRepo{}, err
	}
	var organization *string
	if !input.PersonalNamespace {
		organization = &input.Ref.Owner
	}
	body := createRepoBody{
		Name: input.Ref.Name, Organization: organization,
		Type: string(input.Ref.Type), Visibility: string(input.Visibility), SDK: input.SpaceSDK,
	}
	var created CreatedRepo
	err := c.call(ctx, callSpec{method: http.MethodPost, path: "/api/repos/create", body: body, out: &created})
	if err != nil {
		return CreatedRepo{}, err
	}
	return created, nil
}

// WhoAmI returns the exact account identity selected by the broker credential.
func (c *Client) WhoAmI(ctx context.Context) (Identity, error) {
	var identity Identity
	if err := c.call(ctx, callSpec{method: http.MethodGet, path: "/api/whoami-v2", out: &identity}); err != nil {
		return Identity{}, err
	}
	if !ValidNamespaceSegment(identity.Name) {
		return Identity{}, errors.New("hubclient: upstream identity is invalid")
	}
	return identity, nil
}

type deleteRepoBody struct {
	Name         string `json:"name"`
	Organization string `json:"organization"`
	Type         string `json:"type"`
}

// DeleteRepo irreversibly deletes one exact repository.
//
// Spec: DELETE /api/repos/delete.
func (c *Client) DeleteRepo(ctx context.Context, ref RepoRef) error {
	if err := ref.Validate(); err != nil {
		return err
	}
	body := deleteRepoBody{Name: ref.Name, Organization: ref.Owner, Type: string(ref.Type)}
	return c.call(ctx, callSpec{method: http.MethodDelete, path: "/api/repos/delete", body: body})
}

type moveRepoBody struct {
	FromRepo string `json:"fromRepo"`
	ToRepo   string `json:"toRepo"`
	Type     string `json:"type"`
}

// MoveRepo renames or transfers one exact repository.
//
// Spec: POST /api/repos/move.
func (c *Client) MoveRepo(ctx context.Context, from RepoRef, toOwner, toName string) error {
	if err := from.Validate(); err != nil {
		return err
	}
	if !ValidNamespaceSegment(toOwner) || !ValidNamespaceSegment(toName) {
		return errors.New("hubclient: move destination must be exact safe segments")
	}
	body := moveRepoBody{FromRepo: from.ID(), ToRepo: toOwner + "/" + toName, Type: string(from.Type)}
	return c.call(ctx, callSpec{method: http.MethodPost, path: "/api/repos/move", body: body})
}

type visibilitySettingsBody struct {
	Visibility string `json:"visibility"`
}

// UpdateRepoVisibility sets one exact repository visibility. Protected
// visibility is valid for Spaces only.
//
// Spec: PUT /api/{type}s/{owner}/{name}/settings.
func (c *Client) UpdateRepoVisibility(ctx context.Context, ref RepoRef, visibility Visibility) (RepoSettings, error) {
	if err := ref.Validate(); err != nil {
		return RepoSettings{}, err
	}
	switch visibility {
	case VisibilityPublic, VisibilityPrivate:
	case VisibilityProtected:
		if ref.Type != RepoTypeSpace {
			return RepoSettings{}, errors.New("hubclient: protected visibility applies only to spaces")
		}
	default:
		return RepoSettings{}, errors.New("hubclient: visibility must be public, private, or protected")
	}
	body := visibilitySettingsBody{Visibility: string(visibility)}
	var settings RepoSettings
	err := c.call(ctx, callSpec{method: http.MethodPut, path: ref.apiPath("settings"), body: body, out: &settings})
	return settings, err
}

type gatedSettingsBody struct {
	Gated any `json:"gated"`
}

// UpdateRepoGating sets exact gated access. GatedDisabled encodes the
// upstream JSON literal false.
//
// Spec: PUT /api/{type}s/{owner}/{name}/settings.
func (c *Client) UpdateRepoGating(ctx context.Context, ref RepoRef, mode GatedMode) error {
	if err := ref.Validate(); err != nil {
		return err
	}
	var wire any
	switch mode {
	case GatedAuto, GatedManual:
		wire = string(mode)
	case GatedDisabled:
		wire = false
	default:
		return errors.New("hubclient: gated mode must be auto, manual, or disabled")
	}
	return c.call(ctx, callSpec{method: http.MethodPut, path: ref.apiPath("settings"), body: gatedSettingsBody{Gated: wire}})
}
