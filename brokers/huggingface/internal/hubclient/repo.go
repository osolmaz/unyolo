package hubclient

import (
	"context"
	"errors"
	"net/http"
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
