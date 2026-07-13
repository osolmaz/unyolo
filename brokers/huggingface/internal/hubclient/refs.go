package hubclient

import (
	"context"
	"net/http"
	"net/url"
)

// ListRefs lists the observed branches and tags of one exact repository.
//
// Spec: GET /api/{type}s/{owner}/{name}/refs.
func (c *Client) ListRefs(ctx context.Context, ref RepoRef) (Refs, error) {
	if err := ref.Validate(); err != nil {
		return Refs{}, err
	}
	var wire refsWire
	if err := c.call(ctx, callSpec{method: http.MethodGet, path: ref.apiPath("refs"), out: &wire}); err != nil {
		return Refs{}, err
	}
	return wire.toRefs(), nil
}

type createBranchBody struct {
	StartingPoint string `json:"startingPoint,omitempty"`
}

// CreateBranch creates one exact branch from an observed starting revision.
//
// Spec: POST /api/{type}s/{owner}/{name}/branch/{branch}.
func (c *Client) CreateBranch(ctx context.Context, ref RepoRef, branch, startingPoint string) error {
	if err := ref.Validate(); err != nil {
		return err
	}
	if err := validateRefName("branch", branch); err != nil {
		return err
	}
	if err := validateRefName("starting revision", startingPoint); err != nil {
		return err
	}
	spec := callSpec{
		method: http.MethodPost,
		path:   ref.apiPath("branch", url.PathEscape(branch)),
		body:   createBranchBody{StartingPoint: startingPoint},
	}
	return c.call(ctx, spec)
}

// DeleteBranch deletes one exact non-default branch.
//
// Spec: DELETE /api/{type}s/{owner}/{name}/branch/{branch}.
func (c *Client) DeleteBranch(ctx context.Context, ref RepoRef, branch string) error {
	if err := ref.Validate(); err != nil {
		return err
	}
	if err := validateRefName("branch", branch); err != nil {
		return err
	}
	return c.call(ctx, callSpec{method: http.MethodDelete, path: ref.apiPath("branch", url.PathEscape(branch))})
}

type createTagBody struct {
	Tag     string `json:"tag"`
	Message string `json:"message,omitempty"`
}

// CreateTag tags one exact observed revision.
//
// Spec: POST /api/{type}s/{owner}/{name}/tag/{revision}.
func (c *Client) CreateTag(ctx context.Context, ref RepoRef, tag, message, revision string) error {
	if err := ref.Validate(); err != nil {
		return err
	}
	if err := validateRefName("tag", tag); err != nil {
		return err
	}
	if err := validateRefName("revision", revision); err != nil {
		return err
	}
	spec := callSpec{
		method: http.MethodPost,
		path:   ref.apiPath("tag", url.PathEscape(revision)),
		body:   createTagBody{Tag: tag, Message: message},
	}
	return c.call(ctx, spec)
}

// DeleteTag deletes one exact tag.
//
// Spec: DELETE /api/{type}s/{owner}/{name}/tag/{tag}.
func (c *Client) DeleteTag(ctx context.Context, ref RepoRef, tag string) error {
	if err := ref.Validate(); err != nil {
		return err
	}
	if err := validateRefName("tag", tag); err != nil {
		return err
	}
	return c.call(ctx, callSpec{method: http.MethodDelete, path: ref.apiPath("tag", url.PathEscape(tag))})
}
