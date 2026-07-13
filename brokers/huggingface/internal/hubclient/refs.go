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
	return readResource(ctx, c, ref.Validate, ref.apiPath("refs"), func(wire refsWire) Refs { return wire.toRefs() })
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
	return c.deleteRef(ctx, ref, "branch", branch)
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
	return c.deleteRef(ctx, ref, "tag", tag)
}

func (c *Client) deleteRef(ctx context.Context, ref RepoRef, kind, name string) error {
	if err := ref.Validate(); err != nil {
		return err
	}
	if err := validateRefName(kind, name); err != nil {
		return err
	}
	return c.call(ctx, callSpec{method: http.MethodDelete, path: ref.apiPath(kind, url.PathEscape(name))})
}

func readResource[Wire, Result any](ctx context.Context, client *Client, validate func() error, path string, project func(Wire) Result) (Result, error) {
	var wire Wire
	if err := validate(); err != nil {
		var zero Result
		return zero, err
	}
	if err := client.call(ctx, callSpec{method: http.MethodGet, path: path, out: &wire}); err != nil {
		var zero Result
		return zero, err
	}
	return project(wire), nil
}
