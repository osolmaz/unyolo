package githubauth

import (
	"context"
	"errors"
	"net/http"
	"strconv"
	"strings"

	"github.com/osolmaz/unyolo/internal/strictjson"
)

// PullRequestSnapshot is the secret-free state required to bind and verify a
// merge plan. GitHub remains authoritative for the final merge decision.
type PullRequestSnapshot struct {
	ID             int64
	Number         int64
	NodeID         string
	State          string
	Draft          bool
	Merged         bool
	Mergeable      *bool
	MergeableState string
	HeadSHA        string
}

type pullRequestPayload struct {
	ID             int64  `json:"id"`
	Number         int64  `json:"number"`
	NodeID         string `json:"node_id"`
	State          string `json:"state"`
	Draft          bool   `json:"draft"`
	Merged         bool   `json:"merged"`
	Mergeable      *bool  `json:"mergeable"`
	MergeableState string `json:"mergeable_state"`
	Head           struct {
		SHA string `json:"sha"`
	} `json:"head"`
}

// PullRequest returns one bounded merge-state snapshot using the credential
// selected for the immutable operation plan.
func (m *Manager) PullRequest(ctx context.Context, selector Metadata, owner, repo string, number int64) (PullRequestSnapshot, error) {
	request, err := m.pullRequestRequest(ctx, owner, repo, number)
	if err != nil {
		return PullRequestSnapshot{}, err
	}
	response, err := m.doAPI(ctx, selector, request)
	if err != nil {
		return PullRequestSnapshot{}, err
	}
	defer func() { _ = response.Body.Close() }()
	body, err := limitedBody(response.Body, 256<<10)
	if err != nil {
		return PullRequestSnapshot{}, err
	}
	return decodePullRequestSnapshot(body, number)
}

func (m *Manager) pullRequestRequest(ctx context.Context, owner, repo string, number int64) (*http.Request, error) {
	if m == nil || strings.TrimSpace(owner) == "" || strings.TrimSpace(repo) == "" || number <= 0 {
		return nil, errors.New("GitHub pull request selector is invalid")
	}
	path := "repos/" + escapePathParameter(owner) + "/" + escapePathParameter(repo) + "/pulls/" + strconv.FormatInt(number, 10)
	requestURL, err := m.restURL(path, nil)
	if err != nil {
		return nil, err
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, requestURL, http.NoBody)
	if err != nil {
		return nil, errors.New("create GitHub pull request request")
	}
	return request, nil
}

func decodePullRequestSnapshot(body []byte, number int64) (PullRequestSnapshot, error) {
	var payload pullRequestPayload
	if strictjson.Decode(body, &payload, false) != nil || !validPullRequestPayload(payload, number) {
		return PullRequestSnapshot{}, errors.New("GitHub pull request response is invalid")
	}
	return PullRequestSnapshot{
		ID: payload.ID, Number: payload.Number, NodeID: payload.NodeID, State: payload.State, Draft: payload.Draft, Merged: payload.Merged,
		Mergeable: payload.Mergeable, MergeableState: payload.MergeableState, HeadSHA: payload.Head.SHA,
	}, nil
}

func validPullRequestPayload(payload pullRequestPayload, number int64) bool {
	return payload.ID > 0 && payload.Number == number && strings.TrimSpace(payload.NodeID) != "" && strings.TrimSpace(payload.Head.SHA) != ""
}
