// Package githubapi implements bounded, credential-safe GitHub API reads.
package githubapi

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
)

const maxResponseBytes = 1 << 20

type Reader struct {
	BaseURL    *url.URL
	HTTPClient *http.Client
}

type StatusError struct{ Code int }

func (err StatusError) Error() string { return fmt.Sprintf("GitHub API returned status %d", err.Code) }

func StatusCode(err error) (int, bool) {
	var statusErr StatusError
	if !errors.As(err, &statusErr) {
		return 0, false
	}
	return statusErr.Code, true
}

func (r Reader) DefaultBranch(ctx context.Context, token string, owner string, repo string) (string, error) {
	var payload struct {
		DefaultBranch string `json:"default_branch"`
	}
	if err := r.getJSON(ctx, token, r.BaseURL.JoinPath("repos", owner, repo), &payload); err != nil {
		return "", err
	}
	payload.DefaultBranch = strings.TrimSpace(payload.DefaultBranch)
	if payload.DefaultBranch == "" {
		return "", errors.New("repository response omitted default branch")
	}
	return payload.DefaultBranch, nil
}

func (r Reader) BranchProtected(ctx context.Context, token string, owner string, repo string, branch string) (bool, error) {
	var rules []json.RawMessage
	rulesErr := r.getJSON(ctx, token, r.BaseURL.JoinPath("repos", owner, repo, "rules", "branches", branch), &rules)
	if rulesErr == nil && len(rules) > 0 {
		return true, nil
	}
	var protection map[string]any
	protectionErr := r.getJSON(ctx, token, r.BaseURL.JoinPath("repos", owner, repo, "branches", branch, "protection"), &protection)
	if protectionErr == nil {
		return true, nil
	}
	if !isNotFound(rulesErr) {
		return false, rulesErr
	}
	if !isNotFound(protectionErr) {
		return false, protectionErr
	}
	return false, nil
}

func (r Reader) getJSON(ctx context.Context, token string, endpoint *url.URL, out any) error {
	if r.BaseURL == nil || r.HTTPClient == nil {
		return errors.New("GitHub API reader is not configured")
	}
	request, err := githubRequest(ctx, token, endpoint)
	if err != nil {
		return err
	}
	response, err := r.HTTPClient.Do(request)
	if err != nil {
		return errors.New("GitHub API request failed")
	}
	defer func() { _ = response.Body.Close() }()
	return decodeGitHubResponse(response, out)
}

func githubRequest(ctx context.Context, token string, endpoint *url.URL) (*http.Request, error) {
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint.String(), http.NoBody)
	if err != nil {
		return nil, err
	}
	request.Header.Set("Authorization", "Bearer "+token)
	request.Header.Set("Accept", "application/vnd.github+json")
	request.Header.Set("X-GitHub-Api-Version", "2022-11-28")
	return request, nil
}

func decodeGitHubResponse(response *http.Response, out any) error {
	if response.StatusCode < http.StatusOK || response.StatusCode >= http.StatusMultipleChoices {
		return StatusError{Code: response.StatusCode}
	}
	payload, err := io.ReadAll(io.LimitReader(response.Body, maxResponseBytes+1))
	if err != nil || len(payload) > maxResponseBytes {
		return errors.New("GitHub API response was invalid")
	}
	if err := json.Unmarshal(payload, out); err != nil {
		return errors.New("GitHub API response was invalid")
	}
	return nil
}

func isNotFound(err error) bool {
	if err == nil {
		return true
	}
	code, ok := StatusCode(err)
	return ok && code == http.StatusNotFound
}
