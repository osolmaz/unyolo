package githubauth

import (
	"context"
	"errors"
	"net/http"
	"reflect"

	github "github.com/google/go-github/v88/github"
)

type API struct{ client *github.Client }

func (a *API) DefaultBranch(ctx context.Context, owner, repo string) (string, error) {
	if a == nil || a.client == nil {
		return "", errors.New("GitHub API client is unavailable")
	}
	repository, _, err := a.client.Repositories.Get(ctx, owner, repo)
	if err != nil {
		return "", classifyAPIError(err)
	}
	if repository.GetDefaultBranch() == "" {
		return "", errors.New("GitHub repository response omitted its default branch")
	}
	return repository.GetDefaultBranch(), nil
}

func (a *API) BranchProtected(ctx context.Context, owner, repo, branch string) (bool, error) {
	if a == nil || a.client == nil {
		return false, errors.New("GitHub API client is unavailable")
	}
	rules, _, rulesErr := a.client.Repositories.ListRulesForBranch(ctx, owner, repo, branch, &github.ListOptions{PerPage: 100})
	if rulesErr == nil && rules != nil && !reflect.ValueOf(*rules).IsZero() {
		return true, nil
	}
	_, _, protectionErr := a.client.Repositories.GetBranchProtection(ctx, owner, repo, branch)
	if protectionErr == nil {
		return true, nil
	}
	if rulesErr != nil && !IsNotFound(classifyAPIError(rulesErr)) {
		return false, classifyAPIError(rulesErr)
	}
	if !IsNotFound(classifyAPIError(protectionErr)) {
		return false, classifyAPIError(protectionErr)
	}
	return false, nil
}

type PullRequest struct {
	Number int
	URL    string
}

func (a *API) CreatePullRequest(ctx context.Context, owner, repo, title, head, base, body string) (PullRequest, bool, error) {
	if a == nil || a.client == nil {
		return PullRequest{}, false, errors.New("GitHub API client is unavailable")
	}
	created, response, err := a.client.PullRequests.Create(ctx, owner, repo, &github.NewPullRequest{
		Title: &title, Head: &head, Base: &base, Body: &body,
	})
	if err != nil {
		status := responseStatus(nil)
		if response != nil {
			status = response.StatusCode
		}
		return PullRequest{}, status >= http.StatusBadRequest && status < http.StatusInternalServerError, classifyAPIError(err)
	}
	if created.GetNumber() <= 0 || created.GetHTMLURL() == "" {
		return PullRequest{}, false, errors.New("GitHub pull request response is invalid")
	}
	return PullRequest{Number: created.GetNumber(), URL: created.GetHTMLURL()}, true, nil
}

func (a *API) listUserRepositories(ctx context.Context) ([]*github.Repository, error) {
	if a == nil || a.client == nil {
		return nil, errors.New("GitHub API client is unavailable")
	}
	var result []*github.Repository
	opts := &github.RepositoryListByAuthenticatedUserOptions{ListOptions: github.ListOptions{PerPage: 100}}
	for page := 0; page < maxInstallationPages; page++ {
		items, response, err := a.client.Repositories.ListByAuthenticatedUser(ctx, opts)
		if err != nil {
			return nil, classifyAPIError(err)
		}
		result = append(result, items...)
		if response == nil || response.NextPage == 0 {
			return result, nil
		}
		opts.Page = response.NextPage
	}
	return nil, errors.New("GitHub repository listing exceeded its page limit")
}

func (a *API) listInstallationRepositories(ctx context.Context) ([]*github.Repository, error) {
	if a == nil || a.client == nil {
		return nil, errors.New("GitHub API client is unavailable")
	}
	var result []*github.Repository
	opts := &github.ListOptions{PerPage: 100}
	for page := 0; page < maxInstallationPages; page++ {
		items, response, err := a.client.Apps.ListRepos(ctx, opts)
		if err != nil {
			return nil, classifyAPIError(err)
		}
		result = append(result, items.Repositories...)
		if response == nil || response.NextPage == 0 {
			return result, nil
		}
		opts.Page = response.NextPage
	}
	return nil, errors.New("GitHub installation repository listing exceeded its page limit")
}
