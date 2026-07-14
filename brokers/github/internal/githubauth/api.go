package githubauth

import (
	"context"
	"errors"
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
