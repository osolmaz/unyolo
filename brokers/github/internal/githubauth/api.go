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

func (a *API) BranchRequiresPullRequest(ctx context.Context, owner, repo, branch string) (bool, error) {
	if a == nil || a.client == nil {
		return false, errors.New("GitHub API client is unavailable")
	}
	rules, _, rulesErr := a.client.Repositories.ListRulesForBranch(ctx, owner, repo, branch, &github.ListOptions{PerPage: 100})
	if rulesErr == nil {
		return rules != nil && len(rules.PullRequest) > 0, nil
	}
	protection, _, protectionErr := a.client.Repositories.GetBranchProtection(ctx, owner, repo, branch)
	if protectionErr == nil && protection != nil && protection.RequiredPullRequestReviews != nil {
		return true, nil
	}
	return classifyBranchProtectionErrors(rulesErr, protectionErr)
}

func (a *API) BranchProtected(ctx context.Context, owner, repo, branch string) (bool, error) {
	if a == nil || a.client == nil {
		return false, errors.New("GitHub API client is unavailable")
	}
	rules, _, rulesErr := a.client.Repositories.ListRulesForBranch(ctx, owner, repo, branch, &github.ListOptions{PerPage: 100})
	if branchRulesProtected(rules, rulesErr) {
		return true, nil
	}
	_, _, protectionErr := a.client.Repositories.GetBranchProtection(ctx, owner, repo, branch)
	if protectionErr == nil {
		return true, nil
	}
	return classifyBranchProtectionErrors(rulesErr, protectionErr)
}

func branchRulesProtected(rules *github.BranchRules, err error) bool {
	return err == nil && rules != nil && !reflect.ValueOf(*rules).IsZero()
}

func classifyBranchProtectionErrors(rulesErr, protectionErr error) (bool, error) {
	if err := notFoundOrClassified(rulesErr); err != nil {
		return false, err
	}
	if err := notFoundOrClassified(protectionErr); err != nil {
		return false, err
	}
	return false, nil
}

func notFoundOrClassified(err error) error {
	classified := classifyAPIError(err)
	if IsNotFound(classified) {
		return nil
	}
	return classified
}
