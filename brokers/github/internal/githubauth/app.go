package githubauth

import (
	"context"
	"errors"
	"net/http"
	"net/url"
	"strconv"
	"strings"

	"github.com/bradleyfalzon/ghinstallation/v2"
	github "github.com/google/go-github/v88/github"
)

const (
	installationPageSize = 100
	maxInstallationPages = 100
)

type appProvider struct {
	client *github.Client
	apiURL *url.URL
	round  http.RoundTripper
}

func newAppProvider(appID string, privateKey []byte, apiURL *url.URL, client *http.Client) (*appProvider, error) {
	id, err := strconv.ParseInt(strings.TrimSpace(appID), 10, 64)
	if err != nil || id <= 0 {
		return nil, errors.New("GitHub App id is invalid")
	}
	appTransport, err := ghinstallation.NewAppsTransport(versionTransport{base: transport(client)}, id, privateKey)
	if err != nil {
		return nil, errors.New("GitHub App private key is invalid")
	}
	sdk, err := newGitHubClient(cloneHTTPClient(client, appTransport), apiURL, nil)
	if err != nil {
		return nil, errors.New("initialize GitHub App client")
	}
	return &appProvider{client: sdk, apiURL: apiURL, round: appTransport}, nil
}

func (p *appProvider) check(ctx context.Context) error {
	if p == nil || p.client == nil {
		return errors.New("GitHub App credential is unavailable")
	}
	_, _, err := p.client.Apps.Get(ctx, "")
	return classifyAPIError(err)
}

func (p *appProvider) repositoryInstallation(ctx context.Context, owner, repo string) (*github.Installation, error) {
	if p == nil || p.client == nil || strings.TrimSpace(owner) == "" || strings.TrimSpace(repo) == "" {
		return nil, errors.New("GitHub repository installation lookup is invalid")
	}
	installation, _, err := p.client.Apps.GetRepositoryInstallation(ctx, owner, repo)
	if err != nil {
		return nil, classifyAPIError(err)
	}
	if installation.GetID() <= 0 || !installation.GetSuspendedAt().IsZero() {
		return nil, errors.New("GitHub repository installation is unavailable")
	}
	return installation, nil
}

func (p *appProvider) installations(ctx context.Context) ([]*github.Installation, error) {
	if p == nil || p.client == nil {
		return nil, errors.New("GitHub App credential is unavailable")
	}
	result := make([]*github.Installation, 0, installationPageSize)
	opts := &github.ListOptions{PerPage: installationPageSize, Page: 1}
	for page := 0; page < maxInstallationPages; page++ {
		items, response, err := p.client.Apps.ListInstallations(ctx, opts)
		if err != nil {
			return nil, classifyAPIError(err)
		}
		for _, item := range items {
			if item.GetID() > 0 {
				result = append(result, item)
			}
		}
		if response == nil || response.NextPage == 0 {
			return result, nil
		}
		opts.Page = response.NextPage
	}
	return nil, errors.New("GitHub installation listing exceeded its page limit")
}

func (p *appProvider) installationForAccount(ctx context.Context, account string) (*github.Installation, error) {
	account = strings.TrimSpace(account)
	if account == "" {
		return nil, errors.New("GitHub installation account is required")
	}
	installations, err := p.installations(ctx)
	if err != nil {
		return nil, err
	}
	for _, installation := range installations {
		if strings.EqualFold(installation.GetAccount().GetLogin(), account) && installation.GetID() > 0 && installation.GetSuspendedAt().IsZero() {
			return installation, nil
		}
	}
	return nil, errors.New("GitHub installation is unavailable")
}
