package httpapi

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"net/url"
	"strings"

	"github.com/labstack/echo/v4"
	"github.com/osolmaz/brokerkit/brokers/github/internal/config"
	"github.com/osolmaz/brokerkit/brokers/github/internal/githubapp"
	"github.com/osolmaz/brokerkit/httpx"
	"github.com/osolmaz/brokerkit/internal/strictjson"
)

func configuredGitHubApp(cfg config.Config, apiBaseURL *url.URL, client *http.Client) (*githubapp.Source, error) {
	if strings.TrimSpace(cfg.GitHubAppID) == "" && len(cfg.GitHubAppPrivateKey) == 0 {
		return nil, nil
	}
	return githubapp.New(githubapp.Config{
		AppID:         cfg.GitHubAppID,
		PrivateKeyPEM: cfg.GitHubAppPrivateKey,
		APIBaseURL:    apiBaseURL,
		HTTPClient:    client,
	})
}

func (s *Server) fetchGitHubAppRepoList(c echo.Context) (*http.Response, error) {
	ids, err := s.githubApp.Installations(c.Request().Context())
	if err != nil {
		return nil, echo.NewHTTPError(http.StatusBadGateway, "github app installation lookup failed")
	}
	repos := make([]json.RawMessage, 0)
	for _, id := range ids {
		response, err := s.fetchGitHubAppInstallationRepos(c, id)
		if err != nil {
			return nil, err
		}
		if !successfulStatus(response.StatusCode) {
			return response, nil
		}
		installationRepos, err := decodeInstallationRepos(response.Body)
		_ = response.Body.Close()
		if err != nil {
			return nil, echo.NewHTTPError(http.StatusBadGateway, "decode github app repository list")
		}
		repos = append(repos, installationRepos...)
	}
	body, err := json.Marshal(map[string][]json.RawMessage{"repositories": repos})
	if err != nil {
		return nil, echo.NewHTTPError(http.StatusBadGateway, "encode github app repository list")
	}
	return &http.Response{
		StatusCode: http.StatusOK,
		Header:     make(http.Header),
		Body:       io.NopCloser(bytes.NewReader(body)),
	}, nil
}

func (s *Server) fetchGitHubAppInstallationRepos(c echo.Context, installationID int64) (*http.Response, error) {
	token, err := s.githubApp.InstallationToken(c.Request().Context(), installationID)
	if err != nil {
		return nil, echo.NewHTTPError(http.StatusBadGateway, "github app token minting failed")
	}
	request, err := http.NewRequestWithContext(c.Request().Context(), http.MethodGet, s.repoListURL(c, "installation", "repositories").String(), http.NoBody)
	if err != nil {
		return nil, echo.NewHTTPError(http.StatusBadGateway, "create upstream github request")
	}
	configureInstallationTokenRequest(request, token.Value)
	// #nosec G704 -- upstream URL is built from a fixed GitHub API base URL.
	markUpstreamDispatched(c)
	response, err := s.githubClient.Do(request)
	if err != nil {
		return nil, echo.NewHTTPError(http.StatusBadGateway, "upstream github request failed")
	}
	return response, nil
}

func decodeInstallationRepos(body io.Reader) ([]json.RawMessage, error) {
	data, err := httpx.ReadLimited(body, 10*1024*1024)
	if err != nil {
		return nil, err
	}
	var payload struct {
		Repositories []json.RawMessage `json:"repositories"`
	}
	if err := strictjson.Decode(data, &payload, false); err != nil {
		return nil, err
	}
	return payload.Repositories, nil
}

func (s *Server) configureGitHubAPIRequest(c echo.Context, request *http.Request, owner string, repo string) error {
	token, err := s.githubCredentialForRepo(c, owner, repo)
	if err != nil {
		return err
	}
	configureInstallationTokenRequest(request, token)
	return nil
}

func (s *Server) configureGitHubGitRequest(c echo.Context, request *http.Request, owner string, repo string) error {
	token, err := s.githubCredentialForRepo(c, owner, repo)
	if err != nil {
		return err
	}
	request.Header.Set("Authorization", githubGitAuthorization(token))
	return nil
}

func (s *Server) githubCredentialForRepo(c echo.Context, owner string, repo string) (string, error) {
	if s.githubApp == nil {
		return s.githubToken, nil
	}
	token, err := s.githubApp.InstallationTokenForRepo(c.Request().Context(), owner, repo)
	if err != nil {
		return "", echo.NewHTTPError(http.StatusBadGateway, "github app token minting failed")
	}
	c.Set("github_installation_id", token.InstallationID)
	return token.Value, nil
}

func configureInstallationTokenRequest(request *http.Request, token string) {
	request.Header.Set("Authorization", "Bearer "+token)
	request.Header.Set("Accept", "application/vnd.github+json")
	request.Header.Set("X-GitHub-Api-Version", "2022-11-28")
}
