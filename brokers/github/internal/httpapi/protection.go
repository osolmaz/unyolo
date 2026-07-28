package httpapi

import (
	"net/http"
	"strings"

	"github.com/labstack/echo/v4"
	"github.com/osolmaz/unyolo/brokers/github/internal/githubauth"
)

func (s *Server) enforceReceivePackBackstops(c echo.Context, authorized []authorizedReceivePackRequest) error {
	branches := receivePackBranches(authorized)
	if len(branches) == 0 {
		return nil
	}
	owner := c.Param("owner")
	repo := strings.TrimSuffix(c.Param("repoGit"), ".git")
	api, err := s.githubInspectionAPI(c, owner, repo)
	if err != nil {
		return echo.NewHTTPError(http.StatusServiceUnavailable, "GitHub repository safety state is unavailable")
	}
	defaultBranch, err := api.DefaultBranch(c.Request().Context(), owner, repo)
	if err != nil {
		return echo.NewHTTPError(http.StatusServiceUnavailable, "GitHub repository safety state is unavailable")
	}
	for branch := range branches {
		if err := enforceBranchBackstop(c, api, owner, repo, branch, defaultBranch); err != nil {
			return err
		}
	}
	return nil
}

func (s *Server) githubInspectionAPI(c echo.Context, owner, repo string) (*githubauth.API, error) {
	repositoryCredential, err := s.githubCredentialForRepo(c, owner, repo)
	if err != nil {
		return nil, err
	}
	inspectionCredential, err := s.githubInspectionCredential(c, repositoryCredential)
	if err != nil {
		return nil, err
	}
	return s.githubCredentials.API(inspectionCredential)
}

func (s *Server) githubInspectionCredential(c echo.Context, repositoryCredential *githubauth.Credential) (*githubauth.Credential, error) {
	metadata := repositoryCredential.Metadata()
	if metadata.Kind != githubauth.KindInstallation {
		return repositoryCredential, nil
	}
	return s.githubCredentials.InstallationCredential(c.Request().Context(), metadata.InstallationID, metadata.RepositoryIDs,
		map[string]string{"administration": "read", "metadata": "read"})
}

func receivePackBranches(authorized []authorizedReceivePackRequest) map[string]bool {
	branches := map[string]bool{}
	for _, item := range authorized {
		ref := item.Request.Attrs["ref"]
		if strings.HasPrefix(ref, "refs/heads/") {
			branches[strings.TrimPrefix(ref, "refs/heads/")] = true
		}
	}
	return branches
}

func enforceBranchBackstop(c echo.Context, api *githubauth.API, owner, repo, branch, defaultBranch string) error {
	requiresPullRequest, err := api.BranchRequiresPullRequest(c.Request().Context(), owner, repo, branch)
	if err != nil {
		return echo.NewHTTPError(http.StatusServiceUnavailable, "GitHub branch safety state is unavailable")
	}
	if !requiresPullRequest {
		return nil
	}
	message := "protected branch writes must use a GitHub-native workflow"
	if branch == defaultBranch {
		message = "protected default-branch writes must use a GitHub-native workflow"
	}
	return echo.NewHTTPError(http.StatusForbidden, message)
}
