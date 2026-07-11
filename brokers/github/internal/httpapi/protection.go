package httpapi

import (
	"net/http"
	"strings"

	"github.com/labstack/echo/v4"
	"github.com/osolmaz/brokerkit/brokers/github/internal/githubapi"
)

func (s *Server) enforceReceivePackBackstops(c echo.Context, authorized []authorizedReceivePackRequest) error {
	branches := map[string]bool{}
	for _, item := range authorized {
		ref := item.Request.Attrs["ref"]
		if strings.HasPrefix(ref, "refs/heads/") {
			branches[strings.TrimPrefix(ref, "refs/heads/")] = true
		}
	}
	if len(branches) == 0 {
		return nil
	}
	owner := c.Param("owner")
	repo := strings.TrimSuffix(c.Param("repoGit"), ".git")
	token, err := s.githubCredentialForRepo(c, owner, repo)
	if err != nil {
		return err
	}
	reader := githubapi.Reader{BaseURL: s.githubAPIBaseURL, HTTPClient: s.githubReadClient}
	defaultBranch, err := reader.DefaultBranch(c.Request().Context(), token, owner, repo)
	if err != nil {
		return echo.NewHTTPError(http.StatusServiceUnavailable, "GitHub repository safety state is unavailable")
	}
	for branch := range branches {
		protected, err := reader.BranchProtected(c.Request().Context(), token, owner, repo, branch)
		if err != nil {
			return echo.NewHTTPError(http.StatusServiceUnavailable, "GitHub branch safety state is unavailable")
		}
		if protected {
			message := "protected branch writes must use a GitHub-native workflow"
			if branch == defaultBranch {
				message = "protected default-branch writes must use a GitHub-native workflow"
			}
			return echo.NewHTTPError(http.StatusForbidden, message)
		}
	}
	return nil
}
