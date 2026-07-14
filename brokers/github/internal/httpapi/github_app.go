package httpapi

import (
	"context"
	"net/http"
	"strings"

	"github.com/labstack/echo/v4"
	"github.com/osolmaz/brokerkit/brokers/github/internal/githubauth"
	"github.com/osolmaz/brokerkit/brokers/github/internal/policy"
)

const githubOperationContextKey = "gh_broker_operation"

func (s *Server) configureGitHubGitRequest(c echo.Context, request *http.Request, owner, repo string) error {
	credential, err := s.githubCredentialForRepo(c, owner, repo)
	if err != nil {
		return err
	}
	return credential.AuthorizeGit(request)
}

func (s *Server) githubCredentialForRepo(c echo.Context, owner, repo string) (*githubauth.Credential, error) {
	operation, _ := c.Get(githubOperationContextKey).(string)
	credential, err := s.githubCredentialForRepoContext(c.Request().Context(), operation, owner, repo)
	if err != nil {
		return nil, echo.NewHTTPError(http.StatusBadGateway, "GitHub credential acquisition failed")
	}
	if installationID := credential.Metadata().InstallationID; installationID > 0 {
		c.Set("github_installation_id", installationID)
	}
	return credential, nil
}

func (s *Server) githubCredentialForRepoContext(ctx context.Context, operation string, owner, repo string) (*githubauth.Credential, error) {
	if strings.TrimSpace(operation) == "" {
		operation = string(policy.OperationContentsRead)
	}
	return s.githubCredentials.RepositoryCredential(ctx, operation, owner, repo)
}
