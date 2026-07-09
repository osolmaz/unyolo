package httpapi

import (
	"fmt"
	"net/http"
	"net/url"
	"strings"

	"github.com/labstack/echo/v4"
	"github.com/osolmaz/brokerkit/httpx"
)

func (s *Server) forwardGit(c echo.Context) (*http.Response, error) {
	request, err := http.NewRequestWithContext(
		c.Request().Context(),
		c.Request().Method,
		s.gitUpstreamURL(c).String(),
		c.Request().Body,
	)
	if err != nil {
		return nil, echo.NewHTTPError(http.StatusBadGateway, "create upstream github request")
	}
	httpx.CopyHeaders(request.Header, c.Request().Header, httpx.ProxyRequestHeader)
	if err := s.configureGitHubGitRequest(c, request, c.Param("owner"), strings.TrimSuffix(c.Param("repoGit"), ".git")); err != nil {
		return nil, err
	}
	// #nosec G704 -- upstream URL is built from a fixed GitHub base URL and policy-gated route params.
	response, err := s.githubClient.Do(request)
	if err != nil {
		return nil, echo.NewHTTPError(http.StatusBadGateway, "upstream github request failed")
	}
	return response, nil
}

func (s *Server) gitUpstreamURL(c echo.Context) *url.URL {
	upstreamURL := s.githubGitBaseURL.JoinPath(c.Param("owner"), c.Param("repoGit"), strings.TrimPrefix(c.Request().URL.Path, gitRepoPrefix(c)))
	upstreamURL.RawQuery = c.Request().URL.RawQuery
	return upstreamURL
}

func gitRepoPrefix(c echo.Context) string {
	return fmt.Sprintf("/%s/%s/", c.Param("owner"), c.Param("repoGit"))
}
