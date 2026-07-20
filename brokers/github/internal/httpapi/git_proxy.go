package httpapi

import (
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"

	"github.com/labstack/echo/v4"
	"github.com/osolmaz/brokerkit/git/protocol"
	"github.com/osolmaz/brokerkit/transport/http"
)

const upstreamDispatchedContextKey = "gh_broker_upstream_dispatched"

func markUpstreamDispatched(c echo.Context) {
	c.Set(upstreamDispatchedContextKey, true)
}

func (s *Server) proxyReceivePackAdvertisement(c echo.Context) error {
	c.Request().Header.Del("Accept-Encoding")
	response, err := s.forwardGit(c)
	if err != nil {
		return err
	}
	defer func() { _ = response.Body.Close() }()
	if response.StatusCode < http.StatusOK || response.StatusCode >= http.StatusMultipleChoices {
		httpx.CopyHeaders(c.Response().Header(), response.Header, githubProxyResponseHeader)
		return copyUpstreamResponse(c, response)
	}
	body, err := httpx.ReadLimited(response.Body, s.maxReceivePackBytes)
	if err != nil {
		if errors.Is(err, httpx.ErrBodyTooLarge) {
			return echo.NewHTTPError(http.StatusBadGateway, "Git receive-pack advertisement is too large")
		}
		return echo.NewHTTPError(http.StatusBadGateway, "read Git receive-pack advertisement")
	}
	rewritten, err := gitx.RemoveAdvertisementCapability(body, "thin-pack")
	if err != nil {
		return echo.NewHTTPError(http.StatusBadGateway, "parse Git receive-pack advertisement")
	}
	httpx.CopyHeaders(c.Response().Header(), response.Header, httpx.DropAny(githubProxyResponseHeader, httpx.RewrittenBodyHeader))
	c.Response().WriteHeader(response.StatusCode)
	_, err = c.Response().Write(rewritten)
	return err
}

func upstreamWasDispatched(c echo.Context) bool {
	return c.Get(upstreamDispatchedContextKey) == true
}

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
	markUpstreamDispatched(c)
	response, err := s.githubGitClient.Do(request)
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
