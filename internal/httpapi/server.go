package httpapi

import (
	"encoding/base64"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"

	"github.com/dutifuldev/gitcba/internal/config"
	"github.com/dutifuldev/gitcba/internal/githubaccess"
	"github.com/dutifuldev/gitcba/internal/security"
	"github.com/labstack/echo/v4"
	"github.com/labstack/echo/v4/middleware"
)

type Server struct {
	echo             *echo.Echo
	githubAccess     githubaccess.Config
	githubToken      string
	githubClient     *http.Client
	githubGitBaseURL *url.URL
	githubAPIBaseURL *url.URL
}

func New(cfg config.Config, githubAccess githubaccess.Config) (*Server, error) {
	auth, err := security.NewTokenAuth(cfg.SharedSecret)
	if err != nil {
		return nil, err
	}
	e := echo.New()
	e.HideBanner = true
	e.HidePort = true
	e.Use(middleware.Recover())
	e.Use(noStore)
	e.Use(middleware.BodyLimit("32K"))
	e.GET("/healthz", health)
	gitBaseURL, err := url.Parse("https://github.com")
	if err != nil {
		return nil, err
	}
	apiBaseURL, err := url.Parse("https://api.github.com")
	if err != nil {
		return nil, err
	}
	server := &Server{
		echo:             e,
		githubAccess:     githubAccess,
		githubToken:      cfg.GitHubToken,
		githubClient:     http.DefaultClient,
		githubGitBaseURL: gitBaseURL,
		githubAPIBaseURL: apiBaseURL,
	}
	protected := e.Group("")
	protected.Use(auth.Middleware)
	protected.GET("/:owner/:repoGit/info/refs", server.gitInfoRefs)
	protected.POST("/:owner/:repoGit/git-upload-pack", server.gitUploadPack)
	protected.POST("/:owner/:repoGit/git-receive-pack", server.gitReceivePack)
	protected.POST("/repos/:owner/:repo/pulls", server.createPullRequest)
	return server, nil
}

func (s *Server) Handler() http.Handler {
	return s.echo
}

func health(c echo.Context) error {
	return c.JSON(http.StatusOK, map[string]bool{"ok": true})
}

func (s *Server) gitInfoRefs(c echo.Context) error {
	operation, err := operationFromGitService(c.QueryParam("service"))
	if err != nil {
		return err
	}
	return s.authorizeBrokerOperation(c, operation, s.proxyGit)
}

func (s *Server) gitUploadPack(c echo.Context) error {
	return s.authorizeBrokerOperation(c, githubaccess.OperationGitUploadPack, s.proxyGit)
}

func (s *Server) gitReceivePack(c echo.Context) error {
	return s.authorizeBrokerOperation(c, githubaccess.OperationGitReceivePack, s.proxyGit)
}

func (s *Server) createPullRequest(c echo.Context) error {
	return s.authorizeBrokerOperation(c, githubaccess.OperationCreatePullRequest, s.proxyGitHubAPI)
}

func (s *Server) authorizeBrokerOperation(
	c echo.Context,
	operation githubaccess.Operation,
	run func(echo.Context) error,
) error {
	if decision := s.decide(c, operation); !decision.Allowed {
		return echo.NewHTTPError(http.StatusForbidden, decision.Reason)
	}
	return run(c)
}

func (s *Server) decide(c echo.Context, operation githubaccess.Operation) githubaccess.Decision {
	repo := c.Param("repo")
	if repo == "" {
		repo = c.Param("repoGit")
	}
	return s.githubAccess.Decide(githubaccess.DecisionInput{
		Operation: operation,
		Repository: githubaccess.RepositoryRef{
			Owner: c.Param("owner"),
			Name:  strings.TrimSuffix(repo, ".git"),
		},
		TargetOwner: c.Param("owner"),
	})
}

func operationFromGitService(service string) (githubaccess.Operation, error) {
	switch service {
	case "git-upload-pack":
		return githubaccess.OperationGitUploadPack, nil
	case "git-receive-pack":
		return githubaccess.OperationGitReceivePack, nil
	default:
		return "", echo.NewHTTPError(http.StatusBadRequest, "unsupported git service")
	}
}

func noStore(next echo.HandlerFunc) echo.HandlerFunc {
	return func(c echo.Context) error {
		c.Response().Header().Set(echo.HeaderCacheControl, "no-store")
		c.Response().Header().Set("Pragma", "no-cache")
		c.Response().Header().Set("X-Content-Type-Options", "nosniff")
		return next(c)
	}
}

func (s *Server) proxyGit(c echo.Context) error {
	upstreamURL := s.githubGitBaseURL.JoinPath(c.Param("owner"), c.Param("repoGit"), strings.TrimPrefix(c.Request().URL.Path, gitRepoPrefix(c)))
	upstreamURL.RawQuery = c.Request().URL.RawQuery
	return s.proxyTo(c, upstreamURL, func(request *http.Request) {
		request.Header.Set("Authorization", githubGitAuthorization(s.githubToken))
	})
}

func gitRepoPrefix(c echo.Context) string {
	return fmt.Sprintf("/%s/%s/", c.Param("owner"), c.Param("repoGit"))
}

func (s *Server) proxyGitHubAPI(c echo.Context) error {
	upstreamURL := s.githubAPIBaseURL.JoinPath("repos", c.Param("owner"), c.Param("repo"), "pulls")
	return s.proxyTo(c, upstreamURL, func(request *http.Request) {
		request.Header.Set("Authorization", "Bearer "+s.githubToken)
		request.Header.Set("Accept", "application/vnd.github+json")
		request.Header.Set("X-GitHub-Api-Version", "2022-11-28")
	})
}

func (s *Server) proxyTo(c echo.Context, upstreamURL *url.URL, configure func(*http.Request)) error {
	request, err := http.NewRequestWithContext(
		c.Request().Context(),
		c.Request().Method,
		upstreamURL.String(),
		c.Request().Body,
	)
	if err != nil {
		return echo.NewHTTPError(http.StatusBadGateway, "create upstream github request")
	}
	copyRequestHeaders(request.Header, c.Request().Header)
	configure(request)
	return s.doProxy(c, request)
}

func (s *Server) doProxy(c echo.Context, request *http.Request) error {
	// #nosec G704 -- upstream URLs are built from fixed GitHub base URLs and file-policy-gated owner/repo params.
	response, err := s.githubClient.Do(request)
	if err != nil {
		return echo.NewHTTPError(http.StatusBadGateway, "upstream github request failed")
	}
	defer func() {
		_ = response.Body.Close()
	}()
	copyResponseHeaders(c.Response().Header(), response.Header)
	c.Response().WriteHeader(response.StatusCode)
	_, err = io.Copy(c.Response(), response.Body)
	return err
}

func copyRequestHeaders(dst http.Header, src http.Header) {
	copyHeaders(dst, src, dropRequestHeader)
}

func copyResponseHeaders(dst http.Header, src http.Header) {
	copyHeaders(dst, src, hopByHopHeader)
}

func copyHeaders(dst http.Header, src http.Header, drop func(string) bool) {
	for key, values := range src {
		if drop(key) {
			continue
		}
		for _, value := range values {
			dst.Add(key, value)
		}
	}
}

func dropRequestHeader(key string) bool {
	return hopByHopHeader(key) ||
		strings.EqualFold(key, "Authorization") ||
		strings.EqualFold(key, "Cookie")
}

func hopByHopHeader(key string) bool {
	switch strings.ToLower(key) {
	case "connection", "keep-alive", "proxy-authenticate", "proxy-authorization",
		"te", "trailer", "transfer-encoding", "upgrade":
		return true
	default:
		return false
	}
}

func githubGitAuthorization(token string) string {
	credential := base64.StdEncoding.EncodeToString([]byte("x-access-token:" + token))
	return "Basic " + credential
}
