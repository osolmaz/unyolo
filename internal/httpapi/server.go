package httpapi

import (
	"net/http"
	"strings"

	"github.com/dutifuldev/gitcba/internal/config"
	"github.com/dutifuldev/gitcba/internal/githubaccess"
	"github.com/dutifuldev/gitcba/internal/security"
	"github.com/labstack/echo/v4"
	"github.com/labstack/echo/v4/middleware"
)

type Server struct {
	echo         *echo.Echo
	githubAccess githubaccess.Config
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
	server := &Server{echo: e, githubAccess: githubAccess}
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
	return s.authorizeBrokerOperation(c, operation)
}

func (s *Server) gitUploadPack(c echo.Context) error {
	return s.authorizeBrokerOperation(c, githubaccess.OperationGitUploadPack)
}

func (s *Server) gitReceivePack(c echo.Context) error {
	return s.authorizeBrokerOperation(c, githubaccess.OperationGitReceivePack)
}

func (s *Server) createPullRequest(c echo.Context) error {
	return s.authorizeBrokerOperation(c, githubaccess.OperationCreatePullRequest)
}

func (s *Server) authorizeBrokerOperation(c echo.Context, operation githubaccess.Operation) error {
	if decision := s.decide(c, operation); !decision.Allowed {
		return echo.NewHTTPError(http.StatusForbidden, decision.Reason)
	}
	return notImplemented(c, operation)
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

func notImplemented(c echo.Context, operation githubaccess.Operation) error {
	return c.JSON(http.StatusNotImplemented, map[string]string{
		"error":     "broker operation is not implemented yet",
		"operation": string(operation),
	})
}

func noStore(next echo.HandlerFunc) echo.HandlerFunc {
	return func(c echo.Context) error {
		c.Response().Header().Set(echo.HeaderCacheControl, "no-store")
		c.Response().Header().Set("Pragma", "no-cache")
		c.Response().Header().Set("X-Content-Type-Options", "nosniff")
		return next(c)
	}
}
