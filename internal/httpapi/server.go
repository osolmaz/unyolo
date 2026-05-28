package httpapi

import (
	"context"
	"errors"
	"net/http"

	"github.com/dutifuldev/gitcba/internal/config"
	"github.com/dutifuldev/gitcba/internal/credential"
	"github.com/dutifuldev/gitcba/internal/githubaccess"
	"github.com/dutifuldev/gitcba/internal/security"
	"github.com/labstack/echo/v4"
	"github.com/labstack/echo/v4/middleware"
)

type Server struct {
	echo         *echo.Echo
	credential   *credential.Service
	githubAccess *githubaccess.Service
}

func New(cfg config.Config, credentialService *credential.Service, githubAccessService *githubaccess.Service) (*Server, error) {
	auth, err := security.NewTokenAuth(cfg.AdminToken)
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
	server := &Server{echo: e, credential: credentialService, githubAccess: githubAccessService}
	api := e.Group(cfg.APIPrefix)
	api.Use(auth.Middleware)
	api.POST("/credentials", server.registerCredential)
	api.GET("/credentials", server.listCredentials)
	api.GET("/credentials/:id", server.getCredential)
	api.POST("/github-access", server.configureGitHubAccess)
	api.GET("/github-access", server.listGitHubAccess)
	api.GET("/github-access/:id", server.getGitHubAccess)
	return server, nil
}

func (s *Server) Handler() http.Handler {
	return s.echo
}

type registerCredentialRequest struct {
	Name   string          `json:"name"`
	Kind   credential.Kind `json:"kind"`
	Secret string          `json:"secret"`
	Scopes []string        `json:"scopes"`
}

type configureGitHubAccessRequest struct {
	CredentialID string                       `json:"credential_id"`
	Owners       []string                     `json:"owners"`
	Repositories []githubaccess.RepositoryRef `json:"repositories"`
}

func (s *Server) registerCredential(c echo.Context) error {
	var request registerCredentialRequest
	if err := c.Bind(&request); err != nil {
		return echo.NewHTTPError(http.StatusBadRequest, "invalid JSON body")
	}
	secret, err := credential.NewSecretMaterial(request.Secret)
	request.Secret = ""
	if err != nil {
		return echo.NewHTTPError(http.StatusBadRequest, err.Error())
	}
	record, err := s.credential.Register(c.Request().Context(), credential.RegisterInput{
		Name:   request.Name,
		Kind:   request.Kind,
		Secret: secret,
		Scopes: request.Scopes,
	})
	if err != nil {
		return mapCredentialError(err)
	}
	return c.JSON(http.StatusCreated, record)
}

func (s *Server) listCredentials(c echo.Context) error {
	return jsonList(c, s.credential.List, mapCredentialError)
}

func (s *Server) getCredential(c echo.Context) error {
	return jsonGet(c, s.credential.Get, mapCredentialError)
}

func (s *Server) configureGitHubAccess(c echo.Context) error {
	var request configureGitHubAccessRequest
	if err := c.Bind(&request); err != nil {
		return echo.NewHTTPError(http.StatusBadRequest, "invalid JSON body")
	}
	selection, err := s.githubAccess.Configure(c.Request().Context(), githubaccess.ConfigureInput{
		CredentialID: request.CredentialID,
		Owners:       request.Owners,
		Repositories: request.Repositories,
	})
	if err != nil {
		return mapGitHubAccessError(err)
	}
	return c.JSON(http.StatusCreated, selection)
}

func (s *Server) listGitHubAccess(c echo.Context) error {
	return jsonList(c, s.githubAccess.List, mapGitHubAccessError)
}

func (s *Server) getGitHubAccess(c echo.Context) error {
	return jsonGet(c, s.githubAccess.Get, mapGitHubAccessError)
}

func health(c echo.Context) error {
	return c.JSON(http.StatusOK, map[string]bool{"ok": true})
}

func noStore(next echo.HandlerFunc) echo.HandlerFunc {
	return func(c echo.Context) error {
		c.Response().Header().Set(echo.HeaderCacheControl, "no-store")
		c.Response().Header().Set("Pragma", "no-cache")
		c.Response().Header().Set("X-Content-Type-Options", "nosniff")
		return next(c)
	}
}

func jsonList[T any](
	c echo.Context,
	list func(context.Context) ([]T, error),
	mapError func(error) error,
) error {
	records, err := list(c.Request().Context())
	if err != nil {
		return mapError(err)
	}
	return c.JSON(http.StatusOK, records)
}

func jsonGet[T any](
	c echo.Context,
	get func(context.Context, string) (T, error),
	mapError func(error) error,
) error {
	record, err := get(c.Request().Context(), c.Param("id"))
	if err != nil {
		return mapError(err)
	}
	return c.JSON(http.StatusOK, record)
}

func mapCredentialError(err error) error {
	return mapDomainError(err, credential.ErrNotFound, "credential not found")
}

func mapGitHubAccessError(err error) error {
	return mapDomainError(err, githubaccess.ErrNotFound, "github access selection not found")
}

func mapDomainError(err error, notFound error, message string) error {
	if errors.Is(err, notFound) {
		return echo.NewHTTPError(http.StatusNotFound, message)
	}
	return echo.NewHTTPError(http.StatusBadRequest, err.Error())
}
