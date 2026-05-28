package httpapi

import (
	"context"
	"errors"
	"net/http"
	"strings"

	"github.com/dutifuldev/gitcba/internal/config"
	"github.com/dutifuldev/gitcba/internal/credential"
	"github.com/dutifuldev/gitcba/internal/policy"
	"github.com/dutifuldev/gitcba/internal/security"
	"github.com/labstack/echo/v4"
	"github.com/labstack/echo/v4/middleware"
)

type Server struct {
	echo       *echo.Echo
	credential *credential.Service
	policy     *policy.Service
}

func New(cfg config.Config, credentialService *credential.Service, policyService *policy.Service) (*Server, error) {
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
	server := &Server{echo: e, credential: credentialService, policy: policyService}
	api := e.Group(cfg.APIPrefix)
	api.Use(auth.Middleware)
	api.POST("/credentials", server.registerCredential)
	api.GET("/credentials", server.listCredentials)
	api.GET("/credentials/:id", server.getCredential)
	api.POST("/repos", server.configureRepository)
	api.GET("/repos", server.listRepositories)
	api.GET("/repos/:id", server.getRepository)
	return server, nil
}

func (s *Server) Handler() http.Handler {
	return s.echo
}

type registerCredentialRequest struct {
	TenantID string          `json:"tenant_id"`
	Name     string          `json:"name"`
	Kind     credential.Kind `json:"kind"`
	Secret   string          `json:"secret"`
	Scopes   []string        `json:"scopes"`
}

type configureRepositoryRequest struct {
	TenantID     string                  `json:"tenant_id"`
	Owner        string                  `json:"owner"`
	Name         string                  `json:"name"`
	Private      bool                    `json:"private"`
	CredentialID string                  `json:"credential_id"`
	Policy       policy.RepositoryPolicy `json:"policy"`
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
		TenantID: request.TenantID,
		Name:     request.Name,
		Kind:     request.Kind,
		Secret:   secret,
		Scopes:   request.Scopes,
	})
	if err != nil {
		return mapCredentialError(err)
	}
	return c.JSON(http.StatusCreated, record)
}

func (s *Server) listCredentials(c echo.Context) error {
	return jsonTenantList(c, s.credential.List, mapCredentialError)
}

func (s *Server) getCredential(c echo.Context) error {
	return jsonTenantGet(c, s.credential.Get, mapCredentialError)
}

func (s *Server) configureRepository(c echo.Context) error {
	var request configureRepositoryRequest
	if err := c.Bind(&request); err != nil {
		return echo.NewHTTPError(http.StatusBadRequest, "invalid JSON body")
	}
	repository, err := s.policy.Configure(c.Request().Context(), policy.RepositoryInput{
		TenantID:     request.TenantID,
		Owner:        request.Owner,
		Name:         request.Name,
		Private:      request.Private,
		CredentialID: request.CredentialID,
		Policy:       request.Policy,
	})
	if err != nil {
		return mapPolicyError(err)
	}
	return c.JSON(http.StatusCreated, repository)
}

func (s *Server) listRepositories(c echo.Context) error {
	return jsonTenantList(c, s.policy.List, mapPolicyError)
}

func (s *Server) getRepository(c echo.Context) error {
	return jsonTenantGet(c, s.policy.Get, mapPolicyError)
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

func tenantFromRequest(c echo.Context) string {
	return strings.TrimSpace(c.Request().Header.Get("X-CBA-Tenant"))
}

func requireTenant(c echo.Context) (string, error) {
	tenantID := tenantFromRequest(c)
	if tenantID == "" {
		return "", echo.NewHTTPError(http.StatusBadRequest, "X-CBA-Tenant header is required")
	}
	return tenantID, nil
}

func jsonTenantList[T any](
	c echo.Context,
	list func(context.Context, string) ([]T, error),
	mapError func(error) error,
) error {
	tenantID, err := requireTenant(c)
	if err != nil {
		return err
	}
	records, err := list(c.Request().Context(), tenantID)
	if err != nil {
		return mapError(err)
	}
	return c.JSON(http.StatusOK, records)
}

func jsonTenantGet[T any](
	c echo.Context,
	get func(context.Context, string, string) (T, error),
	mapError func(error) error,
) error {
	tenantID, err := requireTenant(c)
	if err != nil {
		return err
	}
	record, err := get(c.Request().Context(), tenantID, c.Param("id"))
	if err != nil {
		return mapError(err)
	}
	return c.JSON(http.StatusOK, record)
}

func mapCredentialError(err error) error {
	return mapDomainError(err, credential.ErrNotFound, "credential not found")
}

func mapPolicyError(err error) error {
	return mapDomainError(err, policy.ErrNotFound, "repository not found")
}

func mapDomainError(err error, notFound error, message string) error {
	if errors.Is(err, notFound) {
		return echo.NewHTTPError(http.StatusNotFound, message)
	}
	return echo.NewHTTPError(http.StatusBadRequest, err.Error())
}
