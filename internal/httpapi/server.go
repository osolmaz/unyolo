package httpapi

import (
	"errors"
	"net/http"
	"strings"

	"github.com/dutifuldev/gitcba/internal/config"
	"github.com/dutifuldev/gitcba/internal/credential"
	"github.com/dutifuldev/gitcba/internal/security"
	"github.com/labstack/echo/v4"
	"github.com/labstack/echo/v4/middleware"
)

type Server struct {
	echo       *echo.Echo
	credential *credential.Service
}

func New(cfg config.Config, service *credential.Service) (*Server, error) {
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
	server := &Server{echo: e, credential: service}
	api := e.Group(cfg.APIPrefix)
	api.Use(auth.Middleware)
	api.POST("/credentials", server.registerCredential)
	api.GET("/credentials", server.listCredentials)
	api.GET("/credentials/:id", server.getCredential)
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
	tenantID := tenantFromRequest(c)
	if tenantID == "" {
		return echo.NewHTTPError(http.StatusBadRequest, "X-CBA-Tenant header is required")
	}
	records, err := s.credential.List(c.Request().Context(), tenantID)
	if err != nil {
		return mapCredentialError(err)
	}
	return c.JSON(http.StatusOK, records)
}

func (s *Server) getCredential(c echo.Context) error {
	tenantID := tenantFromRequest(c)
	if tenantID == "" {
		return echo.NewHTTPError(http.StatusBadRequest, "X-CBA-Tenant header is required")
	}
	record, err := s.credential.Get(c.Request().Context(), tenantID, c.Param("id"))
	if err != nil {
		return mapCredentialError(err)
	}
	return c.JSON(http.StatusOK, record)
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

func mapCredentialError(err error) error {
	if errors.Is(err, credential.ErrNotFound) {
		return echo.NewHTTPError(http.StatusNotFound, "credential not found")
	}
	return echo.NewHTTPError(http.StatusBadRequest, err.Error())
}
