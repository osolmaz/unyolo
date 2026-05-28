package security

import (
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"net/http"
	"strings"

	"github.com/labstack/echo/v4"
)

const (
	basicPrefix  = "Basic "
	bearerPrefix = "Bearer "
)

type TokenAuth struct {
	token string
}

func NewTokenAuth(token string) (TokenAuth, error) {
	if strings.TrimSpace(token) == "" {
		return TokenAuth{}, errors.New("shared secret is required")
	}
	return TokenAuth{token: token}, nil
}

func (a TokenAuth) Middleware(next echo.HandlerFunc) echo.HandlerFunc {
	return func(c echo.Context) error {
		header := c.Request().Header.Get(echo.HeaderAuthorization)
		if header == "" {
			return echo.NewHTTPError(http.StatusUnauthorized, "missing authorization")
		}
		candidate, ok := credentialFromAuthorization(header)
		if !ok {
			return echo.NewHTTPError(http.StatusUnauthorized, "unsupported authorization")
		}
		if !constantTimeEqual(candidate, a.token) {
			return echo.NewHTTPError(http.StatusForbidden, "invalid authorization")
		}
		return next(c)
	}
}

func credentialFromAuthorization(header string) (string, bool) {
	switch {
	case strings.HasPrefix(header, bearerPrefix):
		return strings.TrimPrefix(header, bearerPrefix), true
	case strings.HasPrefix(header, basicPrefix):
		payload := strings.TrimPrefix(header, basicPrefix)
		decoded, err := base64.StdEncoding.DecodeString(payload)
		if err != nil {
			return "", false
		}
		_, password, ok := strings.Cut(string(decoded), ":")
		return password, ok
	default:
		return "", false
	}
}

func constantTimeEqual(candidate string, expected string) bool {
	if len(candidate) != len(expected) {
		return false
	}
	return subtle.ConstantTimeCompare([]byte(candidate), []byte(expected)) == 1
}
