package security

import (
	"crypto/subtle"
	"errors"
	"net/http"
	"strings"

	"github.com/labstack/echo/v4"
)

const bearerPrefix = "Bearer "

type TokenAuth struct {
	token string
}

func NewTokenAuth(token string) (TokenAuth, error) {
	if strings.TrimSpace(token) == "" {
		return TokenAuth{}, errors.New("admin token is required")
	}
	return TokenAuth{token: token}, nil
}

func (a TokenAuth) Middleware(next echo.HandlerFunc) echo.HandlerFunc {
	return func(c echo.Context) error {
		header := c.Request().Header.Get(echo.HeaderAuthorization)
		if !strings.HasPrefix(header, bearerPrefix) {
			return echo.NewHTTPError(http.StatusUnauthorized, "missing bearer token")
		}
		candidate := strings.TrimPrefix(header, bearerPrefix)
		if !constantTimeEqual(candidate, a.token) {
			return echo.NewHTTPError(http.StatusForbidden, "invalid bearer token")
		}
		return next(c)
	}
}

func constantTimeEqual(candidate string, expected string) bool {
	if len(candidate) != len(expected) {
		return false
	}
	return subtle.ConstantTimeCompare([]byte(candidate), []byte(expected)) == 1
}
