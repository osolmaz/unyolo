package security

import (
	"errors"
	"net/http"
	"strings"

	"github.com/labstack/echo/v4"
	"github.com/osolmaz/brokerkit/auth"
)

const clientContextKey = "gh-broker.client"

type TokenAuth struct {
	authenticator *auth.Authenticator
}

func NewTokenAuth(token string) (TokenAuth, error) {
	return NewTokenAuthForClient(token, "default")
}

func NewTokenAuthForClient(token string, client string) (TokenAuth, error) {
	client = strings.TrimSpace(client)
	if client == "" {
		return TokenAuth{}, errors.New("client id is required")
	}
	authenticator, err := auth.New(map[string]string{client: token}, auth.Options{})
	if err != nil {
		return TokenAuth{}, err
	}
	return TokenAuth{authenticator: authenticator}, nil
}

func ClientFromContext(c echo.Context) string {
	client, _ := c.Get(clientContextKey).(string)
	return client
}

func (a TokenAuth) Middleware(next echo.HandlerFunc) echo.HandlerFunc {
	return func(c echo.Context) error {
		client, err := a.authenticator.AuthenticateRequest(c.Request())
		if errors.Is(err, auth.ErrMissing) {
			return echo.NewHTTPError(http.StatusUnauthorized, "missing authorization")
		}
		if err != nil {
			return echo.NewHTTPError(http.StatusForbidden, "invalid authorization")
		}
		c.Set(clientContextKey, client)
		return next(c)
	}
}
