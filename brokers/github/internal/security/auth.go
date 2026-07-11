package security

import (
	"errors"
	"net/http"

	"github.com/labstack/echo/v4"
	"github.com/osolmaz/brokerkit/auth"
)

const clientContextKey = "gh-broker.client"

type TokenAuth struct {
	authenticator *auth.Authenticator
}

// FromAuthenticator adapts the shared Brokerkit client authenticator to Echo middleware.
func FromAuthenticator(authenticator *auth.Authenticator) (TokenAuth, error) {
	if authenticator == nil {
		return TokenAuth{}, errors.New("client authenticator is required")
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

// mutate4go-manifest-begin
// {"version":1,"tested_at":"2026-07-09T22:59:28+08:00","module_hash":"4685e76c9b8a74c33b936ffbaf1f7b308ab24aa99f5c980802a26d3209447972","functions":[{"id":"func/NewTokenAuth","name":"NewTokenAuth","line":18,"end_line":20,"hash":"34f672b48bf5a5ac67de2a142b5564cd35db4bc0c6da8a3a9d31b5eb1277293a"},{"id":"func/NewTokenAuthForClient","name":"NewTokenAuthForClient","line":22,"end_line":32,"hash":"c3b6c6f990210dd38817b612b8fce4439449e14962c6b37cb253320f2f1e5094"},{"id":"func/ClientFromContext","name":"ClientFromContext","line":34,"end_line":37,"hash":"fb4fd3ec592a7aa610b384a1b20da27d35c8c761d1cee162735b7e8fc7ee1822"},{"id":"func/TokenAuth.Middleware","name":"TokenAuth.Middleware","line":39,"end_line":51,"hash":"75e2092d8058f388035b0843a5bba9f6aac7f6719a32d9b9571f1e2f6d84770f"}]}
// mutate4go-manifest-end
