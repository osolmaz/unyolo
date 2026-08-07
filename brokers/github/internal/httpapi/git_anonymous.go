package httpapi

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net/http"

	"github.com/labstack/echo/v4"
	corepolicy "github.com/osolmaz/unyolo/authorization/policy"
	"github.com/osolmaz/unyolo/brokers/github/internal/policy"
	httpx "github.com/osolmaz/unyolo/transport/http"
)

const maxAnonymousGitReadRequestBytes = 8 << 20

const githubAuthModeContextKey = "gh_broker_auth_mode"

type githubCredentialUseRequestContextKey struct{}

type managedCredentialRequiredError struct {
	status int
}

func (e managedCredentialRequiredError) Error() string { return "managed credential may help" }

func (s *Server) tryAnonymousGitTransfer(
	c echo.Context,
	request policy.Request,
	run func(echo.Context) error,
) (bool, error) {
	if request.Operation != policy.OperationGitFetch {
		return false, nil
	}
	decision := s.policy.EvaluateAnonymous(request)
	if !decision.Allowed {
		return false, nil
	}
	replay, err := bufferAnonymousGitRequest(c.Request())
	if err != nil {
		return true, err
	}
	setGitHubCredentialUse(c, corepolicy.CredentialUseNone)
	defer setGitHubCredentialUse(c, corepolicy.CredentialUseManaged)
	replay()
	err = run(c)
	var required managedCredentialRequiredError
	if errors.As(err, &required) {
		s.audit(c, request, "anonymous_fallback", required.Error(), required.status, decision.MatchedRuleIDs)
		replay()
		return false, nil
	}
	outcome, reason := "proxied_anonymous", ""
	if err != nil {
		outcome, reason = errorOutcome(err), errorString(err)
	}
	s.audit(c, request, outcome, reason, responseStatus(c), decision.MatchedRuleIDs)
	return true, err
}

func bufferAnonymousGitRequest(request *http.Request) (func(), error) {
	if request.Body == nil || request.Body == http.NoBody {
		return func() {}, nil
	}
	body, err := httpx.ReadLimited(request.Body, maxAnonymousGitReadRequestBytes)
	if err != nil {
		if errors.Is(err, httpx.ErrBodyTooLarge) {
			return nil, echo.NewHTTPError(http.StatusRequestEntityTooLarge, "Git read request is too large")
		}
		return nil, echo.NewHTTPError(http.StatusBadRequest, "read Git request")
	}
	reset := func() {
		request.Body = io.NopCloser(bytes.NewReader(body))
		request.ContentLength = int64(len(body))
	}
	reset()
	return reset, nil
}

func setGitHubCredentialUse(c echo.Context, use corepolicy.CredentialUse) {
	c.Set(githubAuthModeContextKey, use)
}

func githubCredentialUse(c echo.Context) corepolicy.CredentialUse {
	use, _ := c.Get(githubAuthModeContextKey).(corepolicy.CredentialUse)
	if use == "" {
		return corepolicy.CredentialUseManaged
	}
	return use
}

func withGitHubCredentialUse(c echo.Context, ctx context.Context) context.Context {
	return context.WithValue(ctx, githubCredentialUseRequestContextKey{}, githubCredentialUse(c))
}

func requestCredentialUse(request *http.Request) corepolicy.CredentialUse {
	use, _ := request.Context().Value(githubCredentialUseRequestContextKey{}).(corepolicy.CredentialUse)
	if use == "" {
		return corepolicy.CredentialUseManaged
	}
	return use
}

func anonymousCredentialMayHelp(request *http.Request, status int) bool {
	if requestCredentialUse(request) != corepolicy.CredentialUseNone {
		return false
	}
	switch status {
	case http.StatusUnauthorized, http.StatusForbidden, http.StatusNotFound:
		return true
	default:
		return false
	}
}

func sanitizeAnonymousGitRequest(request *http.Request) {
	request.Header.Del("Authorization")
	request.Header.Del("Proxy-Authorization")
	request.Header.Del("Cookie")
	request.Header.Del("Cookie2")
}
