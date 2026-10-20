package httpapi

import (
	"bytes"
	"errors"
	"net/http"
	"net/url"
	"strings"

	"github.com/labstack/echo/v4"
	"github.com/osolmaz/unyolo/brokers/github/internal/apicompat"
	"github.com/osolmaz/unyolo/brokers/github/internal/githubauth"
	"github.com/osolmaz/unyolo/brokers/github/internal/policy"
	"github.com/osolmaz/unyolo/brokers/github/internal/security"
	"github.com/osolmaz/unyolo/operation/digest"
	"github.com/osolmaz/unyolo/transport/http"
)

// githubAPIPrefix is where GitHub Enterprise Server clients, such as the
// GitHub CLI with GH_HOST, send REST calls.
const githubAPIPrefix = "/api/v3"

// graphQLBodyLimit bounds one GraphQL request body.
const graphQLBodyLimit = 1 << 20

// registerGitHubAPI serves the GitHub-compatible REST and GraphQL routes. Each
// request is classified to one catalog operation or reviewed GraphQL shape,
// policy-gated like Git smart HTTP, and forwarded with a narrowed credential.
func (s *Server) registerGitHubAPI(auth security.TokenAuth) {
	s.echo.Any(githubAPIPrefix+"/*", s.githubREST, githubTokenScheme, auth.Middleware)
	s.echo.POST("/api/graphql", s.githubGraphQL, githubTokenScheme, auth.Middleware)
}

// githubTokenScheme accepts GitHub's "token" authorization scheme, which the
// GitHub CLI sends to Enterprise hosts, as a bearer client secret.
func githubTokenScheme(next echo.HandlerFunc) echo.HandlerFunc {
	return func(c echo.Context) error {
		header := c.Request().Header
		if scheme, value, found := strings.Cut(strings.TrimSpace(header.Get("Authorization")), " "); found && strings.EqualFold(scheme, "token") {
			header.Set("Authorization", "Bearer "+strings.TrimSpace(value))
		}
		return next(c)
	}
}

func (s *Server) githubREST(c echo.Context) error {
	escapedPath := strings.TrimPrefix(c.Request().URL.EscapedPath(), githubAPIPrefix)
	match, err := apicompat.MatchREST(c.Request().Method, escapedPath)
	if err != nil {
		return compatError(err)
	}
	body, err := readCompatBody(c, match.Binding.RequestBytesLimit)
	if err != nil {
		return err
	}
	request, err := match.Request(c.QueryParams(), body)
	if err != nil {
		return compatError(err)
	}
	request.Client = security.ClientFromContext(c)
	held, err := s.authorizeHeld(c, request, compatRequestDigest(c, body))
	if err != nil {
		return err
	}
	return s.runHeld(c, []heldAuthorization{held}, func(c echo.Context) error {
		return s.forwardRepositoryAPI(c, request, match.Path, body)
	})
}

func (s *Server) githubGraphQL(c echo.Context) error {
	body, err := readCompatBody(c, graphQLBodyLimit)
	if err != nil {
		return err
	}
	classified, err := apicompat.ClassifyGraphQL(body)
	if err != nil {
		return compatError(err)
	}
	switch classified.Kind {
	case apicompat.GraphQLSchema:
		return s.serveGraphQLSchema(c, body)
	case apicompat.GraphQLRead:
		return s.serveGraphQLRead(c, body, classified.Repositories)
	default:
		return s.serveGraphQLMutation(c, body, classified.Mutation)
	}
}

// serveGraphQLSchema forwards schema introspection, which names no target and
// reads no repository data, with a metadata-only credential.
func (s *Server) serveGraphQLSchema(c echo.Context, body []byte) error {
	request := policy.Request{Client: security.ClientFromContext(c), Operation: "graphql.schema"}
	credential, err := s.githubCredentials.SchemaCredential(c.Request().Context())
	if err != nil {
		s.audit(c, request, "error", "GitHub credential acquisition failed", http.StatusBadGateway, nil)
		return echo.NewHTTPError(http.StatusBadGateway, "GitHub credential acquisition failed")
	}
	if err := s.forwardGitHubAPI(c, "/graphql", body, credential); err != nil {
		s.audit(c, request, errorOutcome(err), errorString(err), errorStatus(c, err), nil)
		return err
	}
	s.audit(c, request, "proxied", "", responseStatus(c), nil)
	return nil
}

func (s *Server) serveGraphQLRead(c echo.Context, body []byte, repositories []githubauth.Repository) error {
	held := make([]heldAuthorization, 0, len(repositories))
	for _, repository := range repositories {
		item, err := s.authorizeHeld(c, policy.Request{
			Client: security.ClientFromContext(c), Operation: policy.OperationGraphQLRead,
			Target: policy.Target{Kind: "repo", Owner: repository.Owner, Name: repository.Name},
		}, "")
		if err != nil {
			s.releaseHeld(held)
			return err
		}
		held = append(held, item)
	}
	return s.runHeld(c, held, func(c echo.Context) error {
		credential, err := s.githubCredentials.GraphQLReadCredential(c.Request().Context(), repositories)
		if err != nil {
			return echo.NewHTTPError(http.StatusBadGateway, "GitHub credential acquisition failed")
		}
		return s.forwardGitHubAPI(c, "/graphql", body, credential)
	})
}

func (s *Server) serveGraphQLMutation(c echo.Context, body []byte, mutation apicompat.Mutation) error {
	node, err := s.githubCredentials.ResolveNode(c.Request().Context(), mutation.NodeID)
	if errors.Is(err, githubauth.ErrNodeNotFound) {
		return echo.NewHTTPError(http.StatusNotFound, "gh-broker: the "+mutation.Field+" subject is not visible to the broker")
	}
	if err != nil {
		return echo.NewHTTPError(http.StatusBadGateway, "gh-broker: could not resolve the "+mutation.Field+" subject")
	}
	request, err := mutation.Request(node)
	if err != nil {
		return compatError(err)
	}
	request.Client = security.ClientFromContext(c)
	held, err := s.authorizeHeld(c, request, compatRequestDigest(c, body))
	if err != nil {
		return err
	}
	return s.runHeld(c, []heldAuthorization{held}, func(c echo.Context) error {
		return s.forwardRepositoryAPI(c, request, "/graphql", body)
	})
}

// forwardRepositoryAPI forwards one authorized call with the installation
// credential narrowed to its repository and the operation's permissions.
func (s *Server) forwardRepositoryAPI(c echo.Context, request policy.Request, path string, body []byte) error {
	owner, repo, _ := apicompat.Repository(request.Target)
	credential, err := s.githubCredentialForRepo(c, owner, repo)
	if err != nil {
		return err
	}
	return s.forwardGitHubAPI(c, path, body, credential)
}

// forwardGitHubAPI sends one call to the GitHub API and copies the response.
// Credential headers are removed, and API links are rewritten to this host so
// clients keep paginating through the broker.
func (s *Server) forwardGitHubAPI(c echo.Context, escapedPath string, body []byte, credential *githubauth.Credential) error {
	base := githubAPIRoot(s.githubAPIBaseURL)
	upstreamURL, err := githubAPIURL(base, escapedPath, c.Request().URL.RawQuery)
	if err != nil {
		return echo.NewHTTPError(http.StatusBadRequest, "gh-broker: the request path is invalid")
	}
	request, err := http.NewRequestWithContext(c.Request().Context(), c.Request().Method, upstreamURL.String(), bytes.NewReader(body))
	if err != nil {
		return echo.NewHTTPError(http.StatusBadGateway, "create upstream github request")
	}
	httpx.CopyHeaders(request.Header, c.Request().Header, httpx.ProxyRequestHeader)
	accept := c.Request().Header.Get("Accept")
	if err := credential.AuthorizeAPI(request); err != nil {
		return echo.NewHTTPError(http.StatusBadGateway, "GitHub credential acquisition failed")
	}
	if accept != "" {
		request.Header.Set("Accept", accept)
	}
	markUpstreamDispatched(c)
	// #nosec G704 -- the upstream URL joins the fixed GitHub API base with a path classified to one reviewed binding.
	response, err := s.githubGitClient.Do(request)
	if err != nil {
		return echo.NewHTTPError(http.StatusBadGateway, "upstream github request failed")
	}
	defer func() { _ = response.Body.Close() }()
	httpx.CopyHeaders(c.Response().Header(), response.Header, githubProxyResponseHeader)
	rewriteGitHubAPILinks(c.Response().Header(), base.String(), c.Scheme()+"://"+c.Request().Host+githubAPIPrefix+"/")
	return copyUpstreamResponse(c, response)
}

func githubAPIRoot(base *url.URL) *url.URL {
	root := *base
	if !strings.HasSuffix(root.Path, "/") {
		root.Path += "/"
	}
	if root.RawPath != "" && !strings.HasSuffix(root.RawPath, "/") {
		root.RawPath += "/"
	}
	return &root
}

func githubAPIURL(base *url.URL, escapedPath, rawQuery string) (*url.URL, error) {
	unescaped, err := url.PathUnescape(escapedPath)
	if err != nil {
		return nil, err
	}
	relative := &url.URL{Path: strings.TrimPrefix(unescaped, "/"), RawPath: strings.TrimPrefix(escapedPath, "/"), RawQuery: rawQuery}
	return base.ResolveReference(relative), nil
}

func rewriteGitHubAPILinks(header http.Header, upstreamRoot, publicRoot string) {
	for _, key := range []string{"Link", "Location"} {
		values := header.Values(key)
		if len(values) == 0 {
			continue
		}
		header.Del(key)
		for _, value := range values {
			header.Add(key, strings.ReplaceAll(value, upstreamRoot, publicRoot))
		}
	}
}

func readCompatBody(c echo.Context, limit int64) ([]byte, error) {
	body, err := httpx.ReadLimited(c.Request().Body, limit)
	if err != nil {
		return nil, echo.NewHTTPError(http.StatusRequestEntityTooLarge, "gh-broker: the request body is too large")
	}
	return body, nil
}

// compatRequestDigest identifies one exact request so a retry reuses its
// pending execution-mode approval.
func compatRequestDigest(c echo.Context, body []byte) string {
	request := c.Request()
	return plandigest.Digest([]byte(request.Method + "\n" + request.URL.RequestURI() + "\n" + plandigest.Digest(body)))
}

func compatError(err error) error {
	var refusal *apicompat.Refusal
	if errors.As(err, &refusal) {
		return echo.NewHTTPError(refusal.Status, refusal.Message)
	}
	return echo.NewHTTPError(http.StatusInternalServerError, "gh-broker: could not classify the request")
}
