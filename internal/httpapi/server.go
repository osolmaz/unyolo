package httpapi

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/dutifuldev/gitcba/internal/config"
	"github.com/dutifuldev/gitcba/internal/githubaccess"
	"github.com/dutifuldev/gitcba/internal/security"
	"github.com/labstack/echo/v4"
	"github.com/labstack/echo/v4/middleware"
)

type Server struct {
	echo                *echo.Echo
	githubAccess        githubaccess.Config
	githubToken         string
	githubClient        *http.Client
	githubGitBaseURL    *url.URL
	githubAPIBaseURL    *url.URL
	logger              *slog.Logger
	maxReceivePackBytes int64
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
	gitBaseURL, err := url.Parse("https://github.com")
	if err != nil {
		return nil, err
	}
	apiBaseURL, err := url.Parse("https://api.github.com")
	if err != nil {
		return nil, err
	}
	githubHTTPTimeout := cfg.GitHubHTTPTimeout
	if githubHTTPTimeout <= 0 {
		githubHTTPTimeout = 30 * time.Second
	}
	maxReceivePackBytes := cfg.MaxReceivePackBytes
	if maxReceivePackBytes <= 0 {
		maxReceivePackBytes = 25 * 1024 * 1024
	}
	server := &Server{
		echo:                e,
		githubAccess:        githubAccess,
		githubToken:         cfg.GitHubToken,
		githubClient:        &http.Client{Timeout: githubHTTPTimeout},
		githubGitBaseURL:    gitBaseURL,
		githubAPIBaseURL:    apiBaseURL,
		logger:              slog.Default(),
		maxReceivePackBytes: maxReceivePackBytes,
	}
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
	return s.authorizeBrokerOperation(c, operation, s.proxyGit)
}

func (s *Server) gitUploadPack(c echo.Context) error {
	return s.authorizeBrokerOperation(c, githubaccess.OperationGitUploadPack, s.proxyGit)
}

func (s *Server) gitReceivePack(c echo.Context) error {
	return s.authorizeBrokerOperation(c, githubaccess.OperationGitReceivePack, s.proxyGitReceivePack)
}

func (s *Server) createPullRequest(c echo.Context) error {
	return s.authorizeBrokerOperation(c, githubaccess.OperationCreatePullRequest, s.proxyGitHubAPI)
}

func (s *Server) authorizeBrokerOperation(
	c echo.Context,
	operation githubaccess.Operation,
	run func(echo.Context) error,
) error {
	if decision := s.decide(c, operation); !decision.Allowed {
		s.audit(c, operation, "denied", decision.Reason, 0)
		return echo.NewHTTPError(http.StatusForbidden, decision.Reason)
	}
	err := run(c)
	if err != nil {
		s.audit(c, operation, errorOutcome(err), errorString(err), errorStatus(c, err))
		return err
	}
	s.audit(c, operation, "proxied", "", responseStatus(c))
	return nil
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

func noStore(next echo.HandlerFunc) echo.HandlerFunc {
	return func(c echo.Context) error {
		c.Response().Header().Set(echo.HeaderCacheControl, "no-store")
		c.Response().Header().Set("Pragma", "no-cache")
		c.Response().Header().Set("X-Content-Type-Options", "nosniff")
		return next(c)
	}
}

func (s *Server) proxyGit(c echo.Context) error {
	upstreamURL := s.githubGitBaseURL.JoinPath(c.Param("owner"), c.Param("repoGit"), strings.TrimPrefix(c.Request().URL.Path, gitRepoPrefix(c)))
	upstreamURL.RawQuery = c.Request().URL.RawQuery
	return s.proxyTo(c, upstreamURL, func(request *http.Request) {
		request.Header.Set("Authorization", githubGitAuthorization(s.githubToken))
	})
}

func gitRepoPrefix(c echo.Context) string {
	return fmt.Sprintf("/%s/%s/", c.Param("owner"), c.Param("repoGit"))
}

func (s *Server) proxyGitReceivePack(c echo.Context) error {
	body, err := readLimited(c.Request().Body, s.maxReceivePackBytes)
	if err != nil {
		return echo.NewHTTPError(http.StatusRequestEntityTooLarge, "git receive-pack request is too large")
	}
	updatedRefs, err := receivePackUpdatedRefs(body)
	if err != nil {
		return echo.NewHTTPError(http.StatusBadRequest, "parse git receive-pack request")
	}
	if len(updatedRefs) > 0 {
		defaultBranch, err := s.fetchDefaultBranch(c, c.Param("owner"), strings.TrimSuffix(c.Param("repoGit"), ".git"))
		if err != nil {
			return err
		}
		if protectedRef := protectedBranchUpdate(updatedRefs, defaultBranch); protectedRef != "" {
			return echo.NewHTTPError(http.StatusForbidden, "push to default branch is denied: "+protectedRef)
		}
	}
	c.Request().Body = io.NopCloser(bytes.NewReader(body))
	c.Request().ContentLength = int64(len(body))
	return s.proxyGit(c)
}

func readLimited(reader io.Reader, limit int64) ([]byte, error) {
	limited := io.LimitReader(reader, limit+1)
	body, err := io.ReadAll(limited)
	if err != nil {
		return nil, err
	}
	if int64(len(body)) > limit {
		return nil, errors.New("body too large")
	}
	return body, nil
}

func receivePackUpdatedRefs(body []byte) ([]string, error) {
	var refs []string
	for offset := 0; offset < len(body); {
		line, nextOffset, flush, err := nextPktLine(body, offset)
		if err != nil {
			return nil, err
		}
		if flush {
			break
		}
		offset = nextOffset
		command := strings.SplitN(strings.TrimSuffix(line, "\n"), "\x00", 2)[0]
		fields := strings.Fields(command)
		if len(fields) >= 3 && strings.HasPrefix(fields[2], "refs/heads/") {
			refs = append(refs, fields[2])
		}
	}
	return refs, nil
}

func nextPktLine(body []byte, offset int) (line string, nextOffset int, flush bool, err error) {
	if len(body)-offset < 4 {
		return "", 0, false, errors.New("short pkt-line")
	}
	size, err := strconv.ParseInt(string(body[offset:offset+4]), 16, 32)
	if err != nil {
		return "", 0, false, err
	}
	if size == 0 {
		return "", 0, true, nil
	}
	if size < 4 || int64(len(body)-offset-4) < size-4 {
		return "", 0, false, errors.New("invalid pkt-line size")
	}
	start := offset + 4
	end := start + int(size) - 4
	return string(body[start:end]), end, false, nil
}

func protectedBranchUpdate(refs []string, defaultBranch string) string {
	protected := map[string]struct{}{
		"refs/heads/main": {},
	}
	if defaultBranch != "" {
		protected["refs/heads/"+defaultBranch] = struct{}{}
	}
	for _, ref := range refs {
		if _, exists := protected[ref]; exists {
			return ref
		}
	}
	return ""
}

func (s *Server) fetchDefaultBranch(c echo.Context, owner string, repo string) (string, error) {
	upstreamURL := s.githubAPIBaseURL.JoinPath("repos", owner, repo)
	request, err := http.NewRequestWithContext(c.Request().Context(), http.MethodGet, upstreamURL.String(), http.NoBody)
	if err != nil {
		return "", echo.NewHTTPError(http.StatusBadGateway, "create upstream github request")
	}
	request.Header.Set("Authorization", "Bearer "+s.githubToken)
	request.Header.Set("Accept", "application/vnd.github+json")
	request.Header.Set("X-GitHub-Api-Version", "2022-11-28")
	// #nosec G704 -- upstream URL is built from a fixed GitHub API base URL and file-policy-gated owner/repo params.
	response, err := s.githubClient.Do(request)
	if err != nil {
		return "", echo.NewHTTPError(http.StatusBadGateway, "fetch default branch")
	}
	defer func() {
		_ = response.Body.Close()
	}()
	if response.StatusCode < http.StatusOK || response.StatusCode >= http.StatusMultipleChoices {
		return "", echo.NewHTTPError(http.StatusBadGateway, "fetch default branch")
	}
	var payload struct {
		DefaultBranch string `json:"default_branch"`
	}
	if err := json.NewDecoder(response.Body).Decode(&payload); err != nil {
		return "", echo.NewHTTPError(http.StatusBadGateway, "decode default branch")
	}
	return payload.DefaultBranch, nil
}

func (s *Server) proxyGitHubAPI(c echo.Context) error {
	upstreamURL := s.githubAPIBaseURL.JoinPath("repos", c.Param("owner"), c.Param("repo"), "pulls")
	return s.proxyTo(c, upstreamURL, func(request *http.Request) {
		request.Header.Set("Authorization", "Bearer "+s.githubToken)
		request.Header.Set("Accept", "application/vnd.github+json")
		request.Header.Set("X-GitHub-Api-Version", "2022-11-28")
	})
}

func (s *Server) proxyTo(c echo.Context, upstreamURL *url.URL, configure func(*http.Request)) error {
	request, err := http.NewRequestWithContext(
		c.Request().Context(),
		c.Request().Method,
		upstreamURL.String(),
		c.Request().Body,
	)
	if err != nil {
		return echo.NewHTTPError(http.StatusBadGateway, "create upstream github request")
	}
	copyRequestHeaders(request.Header, c.Request().Header)
	configure(request)
	return s.doProxy(c, request)
}

func (s *Server) doProxy(c echo.Context, request *http.Request) error {
	// #nosec G704 -- upstream URLs are built from fixed GitHub base URLs and file-policy-gated owner/repo params.
	response, err := s.githubClient.Do(request)
	if err != nil {
		return echo.NewHTTPError(http.StatusBadGateway, "upstream github request failed")
	}
	defer func() {
		_ = response.Body.Close()
	}()
	copyResponseHeaders(c.Response().Header(), response.Header)
	c.Response().WriteHeader(response.StatusCode)
	_, err = io.Copy(c.Response(), response.Body)
	return err
}

func copyRequestHeaders(dst http.Header, src http.Header) {
	copyHeaders(dst, src, dropRequestHeader)
}

func copyResponseHeaders(dst http.Header, src http.Header) {
	copyHeaders(dst, src, hopByHopHeader)
}

func copyHeaders(dst http.Header, src http.Header, drop func(string) bool) {
	for key, values := range src {
		if drop(key) {
			continue
		}
		for _, value := range values {
			dst.Add(key, value)
		}
	}
}

func dropRequestHeader(key string) bool {
	return hopByHopHeader(key) ||
		strings.EqualFold(key, "Authorization") ||
		strings.EqualFold(key, "Cookie")
}

func hopByHopHeader(key string) bool {
	switch strings.ToLower(key) {
	case "connection", "keep-alive", "proxy-authenticate", "proxy-authorization",
		"te", "trailer", "transfer-encoding", "upgrade":
		return true
	default:
		return false
	}
}

func githubGitAuthorization(token string) string {
	credential := base64.StdEncoding.EncodeToString([]byte("x-access-token:" + token))
	return "Basic " + credential
}

func (s *Server) audit(c echo.Context, operation githubaccess.Operation, outcome string, reason string, status int) {
	repo := c.Param("repo")
	if repo == "" {
		repo = c.Param("repoGit")
	}
	attrs := []any{
		"operation", string(operation),
		"outcome", outcome,
		"owner", c.Param("owner"),
		"repo", strings.TrimSuffix(repo, ".git"),
		"method", c.Request().Method,
		"path", c.Request().URL.Path,
	}
	if status != 0 {
		attrs = append(attrs, "status", status)
	}
	if reason != "" {
		attrs = append(attrs, "reason", reason)
	}
	s.logger.Info("broker operation", attrs...)
}

func errorString(err error) string {
	if err == nil {
		return ""
	}
	return err.Error()
}

func errorOutcome(err error) string {
	var httpError *echo.HTTPError
	if errors.As(err, &httpError) && httpError.Code == http.StatusForbidden {
		return "denied"
	}
	return "error"
}

func responseStatus(c echo.Context) int {
	status := c.Response().Status
	if status == 0 {
		return http.StatusOK
	}
	return status
}

func errorStatus(c echo.Context, err error) int {
	var httpError *echo.HTTPError
	if errors.As(err, &httpError) {
		return httpError.Code
	}
	return responseStatus(c)
}
