package httpapi

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/labstack/echo/v4"
	"github.com/labstack/echo/v4/middleware"
	"github.com/osolmaz/brokerkit/grants"
	"github.com/osolmaz/brokerkit/httpx"
	"github.com/osolmaz/brokerkit/notify"
	bktelegram "github.com/osolmaz/brokerkit/notify/telegram"
	"github.com/osolmaz/gh-broker/internal/config"
	"github.com/osolmaz/gh-broker/internal/githubapp"
	"github.com/osolmaz/gh-broker/internal/policy"
	"github.com/osolmaz/gh-broker/internal/security"
)

const maxPullRequestBodyBytes int64 = 64 * 1024

type Server struct {
	echo                *echo.Echo
	policy              *policy.Policy
	grants              *grants.Store
	notifier            notify.Notifier
	telegram            *bktelegram.Client
	githubToken         string
	githubApp           *githubapp.Source
	githubClient        *http.Client
	githubGitBaseURL    *url.URL
	githubAPIBaseURL    *url.URL
	logger              *slog.Logger
	maxReceivePackBytes int64
}

func New(cfg config.Config, brokerPolicy *policy.Policy) (*Server, error) {
	if brokerPolicy == nil {
		return nil, errors.New("policy is required")
	}
	grantStore := grants.New(filepath.Join(stateDir(cfg.StateDir), "grants.json"), grants.Options{})
	auth, err := security.NewTokenAuthForClient(cfg.SharedSecret, cfg.ClientID)
	if err != nil {
		return nil, err
	}
	notifier, telegram, err := configuredNotifier(cfg)
	if err != nil {
		return nil, err
	}
	e := echo.New()
	e.HideBanner = true
	e.HidePort = true
	e.Use(middleware.Recover())
	e.Use(noStore)
	e.GET("/healthz", health)
	gitBaseURL, apiBaseURL, err := githubBaseURLs()
	if err != nil {
		return nil, err
	}
	githubClient := newGitHubClient(defaultDuration(cfg.GitHubHTTPTimeout, 30*time.Second))
	appSource, err := configuredGitHubApp(cfg, apiBaseURL, githubClient)
	if err != nil {
		return nil, err
	}
	server := &Server{
		echo:                e,
		policy:              brokerPolicy,
		grants:              grantStore,
		notifier:            notifier,
		telegram:            telegram,
		githubToken:         cfg.GitHubToken,
		githubApp:           appSource,
		githubClient:        githubClient,
		githubGitBaseURL:    gitBaseURL,
		githubAPIBaseURL:    apiBaseURL,
		logger:              slog.Default(),
		maxReceivePackBytes: defaultInt64(cfg.MaxReceivePackBytes, 25*1024*1024),
	}
	protected := e.Group("")
	protected.Use(auth.Middleware)
	protected.Use(validateRouteParams)
	protected.GET("/api/repos", server.listRepos)
	protected.POST("/api/grants", server.createGrant)
	protected.GET("/api/grants", server.listGrants)
	protected.GET("/api/grants/:id", server.getGrant)
	protected.GET("/api/repos/:owner/:repo/contents", server.readContents)
	protected.GET("/api/repos/:owner/:repo/contents/*", server.readContents)
	protected.POST("/api/repos/:owner/:repo/pulls", server.createPullRequest)
	protected.POST("/repos/:owner/:repo/pulls", server.createPullRequest)
	protected.GET("/:owner/:repoGit/info/refs", server.gitInfoRefs)
	protected.POST("/:owner/:repoGit/git-upload-pack", server.gitUploadPack)
	protected.POST("/:owner/:repoGit/git-receive-pack", server.gitReceivePack)
	return server, nil
}

func githubBaseURLs() (*url.URL, *url.URL, error) {
	gitBaseURL, err := url.Parse("https://github.com")
	if err != nil {
		return nil, nil, err
	}
	apiBaseURL, err := url.Parse("https://api.github.com")
	if err != nil {
		return nil, nil, err
	}
	return gitBaseURL, apiBaseURL, nil
}

func defaultDuration(value time.Duration, fallback time.Duration) time.Duration {
	if value <= 0 {
		return fallback
	}
	return value
}

func defaultInt64(value int64, fallback int64) int64 {
	if value <= 0 {
		return fallback
	}
	return value
}

func newGitHubClient(timeout time.Duration) *http.Client {
	return &http.Client{
		Timeout:       timeout,
		CheckRedirect: stopGitHubRedirect,
	}
}

func stopGitHubRedirect(_ *http.Request, _ []*http.Request) error {
	return http.ErrUseLastResponse
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
	return s.authorizeBrokerRequest(c, s.repoRequest(c, operation, nil), s.proxyGit)
}

func (s *Server) gitUploadPack(c echo.Context) error {
	return s.authorizeBrokerRequest(c, s.repoRequest(c, policy.OperationGitFetch, nil), s.proxyGit)
}

func (s *Server) gitReceivePack(c echo.Context) error {
	body, commands, err := s.readReceivePackBody(c)
	if err != nil {
		return err
	}
	if len(commands) == 0 {
		c.Request().Body = io.NopCloser(bytes.NewReader(body))
		c.Request().ContentLength = int64(len(body))
		return s.authorizeBrokerRequest(c, s.repoRequest(c, policy.OperationGitPushAdvertise, nil), s.proxyGit)
	}
	authorized, err := s.authorizeReceivePackCommands(c, commands)
	if err != nil {
		return err
	}
	return s.proxyAuthorizedReceivePack(c, body, authorized)
}

func (s *Server) readReceivePackBody(c echo.Context) ([]byte, []receivePackCommand, error) {
	body, err := httpx.ReadLimited(c.Request().Body, s.maxReceivePackBytes)
	if err != nil {
		return nil, nil, echo.NewHTTPError(http.StatusRequestEntityTooLarge, "git receive-pack request is too large")
	}
	commands, err := receivePackCommandsFromBody(body)
	if err != nil {
		return nil, nil, echo.NewHTTPError(http.StatusBadRequest, "parse git receive-pack request")
	}
	return body, commands, nil
}

func (s *Server) authorizeReceivePackCommands(c echo.Context, commands []receivePackCommand) ([]authorizedReceivePackRequest, error) {
	authorized := make([]authorizedReceivePackRequest, 0, len(commands))
	for _, command := range commands {
		operation, err := s.classifyReceivePackCommand(c, command)
		if err != nil {
			return nil, err
		}
		request := s.repoRequest(c, operation, map[string]string{"ref": command.Ref})
		decision, err := s.evaluateBrokerRequest(request)
		if err != nil {
			return nil, echo.NewHTTPError(http.StatusInternalServerError, "could not inspect grants")
		}
		if !decision.Allowed {
			s.audit(c, request, outcomeForDecision(decision), decision.Reason, 0, decision.MatchedRuleIDs)
			return nil, echo.NewHTTPError(statusForDecision(decision), decision.Reason)
		}
		authorized = append(authorized, authorizedReceivePackRequest{Request: request, Decision: decision})
	}
	return authorized, nil
}

func (s *Server) proxyAuthorizedReceivePack(c echo.Context, body []byte, authorized []authorizedReceivePackRequest) error {
	reserved, err := s.reserveAuthorizedGrants(authorized)
	if err != nil {
		s.releaseGrantUses(reserved)
		return echo.NewHTTPError(http.StatusConflict, "grant is no longer active")
	}
	c.Request().Body = io.NopCloser(bytes.NewReader(body))
	c.Request().ContentLength = int64(len(body))
	response, err := s.forwardGit(c)
	if err != nil {
		s.releaseGrantUses(reserved)
		s.auditAuthorizedReceivePack(c, authorized, errorOutcome(err), errorString(err), errorStatus(c, err))
		return err
	}
	defer func() {
		_ = response.Body.Close()
	}()
	if err := s.commitGrantUses(reserved); err != nil {
		s.auditAuthorizedReceivePack(c, authorized, "error", "grant use commit failed", response.StatusCode)
		return echo.NewHTTPError(http.StatusInternalServerError, "could not commit grant use")
	}
	httpx.CopyHeaders(c.Response().Header(), response.Header, githubProxyResponseHeader)
	if err := copyUpstreamResponse(c, response); err != nil {
		s.auditAuthorizedReceivePack(c, authorized, "error", err.Error(), responseStatus(c))
		return err
	}
	s.auditAuthorizedReceivePack(c, authorized, "proxied", "", responseStatus(c))
	return nil
}

func (s *Server) createPullRequest(c echo.Context) error {
	body, err := httpx.ReadLimited(c.Request().Body, maxPullRequestBodyBytes)
	if err != nil {
		return echo.NewHTTPError(http.StatusRequestEntityTooLarge, "pull request body is too large")
	}
	attrs, err := pullRequestAttrs(body)
	if err != nil {
		return echo.NewHTTPError(http.StatusBadRequest, err.Error())
	}
	request := s.repoRequest(c, policy.OperationPullRequestCreate, attrs)
	return s.authorizeBrokerRequest(c, request, func(c echo.Context) error {
		c.Request().Body = io.NopCloser(bytes.NewReader(body))
		c.Request().ContentLength = int64(len(body))
		return s.proxyPullRequest(c)
	})
}

func (s *Server) listRepos(c echo.Context) error {
	request := policy.Request{
		Client:    security.ClientFromContext(c),
		Operation: policy.OperationInstallationReposList,
		Target:    policy.Target{Kind: "installation"},
	}
	return s.authorizeBrokerRequest(c, request, s.fetchAndFilterRepos)
}

func (s *Server) readContents(c echo.Context) error {
	contentPath, err := contentPathParam(c)
	if err != nil {
		return err
	}
	attrs := map[string]string{"path": contentPath}
	if ref := c.QueryParam("ref"); ref != "" {
		attrs["ref"] = ref
	}
	request := s.repoRequest(c, policy.OperationContentsRead, attrs)
	return s.authorizeBrokerRequest(c, request, s.proxyContents)
}

func (s *Server) authorizeBrokerRequest(
	c echo.Context,
	request policy.Request,
	run func(echo.Context) error,
) error {
	decision, err := s.evaluateBrokerRequest(request)
	if err != nil {
		s.audit(c, request, "error", "could not inspect grants", 0, nil)
		return echo.NewHTTPError(http.StatusInternalServerError, "could not inspect grants")
	}
	if !decision.Allowed {
		s.audit(c, request, outcomeForDecision(decision), decision.Reason, 0, decision.MatchedRuleIDs)
		return echo.NewHTTPError(statusForDecision(decision), decision.Reason)
	}
	reserved, err := s.reserveGrantUse(decision.GrantID)
	if err != nil {
		s.audit(c, request, "error", "grant is no longer active", 0, decision.MatchedRuleIDs)
		return echo.NewHTTPError(http.StatusConflict, "grant is no longer active")
	}
	err = run(c)
	if err != nil {
		s.releaseGrantUses(reserved)
		s.audit(c, request, errorOutcome(err), errorString(err), errorStatus(c, err), decision.MatchedRuleIDs)
		return err
	}
	if err := s.commitGrantUses(reserved); err != nil {
		s.audit(c, request, "error", "grant use commit failed", responseStatus(c), decision.MatchedRuleIDs)
		return echo.NewHTTPError(http.StatusInternalServerError, "could not commit grant use")
	}
	s.audit(c, request, "proxied", "", responseStatus(c), decision.MatchedRuleIDs)
	return nil
}

func (s *Server) repoRequest(c echo.Context, operation policy.Operation, attrs map[string]string) policy.Request {
	repo := c.Param("repo")
	if repo == "" {
		repo = c.Param("repoGit")
	}
	return policy.Request{
		Client:    security.ClientFromContext(c),
		Operation: operation,
		Target: policy.Target{
			Kind:  "repo",
			Owner: c.Param("owner"),
			Name:  strings.TrimSuffix(repo, ".git"),
		},
		Attrs: attrs,
	}
}

func operationFromGitService(service string) (policy.Operation, error) {
	switch service {
	case "git-upload-pack":
		return policy.OperationGitFetch, nil
	case "git-receive-pack":
		return policy.OperationGitPushAdvertise, nil
	default:
		return "", echo.NewHTTPError(http.StatusBadRequest, "unsupported git service")
	}
}

func noStore(next echo.HandlerFunc) echo.HandlerFunc {
	return func(c echo.Context) error {
		httpx.NoStore(c.Response().Header())
		return next(c)
	}
}

func validateRouteParams(next echo.HandlerFunc) echo.HandlerFunc {
	return func(c echo.Context) error {
		for _, key := range []string{"owner", "repo", "repoGit"} {
			if value := c.Param(key); value != "" {
				if err := validateRouteSegment(value); err != nil {
					return echo.NewHTTPError(http.StatusBadRequest, err.Error())
				}
			}
		}
		return next(c)
	}
}

func validateRouteSegment(value string) error {
	segment, err := url.PathUnescape(value)
	if err != nil {
		return errors.New("route parameter contains invalid escaping")
	}
	if strings.Contains(segment, "/") {
		return errors.New("route parameter contains escaped path separator")
	}
	if segment == "." || segment == ".." {
		return errors.New("route parameter contains unsupported path segment")
	}
	return nil
}

func (s *Server) proxyGit(c echo.Context) error {
	return s.proxyTo(c, s.gitUpstreamURL(c), func(request *http.Request) error {
		return s.configureGitHubGitRequest(c, request, c.Param("owner"), strings.TrimSuffix(c.Param("repoGit"), ".git"))
	})
}

func (s *Server) classifyReceivePackCommand(c echo.Context, command receivePackCommand) (policy.Operation, error) {
	switch {
	case isZeroOID(command.NewOID):
		return policy.OperationGitRefDelete, nil
	case strings.HasPrefix(command.Ref, "refs/tags/"):
		return policy.OperationGitTagUpdate, nil
	case !strings.HasPrefix(command.Ref, "refs/heads/"):
		return "", echo.NewHTTPError(http.StatusForbidden, "unsupported git ref update")
	case isZeroOID(command.OldOID):
		return policy.OperationGitPushBranchCreate, nil
	default:
		return policy.OperationGitPushForce, nil
	}
}

func isZeroOID(value string) bool {
	if len(value) != 40 && len(value) != 64 {
		return false
	}
	for _, char := range value {
		if char != '0' {
			return false
		}
	}
	return true
}

func pullRequestAttrs(body []byte) (map[string]string, error) {
	var payload struct {
		Title               string `json:"title"`
		Body                string `json:"body"`
		Head                string `json:"head"`
		Base                string `json:"base"`
		Draft               bool   `json:"draft"`
		MaintainerCanModify *bool  `json:"maintainer_can_modify"`
	}
	decoder := json.NewDecoder(bytes.NewReader(body))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&payload); err != nil {
		return nil, errors.New("invalid pull request json")
	}
	if strings.TrimSpace(payload.Title) == "" {
		return nil, errors.New("pull request title is required")
	}
	if len(payload.Title) > 256 {
		return nil, errors.New("pull request title is too long")
	}
	if len(payload.Body) > 60000 {
		return nil, errors.New("pull request body is too long")
	}
	baseRef, err := branchNameToRef(payload.Base)
	if err != nil {
		return nil, fmt.Errorf("invalid pull request base: %w", err)
	}
	headRef, err := headNameToRef(payload.Head)
	if err != nil {
		return nil, fmt.Errorf("invalid pull request head: %w", err)
	}
	return map[string]string{"base_ref": baseRef, "head_ref": headRef, "ref": headRef}, nil
}

func headNameToRef(head string) (string, error) {
	if strings.Contains(head, ":") {
		return "", errors.New("fork-qualified pull request heads are not supported")
	}
	return branchNameToRef(head)
}

func branchNameToRef(branch string) (string, error) {
	branch = strings.TrimSpace(branch)
	if err := validateBranchName(branch); err != nil {
		return "", err
	}
	return "refs/heads/" + branch, nil
}

func validateBranchName(branch string) error {
	for _, validate := range []func(string) error{
		requireBranchName,
		validateBranchPath,
		validateBranchGitSyntax,
		validateBranchChars,
	} {
		if err := validate(branch); err != nil {
			return err
		}
	}
	return nil
}

func requireBranchName(branch string) error {
	if branch == "" {
		return errors.New("branch is required")
	}
	return nil
}

func validateBranchPath(branch string) error {
	if strings.HasPrefix(branch, "/") || strings.HasSuffix(branch, "/") || strings.Contains(branch, "//") {
		return errors.New("branch path is malformed")
	}
	return nil
}

func validateBranchGitSyntax(branch string) error {
	if strings.Contains(branch, "..") || strings.Contains(branch, "@{") {
		return errors.New("branch contains unsupported git syntax")
	}
	return nil
}

func validateBranchChars(branch string) error {
	if strings.ContainsAny(branch, " \t\r\n~^:?*[\\") {
		return errors.New("branch contains unsupported characters")
	}
	return nil
}

func contentPathParam(c echo.Context) (string, error) {
	contentPath := c.Param("*")
	if contentPath == "" {
		return ".", nil
	}
	if err := validateContentPath(contentPath); err != nil {
		return "", echo.NewHTTPError(http.StatusBadRequest, err.Error())
	}
	return contentPath, nil
}

func validateContentPath(contentPath string) error {
	for _, rawSegment := range strings.Split(contentPath, "/") {
		segment, err := url.PathUnescape(rawSegment)
		if err != nil {
			segment = rawSegment
		}
		if escapedPathSeparator(rawSegment) || strings.Contains(segment, "/") {
			return errors.New("content path contains escaped path separator")
		}
		if segment == "" || segment == "." || segment == ".." {
			return errors.New("content path contains unsupported path segment")
		}
	}
	return nil
}

func escapedPathSeparator(segment string) bool {
	return strings.Contains(strings.ToLower(segment), "%2f")
}

func (s *Server) proxyPullRequest(c echo.Context) error {
	upstreamURL := s.githubAPIBaseURL.JoinPath("repos", c.Param("owner"), c.Param("repo"), "pulls")
	return s.proxyTo(c, upstreamURL, func(request *http.Request) error {
		return s.configureGitHubAPIRequest(c, request, c.Param("owner"), c.Param("repo"))
	})
}

func (s *Server) proxyContents(c echo.Context) error {
	segments := []string{"repos", c.Param("owner"), c.Param("repo"), "contents"}
	contentPath, err := contentPathParam(c)
	if err != nil {
		return err
	}
	if contentPath != "." {
		segments = append(segments, escapedJoinPathSegments(contentPath)...)
	}
	upstreamURL := s.githubAPIBaseURL.JoinPath(segments...)
	query := url.Values{}
	if ref := c.QueryParam("ref"); ref != "" {
		query.Set("ref", ref)
	}
	upstreamURL.RawQuery = query.Encode()
	return s.proxyTo(c, upstreamURL, func(request *http.Request) error {
		return s.configureGitHubAPIRequest(c, request, c.Param("owner"), c.Param("repo"))
	})
}

func escapedJoinPathSegments(pathValue string) []string {
	segments := strings.Split(pathValue, "/")
	for index, segment := range segments {
		segments[index] = strings.ReplaceAll(segment, "%", "%25")
	}
	return segments
}

func (s *Server) fetchAndFilterRepos(c echo.Context) error {
	response, err := s.fetchRepoList(c)
	if err != nil {
		return err
	}
	defer func() {
		_ = response.Body.Close()
	}()
	if !successfulStatus(response.StatusCode) {
		httpx.CopyHeaders(c.Response().Header(), response.Header, githubProxyResponseHeader)
		return copyUpstreamResponse(c, response)
	}
	httpx.CopyHeaders(c.Response().Header(), response.Header, githubFilteredResponseHeader)
	return s.writeFilteredRepoList(c, response)
}

func (s *Server) fetchRepoList(c echo.Context) (*http.Response, error) {
	if s.githubApp != nil {
		return s.fetchGitHubAppRepoList(c)
	}
	upstreamURLs := s.repoListURLs(c)
	var response *http.Response
	var err error
	for index, upstreamURL := range upstreamURLs {
		response, err = s.fetchRepoListURL(c, upstreamURL)
		if err != nil {
			return nil, err
		}
		if index == 0 && repoListShouldFallback(response.StatusCode) {
			_ = response.Body.Close()
			continue
		}
		return response, nil
	}
	return response, nil
}

func (s *Server) fetchRepoListURL(c echo.Context, upstreamURL *url.URL) (*http.Response, error) {
	request, err := http.NewRequestWithContext(c.Request().Context(), http.MethodGet, upstreamURL.String(), http.NoBody)
	if err != nil {
		return nil, echo.NewHTTPError(http.StatusBadGateway, "create upstream github request")
	}
	if err := s.configureGitHubAPIRequest(c, request, "", ""); err != nil {
		return nil, err
	}
	// #nosec G704 -- upstream URL is built from a fixed GitHub API base URL.
	response, err := s.githubClient.Do(request)
	if err != nil {
		return nil, echo.NewHTTPError(http.StatusBadGateway, "upstream github request failed")
	}
	return response, nil
}

func (s *Server) repoListURLs(c echo.Context) []*url.URL {
	userURL := s.repoListURL(c, "user", "repos")
	installationURL := s.repoListURL(c, "installation", "repositories")
	if looksLikeInstallationToken(s.githubToken) {
		return []*url.URL{installationURL, userURL}
	}
	return []*url.URL{userURL, installationURL}
}

func (s *Server) repoListURL(c echo.Context, pathSegments ...string) *url.URL {
	upstreamURL := s.githubAPIBaseURL.JoinPath(pathSegments...)
	query := url.Values{}
	query.Set("per_page", boundedQueryInt(c.QueryParam("per_page"), 100, 1, 100))
	if page := boundedQueryInt(c.QueryParam("page"), 0, 1, 100000); page != "0" {
		query.Set("page", page)
	}
	upstreamURL.RawQuery = query.Encode()
	return upstreamURL
}

func looksLikeInstallationToken(token string) bool {
	return strings.HasPrefix(token, "ghs_")
}

func repoListShouldFallback(status int) bool {
	return status == http.StatusUnauthorized || status == http.StatusForbidden
}

func successfulStatus(status int) bool {
	return status >= http.StatusOK && status < http.StatusMultipleChoices
}

func copyUpstreamResponse(c echo.Context, response *http.Response) error {
	c.Response().WriteHeader(response.StatusCode)
	_, err := io.Copy(c.Response(), response.Body)
	return err
}

func (s *Server) writeFilteredRepoList(c echo.Context, response *http.Response) error {
	body, err := httpx.ReadLimited(response.Body, 10*1024*1024)
	if err != nil {
		return echo.NewHTTPError(http.StatusBadGateway, "github repo list response is too large")
	}
	filtered, err := s.filterRepos(c, body)
	if err != nil {
		return echo.NewHTTPError(http.StatusBadGateway, "decode github repo list")
	}
	return c.JSONBlob(response.StatusCode, filtered)
}

func (s *Server) filterRepos(c echo.Context, body []byte) ([]byte, error) {
	var repos []json.RawMessage
	if err := json.Unmarshal(body, &repos); err != nil {
		var installationPayload struct {
			Repositories []json.RawMessage `json:"repositories"`
		}
		if objectErr := json.Unmarshal(body, &installationPayload); objectErr != nil || installationPayload.Repositories == nil {
			return nil, err
		}
		repos = installationPayload.Repositories
		filtered := s.filterRepoArray(c, repos)
		return json.Marshal(map[string][]json.RawMessage{"repositories": filtered})
	}
	return json.Marshal(s.filterRepoArray(c, repos))
}

func (s *Server) filterRepoArray(c echo.Context, repos []json.RawMessage) []json.RawMessage {
	filtered := make([]json.RawMessage, 0, len(repos))
	for _, raw := range repos {
		owner, name, ok := repoIdentity(raw)
		if !ok {
			continue
		}
		request := policy.Request{
			Client:    security.ClientFromContext(c),
			Operation: policy.OperationRepoMetadataRead,
			Target:    policy.Target{Kind: "repo", Owner: owner, Name: name},
		}
		if s.policy.Allows(request) {
			filtered = append(filtered, raw)
		}
	}
	return filtered
}

func repoIdentity(raw json.RawMessage) (string, string, bool) {
	var repo struct {
		Name     string `json:"name"`
		FullName string `json:"full_name"`
		Owner    struct {
			Login string `json:"login"`
		} `json:"owner"`
	}
	if err := json.Unmarshal(raw, &repo); err != nil {
		return "", "", false
	}
	owner := strings.TrimSpace(repo.Owner.Login)
	name := strings.TrimSpace(repo.Name)
	if owner == "" || name == "" {
		fullOwner, fullName, ok := strings.Cut(repo.FullName, "/")
		if ok {
			owner = strings.TrimSpace(fullOwner)
			name = strings.TrimSpace(fullName)
		}
	}
	return owner, name, owner != "" && name != ""
}

func boundedQueryInt(value string, fallback int, minValue int, maxValue int) string {
	if value == "" {
		return strconv.Itoa(fallback)
	}
	parsed, err := strconv.Atoi(value)
	if err != nil || parsed < minValue || parsed > maxValue {
		return strconv.Itoa(fallback)
	}
	return strconv.Itoa(parsed)
}

func (s *Server) proxyTo(c echo.Context, upstreamURL *url.URL, configure func(*http.Request) error) error {
	request, err := http.NewRequestWithContext(
		c.Request().Context(),
		c.Request().Method,
		upstreamURL.String(),
		c.Request().Body,
	)
	if err != nil {
		return echo.NewHTTPError(http.StatusBadGateway, "create upstream github request")
	}
	httpx.CopyHeaders(request.Header, c.Request().Header, httpx.ProxyRequestHeader)
	if err := configure(request); err != nil {
		return err
	}
	return s.doProxy(c, request)
}

func (s *Server) doProxy(c echo.Context, request *http.Request) error {
	// #nosec G704 -- upstream URLs are built from fixed GitHub base URLs and policy-gated route params.
	response, err := s.githubClient.Do(request)
	if err != nil {
		return echo.NewHTTPError(http.StatusBadGateway, "upstream github request failed")
	}
	defer func() {
		_ = response.Body.Close()
	}()
	httpx.CopyHeaders(c.Response().Header(), response.Header, githubProxyResponseHeader)
	c.Response().WriteHeader(response.StatusCode)
	_, err = io.Copy(c.Response(), response.Body)
	return err
}

func (s *Server) audit(c echo.Context, request policy.Request, outcome string, reason string, status int, matchedRuleIDs []string) {
	repo := request.Target.Name
	if repo == "" {
		repo = strings.TrimSuffix(c.Param("repoGit"), ".git")
	}
	attrs := []any{
		"client", request.Client,
		"operation", string(request.Operation),
		"outcome", outcome,
		"owner", request.Target.Owner,
		"repo", repo,
		"method", c.Request().Method,
		"path", c.Request().URL.Path,
	}
	if status != 0 {
		attrs = append(attrs, "status", status)
	}
	if reason != "" {
		attrs = append(attrs, "reason", reason)
	}
	if len(matchedRuleIDs) > 0 {
		attrs = append(attrs, "matched_rules", matchedRuleIDs)
	}
	if installationID, ok := c.Get("github_installation_id").(int64); ok && installationID > 0 {
		attrs = append(attrs, "github_installation_id", installationID)
	}
	s.logger.Info("broker operation", attrs...)
}

func (s *Server) auditAuthorizedReceivePack(c echo.Context, authorized []authorizedReceivePackRequest, outcome string, reason string, status int) {
	for _, item := range authorized {
		s.audit(c, item.Request, outcome, reason, status, item.Decision.MatchedRuleIDs)
	}
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

func outcomeForDecision(decision policy.Decision) string {
	switch decision.Effect {
	case policy.EffectRequest:
		return "requires_grant"
	default:
		return "denied"
	}
}

func statusForDecision(decision policy.Decision) int {
	if decision.Effect == policy.EffectRequest {
		return http.StatusConflict
	}
	return http.StatusForbidden
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
