package httpapi

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/labstack/echo/v4"
	"github.com/labstack/echo/v4/middleware"
	"github.com/osolmaz/brokerkit/agentapi"
	"github.com/osolmaz/brokerkit/agentops"
	bkaudit "github.com/osolmaz/brokerkit/audit"
	bkauth "github.com/osolmaz/brokerkit/auth"
	bkauthorization "github.com/osolmaz/brokerkit/authorization"
	"github.com/osolmaz/brokerkit/brokers/github/internal/approval"
	"github.com/osolmaz/brokerkit/brokers/github/internal/config"
	"github.com/osolmaz/brokerkit/brokers/github/internal/ghplan"
	"github.com/osolmaz/brokerkit/brokers/github/internal/githubauth"
	"github.com/osolmaz/brokerkit/brokers/github/internal/opcatalog"
	"github.com/osolmaz/brokerkit/brokers/github/internal/operations"
	"github.com/osolmaz/brokerkit/brokers/github/internal/policy"
	"github.com/osolmaz/brokerkit/brokers/github/internal/security"
	"github.com/osolmaz/brokerkit/capability"
	"github.com/osolmaz/brokerkit/controlplane"
	"github.com/osolmaz/brokerkit/credentialstore"
	"github.com/osolmaz/brokerkit/grants"
	"github.com/osolmaz/brokerkit/httpx"
	"github.com/osolmaz/brokerkit/internal/strictjson"
	"github.com/osolmaz/brokerkit/notify"
	bktelegram "github.com/osolmaz/brokerkit/notify/telegram"
	"github.com/osolmaz/brokerkit/sealedpayload"
	"github.com/osolmaz/brokerkit/sealedstore"
	"github.com/osolmaz/brokerkit/state"
	"github.com/osolmaz/brokerkit/streamstore"
)

type Server struct {
	echo                *echo.Echo
	authorization       *bkauthorization.Coordinator
	policy              *policy.Policy
	grants              *grants.Store
	plans               *ghplan.Store
	planValidator       ghplan.Validator
	control             *controlplane.Runtime
	database            *state.Database
	operations          *agentops.Store
	operationRegistry   *operations.Registry
	operationRuntime    *operations.Runtime
	agentAPI            *agentapi.Handler
	sealedStore         *sealedstore.Store
	sealedPayloads      *sealedpayload.Service
	credentialStore     *credentialstore.Store
	streamStore         *streamstore.Store
	notifier            notify.Notifier
	telegram            *bktelegram.Client
	githubCredentials   *githubauth.Manager
	githubWebhookSecret string
	githubClient        *http.Client
	githubGitBaseURL    *url.URL
	githubAPIBaseURL    *url.URL
	auditWriter         *bkaudit.Writer
	logger              *slog.Logger
	maxReceivePackBytes int64
	operatorConfigured  bool
	closeOnce           sync.Once
	closeErr            error
	lifecycleContext    context.Context
	lifecycleCancel     context.CancelFunc
	backgroundWorkers   sync.WaitGroup
}

func New(cfg config.Config, brokerPolicy *policy.Policy) (*Server, error) {
	if brokerPolicy == nil {
		return nil, errors.New("policy is required")
	}
	core, err := newCoreDependencies(cfg)
	if err != nil {
		return nil, err
	}
	e := echo.New()
	e.HideBanner = true
	e.HidePort = true
	e.Use(middleware.Recover())
	e.Use(noStore)
	e.GET("/healthz", health)
	gitBaseURL, apiBaseURL, githubClient, appSource, credentialSlots, err := newGitHubDependencies(cfg)
	if err != nil {
		_ = core.database.Close()
		return nil, err
	}
	server := &Server{
		echo: e, policy: brokerPolicy, grants: core.grants, plans: core.plans, planValidator: core.validator, control: core.control,
		database: core.database, operations: agentops.New(core.database), notifier: core.notifier, telegram: core.telegram,
		githubCredentials: appSource, githubWebhookSecret: cfg.GitHubWebhookSecret,
		credentialStore: credentialSlots,
		githubClient:    githubClient, githubGitBaseURL: gitBaseURL, githubAPIBaseURL: apiBaseURL,
		auditWriter: core.audit, logger: slog.Default(), maxReceivePackBytes: defaultInt64(cfg.MaxReceivePackBytes, 25*1024*1024),
		operatorConfigured: cfg.OperatorSecret != "",
	}
	server.sealedStore, err = sealedstore.Open(stateDir(cfg.StateDir))
	if err != nil {
		_ = core.database.Close()
		return nil, err
	}
	server.streamStore, err = streamstore.Open(stateDir(cfg.StateDir))
	if err != nil {
		_ = core.database.Close()
		return nil, err
	}
	adapters, err := operations.NewGeneratedAdapters(appSource, operations.Options{
		RequestingUserID: cfg.GitHubUserID,
		SealedStore:      server.sealedStore,
		CredentialStore:  server.credentialStore,
		StreamStore:      server.streamStore,
	})
	if err != nil {
		_ = core.database.Close()
		return nil, err
	}
	server.operationRegistry, err = operations.NewRegistry(adapters...)
	if err != nil {
		_ = core.database.Close()
		return nil, err
	}
	if err = server.operationRegistry.ValidateCoverage(); err != nil {
		_ = core.database.Close()
		return nil, err
	}
	registry, registryErr := policy.AuthorizationRegistry()
	if registryErr == nil {
		server.authorization, registryErr = bkauthorization.New(bkauthorization.Options{
			Registry: registry, Decide: brokerPolicy.DecideAuthorization, Grants: core.grants,
		})
	}
	if registryErr != nil {
		_ = core.database.Close()
		return nil, registryErr
	}
	server.operationRuntime, err = server.newOperationRuntime()
	if err != nil {
		_ = core.database.Close()
		return nil, err
	}
	server.agentAPI, err = agentapi.New(agentapi.Options{
		Store: server.operations, Authenticate: core.control.Clients.AuthenticateHeader,
		Submit: server.submitAgentOperation, Cancel: server.cancelAgentOperation, Realm: "gh-broker",
	})
	if err != nil {
		_ = core.database.Close()
		return nil, err
	}
	server.sealedPayloads, err = sealedpayload.New(sealedpayload.Options{
		Store: server.sealedStore,
		Descriptor: func(name string) (capability.Descriptor, bool) {
			descriptor, found := opcatalog.ByName(name)
			return descriptor.Descriptor, found
		},
		Authenticate: server.authenticateAgentUpload,
		WriteFailure: writeSealedPayloadFailure,
	})
	if err != nil {
		_ = core.database.Close()
		return nil, err
	}
	server.registerRoutes(core.auth)
	return server, nil
}

type coreDependencies struct {
	database  *state.Database
	grants    *grants.Store
	plans     *ghplan.Store
	validator ghplan.Validator
	audit     *bkaudit.Writer
	control   *controlplane.Runtime
	auth      security.TokenAuth
	notifier  notify.Notifier
	telegram  *bktelegram.Client
}

func newCoreDependencies(cfg config.Config) (coreDependencies, error) {
	database, err := state.Open(context.Background(), stateDir(cfg.StateDir), state.Options{})
	if err != nil {
		return coreDependencies{}, err
	}
	grantStore := grants.NewDatabase(database, grants.Options{})
	plans, err := ghplan.NewStore(database, githubCredentialMode(cfg))
	if err != nil {
		_ = database.Close()
		return coreDependencies{}, err
	}
	validator := ghplan.Validator{Store: plans}
	auditWriter := bkaudit.New(os.Stderr)
	control, auth, err := newControlPlane(cfg, grantStore, validator, auditWriter)
	if err != nil {
		_ = database.Close()
		return coreDependencies{}, err
	}
	notifier, telegram, err := configuredNotifier(cfg)
	if err != nil {
		_ = database.Close()
		return coreDependencies{}, err
	}
	return coreDependencies{database: database, grants: grantStore, plans: plans, validator: validator, audit: auditWriter,
		control: control, auth: auth, notifier: notifier, telegram: telegram}, nil
}

func newGitHubDependencies(cfg config.Config) (*url.URL, *url.URL, *http.Client, *githubauth.Manager, *credentialstore.Store, error) {
	gitBaseURL, apiBaseURL, err := githubBaseURLs(cfg)
	if err != nil {
		return nil, nil, nil, nil, nil, err
	}
	client := newGitHubClient(defaultDuration(cfg.GitHubHTTPTimeout, 30*time.Second))
	encryptedStore, err := credentialstore.Open(stateDir(cfg.StateDir))
	if err != nil {
		return nil, nil, nil, nil, nil, err
	}
	manager, err := githubauth.New(githubauth.Config{
		AppID: cfg.GitHubAppID, AppPrivateKey: cfg.GitHubAppPrivateKey, AppClientID: cfg.GitHubAppClientID,
		AppClientSecret: []byte(cfg.GitHubAppClientSecret), DevelopmentToken: []byte(cfg.GitHubToken),
		DevelopmentTokenFile: cfg.GitHubTokenFile, APIBaseURL: apiBaseURL, WebBaseURL: gitBaseURL,
		HTTPClient: client, Store: encryptedStore,
	})
	return gitBaseURL, apiBaseURL, client, manager, encryptedStore, err
}

func githubCredentialMode(cfg config.Config) string {
	if strings.TrimSpace(cfg.GitHubAppID) != "" && len(cfg.GitHubAppPrivateKey) > 0 {
		return string(githubauth.KindInstallation)
	}
	return string(githubauth.KindDevelopmentToken)
}

func newControlPlane(cfg config.Config, grantStore *grants.Store, planValidator ghplan.Validator, auditWriter *bkaudit.Writer) (*controlplane.Runtime, security.TokenAuth, error) {
	operatorSecrets := map[string]string{}
	if cfg.OperatorSecret != "" {
		operatorSecrets[cfg.OperatorID] = cfg.OperatorSecret
	}
	control, err := controlplane.New(controlplane.Options{
		Broker: "gh-broker", Store: grantStore,
		ClientSecrets: map[string]string{cfg.ClientID: cfg.SharedSecret}, OperatorSecrets: operatorSecrets,
		Presenter: approval.Presenter{}, ActivationValidator: planValidator, Audit: auditWriter,
	})
	if err != nil {
		return nil, security.TokenAuth{}, err
	}
	auth, err := security.FromAuthenticator(control.Clients)
	if err != nil {
		return nil, security.TokenAuth{}, err
	}
	return control, auth, nil
}

func (s *Server) registerRoutes(auth security.TokenAuth) {
	s.agentAPI.Register(s.echo)
	s.echo.POST("/api/agent/v1/sealed-payloads", s.sealedPayloads.Upload)
	s.echo.POST("/api/agent/v1/streams", s.uploadStream)
	s.echo.GET("/api/agent/v1/streams/:id", s.downloadStream)
	protected := s.echo.Group("")
	protected.Use(auth.Middleware)
	protected.Use(validateRouteParams)
	protected.GET("/api/repos", s.listRepos)
	protected.POST("/api/grants", s.createGrant)
	protected.GET("/api/grants", s.listGrants)
	protected.GET("/api/grants/:id", s.getGrant)
	protected.GET("/api/repos/:owner/:repo/contents", s.readContents)
	protected.GET("/api/repos/:owner/:repo/contents/*", s.readContents)
	protected.GET("/:owner/:repoGit/info/refs", s.gitInfoRefs)
	protected.POST("/:owner/:repoGit/git-upload-pack", s.gitUploadPack)
	protected.POST("/:owner/:repoGit/git-receive-pack", s.gitReceivePack)
	s.echo.POST("/webhooks/github", s.githubWebhook)
}

func (s *Server) authenticateAgentUpload(response http.ResponseWriter, request *http.Request) (string, bool) {
	client, err := s.control.Clients.AuthenticateHeader(request.Header.Get("Authorization"))
	if err == nil {
		return client, true
	}
	status := http.StatusForbidden
	reason := "bad_auth"
	message := "Authentication failed"
	if errors.Is(err, bkauth.ErrMissing) {
		status = http.StatusUnauthorized
		reason = "missing_auth"
		message = "Authentication required"
		response.Header().Set("WWW-Authenticate", `Bearer realm="gh-broker"`)
	}
	writeSealedPayloadFailure(response, status, reason, message)
	return "", false
}

func writeSealedPayloadFailure(response http.ResponseWriter, status int, reason, message string) {
	response.Header().Set("Content-Type", "application/json")
	response.WriteHeader(status)
	_ = json.NewEncoder(response).Encode(map[string]any{
		"status": "fail",
		"data":   map[string]string{"reason": reason, "message": message},
	})
}

// OperatorHandler exposes Brokerkit's shared inbox over the canonical grant store.
func (s *Server) OperatorHandler() http.Handler { return s.control.OperatorHandler }

func githubBaseURLs(cfg config.Config) (*url.URL, *url.URL, error) {
	webBase := cfg.GitHubWebBaseURL
	if strings.TrimSpace(webBase) == "" {
		webBase = "https://github.com/"
	}
	apiBase := cfg.GitHubAPIBaseURL
	if strings.TrimSpace(apiBase) == "" {
		apiBase = "https://api.github.com/"
	}
	gitBaseURL, err := url.Parse(webBase)
	if err != nil {
		return nil, nil, err
	}
	apiBaseURL, err := url.Parse(apiBase)
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

// Close releases the broker's durable state lease and database handles.
func (s *Server) Close() error {
	if s == nil {
		return nil
	}
	s.closeOnce.Do(func() {
		if s.lifecycleCancel != nil {
			s.lifecycleCancel()
		}
		if s.operationRuntime != nil {
			s.operationRuntime.Wait()
		}
		if s.sealedPayloads != nil {
			s.sealedPayloads.Wait()
		}
		s.backgroundWorkers.Wait()
		s.closeErr = s.database.Close()
	})
	return s.closeErr
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
	if err := s.enforceReceivePackBackstops(c, authorized); err != nil {
		s.releaseGrantUses(reserved)
		s.auditAuthorizedReceivePack(c, authorized, errorOutcome(err), errorString(err), errorStatus(c, err))
		return err
	}
	c.Request().Body = io.NopCloser(bytes.NewReader(body))
	c.Request().ContentLength = int64(len(body))
	response, err := s.forwardGit(c)
	if err != nil {
		err = s.settleFailedExecution(c, reserved, err)
		s.auditAuthorizedReceivePack(c, authorized, errorOutcome(err), errorString(err), errorStatus(c, err))
		return err
	}
	defer func() {
		_ = response.Body.Close()
	}()
	if err := s.commitGrantUses(reserved); err != nil {
		_ = s.closeGrantUsesAfterCommitFailure(reserved)
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
	return s.runAuthorizedBrokerRequest(c, request, decision, reserved, run)
}

func (s *Server) runAuthorizedBrokerRequest(
	c echo.Context,
	request policy.Request,
	decision policy.Decision,
	reserved []grants.Grant,
	run func(echo.Context) error,
) error {
	c.Set(githubOperationContextKey, string(request.Operation))
	err := run(c)
	if err != nil {
		err = s.settleFailedExecution(c, reserved, err)
		s.audit(c, request, errorOutcome(err), errorString(err), errorStatus(c, err), decision.MatchedRuleIDs)
		return err
	}
	if err := s.commitGrantUses(reserved); err != nil {
		_ = s.closeGrantUsesAfterCommitFailure(reserved)
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
	if err := strictjson.Decode(body, &payload, true); err != nil {
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
	return s.fetchCredentialRepoList(c)
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

func (s *Server) audit(c echo.Context, request policy.Request, outcome string, reason string, status int, matchedRuleIDs []string) {
	repo := request.Target.Name
	if repo == "" {
		repo = strings.TrimSuffix(c.Param("repoGit"), ".git")
	}
	event := bkaudit.Event{
		Broker:         "gh-broker",
		Client:         request.Client,
		Operation:      string(request.Operation),
		Target:         repositoryTarget(request.Target.Owner, repo),
		Decision:       outcome,
		Reason:         reason,
		MatchedRuleIDs: matchedRuleIDs,
		Status:         status,
		Attrs: map[string]string{
			"method": c.Request().Method,
			"path":   c.Request().URL.Path,
		},
		Extensions: map[string]string{},
	}
	if installationID, ok := c.Get("github_installation_id").(int64); ok && installationID > 0 {
		event.Extensions["github_installation_id"] = strconv.FormatInt(installationID, 10)
	}
	_ = s.auditWriter.Record(event)
}

func repositoryTarget(owner string, repo string) string {
	if owner == "" {
		return repo
	}
	return owner + "/" + repo
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
