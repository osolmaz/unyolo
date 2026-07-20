package httpapi

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
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
	"github.com/osolmaz/brokerkit/agent/api"
	"github.com/osolmaz/brokerkit/agent/runtime"
	"github.com/osolmaz/brokerkit/agent/v1"
	"github.com/osolmaz/brokerkit/approval/notification"
	bktelegram "github.com/osolmaz/brokerkit/approval/notifier/telegram"
	bkauth "github.com/osolmaz/brokerkit/auth"
	bkauthorization "github.com/osolmaz/brokerkit/authorization"
	"github.com/osolmaz/brokerkit/authorization/admission"
	"github.com/osolmaz/brokerkit/authorization/grants"
	"github.com/osolmaz/brokerkit/broker/controlplane"
	"github.com/osolmaz/brokerkit/brokers/github/internal/approval"
	"github.com/osolmaz/brokerkit/brokers/github/internal/config"
	"github.com/osolmaz/brokerkit/brokers/github/internal/ghplan"
	"github.com/osolmaz/brokerkit/brokers/github/internal/githubauth"
	"github.com/osolmaz/brokerkit/brokers/github/internal/opcatalog"
	"github.com/osolmaz/brokerkit/brokers/github/internal/operations"
	"github.com/osolmaz/brokerkit/brokers/github/internal/policy"
	"github.com/osolmaz/brokerkit/brokers/github/internal/security"
	"github.com/osolmaz/brokerkit/credential/lifecycle"
	"github.com/osolmaz/brokerkit/credential/provider"
	"github.com/osolmaz/brokerkit/credential/store"
	"github.com/osolmaz/brokerkit/git/server"
	"github.com/osolmaz/brokerkit/internal/storage/sealed"
	"github.com/osolmaz/brokerkit/internal/storage/state"
	"github.com/osolmaz/brokerkit/internal/storage/stream"
	"github.com/osolmaz/brokerkit/operation/capability"
	"github.com/osolmaz/brokerkit/operation/payload"
	bkaudit "github.com/osolmaz/brokerkit/telemetry/audit"
	"github.com/osolmaz/brokerkit/transport/http"
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
	admission           *admission.Controller
	operationRegistry   *operations.Registry
	operationRuntime    *operations.Runtime
	agentAPI            *agentapi.Handler
	sealedStore         *sealedstore.Store
	sealedPayloads      *sealedpayload.Service
	credentialStore     *credentialstore.Store
	streamStore         *streamstore.Store
	notifier            approvalnotify.Notifier
	telegram            *bktelegram.Client
	githubCredentials   *githubauth.Manager
	githubWebhookSecret string
	githubClient        *http.Client
	githubGitClient     *http.Client
	githubGitBaseURL    *url.URL
	githubAPIBaseURL    *url.URL
	auditWriter         *bkaudit.Writer
	logger              *slog.Logger
	maxReceivePackBytes int64
	operatorConfigured  bool
	lfsMu               sync.Mutex
	lfsActions          map[string]githubLFSAction
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
	server, err := newServerWithCore(cfg, brokerPolicy, core)
	if err != nil {
		_ = core.database.Close()
		return nil, err
	}
	return server, nil
}

func newServerWithCore(cfg config.Config, brokerPolicy *policy.Policy, core coreDependencies) (*Server, error) {
	github, err := newGitHubDependencies(cfg, core.audit)
	if err != nil {
		return nil, err
	}
	core.credentialResolver.manager = github.appSource
	operationStore, admissionController, err := newAdmissionDependencies(cfg, core)
	if err != nil {
		return nil, err
	}
	server := newServerSkeleton(cfg, brokerPolicy, core, operationStore, admissionController, github)
	if err := server.configureServerFeatures(cfg, brokerPolicy, core, github.appSource); err != nil {
		return nil, err
	}
	server.registerRoutes(core.auth)
	return server, nil
}

type githubDependencies struct {
	gitBaseURL       *url.URL
	apiBaseURL       *url.URL
	client           *http.Client
	gitClient        *http.Client
	appSource        *githubauth.Manager
	credentialStore  *credentialstore.Store
	webhookSecret    string
	receivePackLimit int64
}

func newAdmissionDependencies(cfg config.Config, core coreDependencies) (*agentops.Store, *admission.Controller, error) {
	operationStore := agentops.New(core.database)
	controller, err := admission.NewConfigured([]string{cfg.ClientID}, cfg.Admission, operationStore.AdmissionUsage)
	if err != nil {
		return nil, nil, err
	}
	controller.SetObserver(core.control.Metrics)
	return operationStore, controller, nil
}

func newServerSkeleton(
	cfg config.Config,
	brokerPolicy *policy.Policy,
	core coreDependencies,
	operationStore *agentops.Store,
	admissionController *admission.Controller,
	github githubDependencies,
) *Server {
	return &Server{
		echo: newEcho(), policy: brokerPolicy, grants: core.grants, plans: core.plans, planValidator: core.validator, control: core.control,
		database: core.database, operations: operationStore, admission: admissionController, notifier: core.notifier, telegram: core.telegram,
		githubCredentials: github.appSource, githubWebhookSecret: github.webhookSecret,
		credentialStore: github.credentialStore,
		githubClient:    github.client, githubGitClient: github.gitClient,
		githubGitBaseURL: github.gitBaseURL, githubAPIBaseURL: github.apiBaseURL,
		auditWriter: core.audit, logger: slog.Default(), maxReceivePackBytes: github.receivePackLimit,
		operatorConfigured: cfg.OperatorSecret != "",
		lfsActions:         map[string]githubLFSAction{},
	}
}

func newEcho() *echo.Echo {
	e := echo.New()
	e.HideBanner = true
	e.HidePort = true
	e.Use(middleware.Recover())
	e.Use(noStore)
	e.GET("/healthz", health)
	return e
}

func (s *Server) configureServerFeatures(cfg config.Config, brokerPolicy *policy.Policy, core coreDependencies, appSource *githubauth.Manager) error {
	for _, configure := range []func() error{
		func() error { return s.configureAgentRuntimeStores(cfg) },
		func() error { return s.configureOperationRegistry(cfg, appSource) },
		func() error { return s.configureAuthorization(brokerPolicy, core.grants) },
		s.configureOperationRuntime,
		func() error { return s.configureAgentAPI(core.control) },
		s.configureSealedPayloads,
	} {
		if err := configure(); err != nil {
			return err
		}
	}
	return nil
}

func (s *Server) configureAgentRuntimeStores(cfg config.Config) error {
	var err error
	s.sealedStore, err = sealedstore.Open(stateDir(cfg.StateDir))
	if err != nil {
		return err
	}
	s.streamStore, err = streamstore.Open(stateDir(cfg.StateDir))
	return err
}

func (s *Server) configureOperationRegistry(cfg config.Config, appSource *githubauth.Manager) error {
	adapters, err := operations.NewGeneratedAdapters(appSource, operations.Options{
		RequestingUserID: cfg.GitHubUserID,
		SealedStore:      s.sealedStore,
		CredentialStore:  s.credentialStore,
		StreamStore:      s.streamStore,
	})
	if err != nil {
		return err
	}
	registry, err := operations.NewRegistry(adapters...)
	if err != nil {
		return err
	}
	if err := registry.ValidateCoverage(); err != nil {
		return err
	}
	s.operationRegistry = registry
	return nil
}

func (s *Server) configureAuthorization(brokerPolicy *policy.Policy, grantStore *grants.Store) error {
	registry, registryErr := policy.AuthorizationRegistry()
	if registryErr == nil {
		s.authorization, registryErr = bkauthorization.New(bkauthorization.Options{
			Registry: registry, Decide: brokerPolicy.DecideAuthorization, Grants: grantStore,
		})
	}
	return registryErr
}

func (s *Server) configureOperationRuntime() error {
	runtime, err := s.newOperationRuntime()
	if err != nil {
		return err
	}
	s.operationRuntime = runtime
	return nil
}

func (s *Server) configureAgentAPI(control *controlplane.Runtime) error {
	handler, err := agentapi.New(agentapi.Options{
		Store: s.operations, Authenticate: control.Clients.AuthenticateHeader,
		Submit: s.submitAgentOperation, Cancel: s.cancelAgentOperation, Realm: "gh-broker",
		Discover: s.discoverAgent,
	})
	if err != nil {
		return err
	}
	s.agentAPI = handler
	return nil
}

func (s *Server) discoverAgent(_ string) agentv1.Descriptor {
	kind := s.githubCredentials.CredentialKind()
	descriptor := agentv1.Descriptor{APIVersion: agentv1.APIVersion, Operations: []string{},
		Credential: agentv1.CredentialDescriptor{Ready: true, Provider: "github", CredentialKind: string(kind), Generation: 1, VerificationState: "valid"}}
	if kind != githubauth.KindInstallation {
		return descriptor
	}
	adapter := githubauth.ProviderAdapter{}
	for _, operation := range opcatalog.MustAll() {
		if !operation.AgentFacing || operation.CredentialKind == string(githubauth.KindUser) {
			continue
		}
		if _, found := adapter.Requirement(operation.Name); found {
			descriptor.Operations = append(descriptor.Operations, operation.Name)
		}
	}
	return descriptor
}

func (s *Server) configureSealedPayloads() error {
	payloads, err := sealedpayload.New(sealedpayload.Options{
		Store: s.sealedStore,
		Descriptor: func(name string) (capability.Descriptor, bool) {
			descriptor, found := opcatalog.ByName(name)
			return descriptor.Descriptor, found
		},
		Authenticate: s.authenticateAgentUpload,
		WriteFailure: writeSealedPayloadFailure,
	})
	if err != nil {
		return err
	}
	s.sealedPayloads = payloads
	return nil
}

type coreDependencies struct {
	database           *state.Database
	grants             *grants.Store
	plans              *ghplan.Store
	validator          ghplan.Validator
	audit              *bkaudit.Writer
	control            *controlplane.Runtime
	auth               security.TokenAuth
	notifier           approvalnotify.Notifier
	telegram           *bktelegram.Client
	credentialResolver *currentGitHubCredentialResolver
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
	credentialResolver := &currentGitHubCredentialResolver{}
	validator := ghplan.Validator{Store: plans,
		Credential:  credentialResolver.snapshot,
		Requirement: (githubauth.ProviderAdapter{}).Requirement,
	}
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
		control: control, auth: auth, notifier: notifier, telegram: telegram, credentialResolver: credentialResolver}, nil
}

type currentGitHubCredentialResolver struct {
	manager *githubauth.Manager
}

func (r *currentGitHubCredentialResolver) snapshot(plan ghplan.Plan) (providercredential.Snapshot, error) {
	manager, err := r.currentManager()
	if err != nil {
		return providercredential.Snapshot{}, err
	}
	metadata, err := operations.CredentialFromPreconditions(plan.Preconditions)
	if err != nil {
		return providercredential.Snapshot{}, err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	return manager.CurrentSnapshot(ctx, metadata, 1, time.Now().UTC())
}

func (r *currentGitHubCredentialResolver) currentManager() (*githubauth.Manager, error) {
	if r == nil || r.manager == nil {
		return nil, errors.New("GitHub credential provider is unavailable")
	}
	return r.manager, nil
}

func newGitHubDependencies(cfg config.Config, auditWriter bkaudit.Recorder) (githubDependencies, error) {
	gitBaseURL, apiBaseURL, err := githubBaseURLs(cfg)
	if err != nil {
		return githubDependencies{}, err
	}
	client := newGitHubClient(defaultDuration(cfg.GitHubHTTPTimeout, 30*time.Second))
	streamTimeout := defaultDuration(cfg.GitHubStreamTimeout, 10*time.Minute)
	gitClient := cloneGitHubClient(client, streamTimeout)
	userStore, err := githubauth.OpenUserCredentialStore(stateDir(cfg.StateDir))
	if err != nil {
		return githubDependencies{}, err
	}
	lifecycle, err := credentiallifecycle.New(auditWriter, "gh-broker", "broker")
	if err != nil {
		return githubDependencies{}, err
	}
	manager, err := githubauth.New(githubauth.Config{
		AppID: cfg.GitHubAppID, AppPrivateKey: cfg.GitHubAppPrivateKey, AppClientID: cfg.GitHubAppClientID,
		AppClientSecret: []byte(cfg.GitHubAppClientSecret), DevelopmentToken: []byte(cfg.GitHubToken),
		DevelopmentTokenFile: cfg.GitHubTokenFile, APIBaseURL: apiBaseURL, WebBaseURL: gitBaseURL,
		HTTPClient: client, StreamTimeout: streamTimeout, Store: userStore, Lifecycle: lifecycle,
	})
	if err != nil {
		return githubDependencies{}, err
	}
	outputStore, err := credentialstore.OpenNamespace(stateDir(cfg.StateDir), "github-operation-outputs")
	if err != nil {
		return githubDependencies{}, err
	}
	return githubDependencies{
		gitBaseURL: gitBaseURL, apiBaseURL: apiBaseURL, client: client, gitClient: gitClient,
		appSource: manager, credentialStore: outputStore, webhookSecret: cfg.GitHubWebhookSecret,
		receivePackLimit: defaultInt64(cfg.MaxReceivePackBytes, 25*1024*1024),
	}, nil
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
		Broker: "gh-broker", ApprovalBroker: "GitHub", Store: grantStore,
		ClientSecrets: map[string]string{cfg.ClientID: cfg.SharedSecret}, OperatorSecrets: operatorSecrets,
		Presenter: approval.Presenter{}, ActivationValidator: planValidator, Audit: auditWriter, State: grantStore.Database(),
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
	protected.POST("/api/grants", s.createGrant)
	protected.GET("/api/grants", s.listGrants)
	protected.GET("/api/grants/:id", s.getGrant)
	protected.GET("/:owner/:repoGit/info/refs", s.gitInfoRefs)
	protected.POST("/:owner/:repoGit/git-upload-pack", s.gitUploadPack)
	protected.POST("/:owner/:repoGit/git-receive-pack", s.gitReceivePack)
	protected.POST("/:owner/:repoGit/info/lfs/objects/batch", s.gitLFSBatch)
	protected.GET("/:owner/:repoGit/info/lfs/objects/:oid", s.gitLFSAction)
	protected.HEAD("/:owner/:repoGit/info/lfs/objects/:oid", s.gitLFSAction)
	protected.PUT("/:owner/:repoGit/info/lfs/objects/:oid/:size", s.gitLFSAction)
	protected.PATCH("/:owner/:repoGit/info/lfs/objects/:oid/:size", s.gitLFSAction)
	protected.POST("/:owner/:repoGit/info/lfs/objects/:oid/verify", s.gitLFSAction)
	protected.GET("/:owner/:repoGit/info/lfs/locks", s.gitLFSDirect)
	protected.POST("/:owner/:repoGit/info/lfs/locks", s.gitLFSDirect)
	protected.POST("/:owner/:repoGit/info/lfs/locks/verify", s.gitLFSDirect)
	protected.POST("/:owner/:repoGit/info/lfs/locks/:lockID/unlock", s.gitLFSDirect)
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

func cloneGitHubClient(client *http.Client, timeout time.Duration) *http.Client {
	clone := *client
	clone.Timeout = timeout
	return &clone
}

func stopGitHubRedirect(_ *http.Request, _ []*http.Request) error {
	return http.ErrUseLastResponse
}

func (s *Server) Handler() http.Handler {
	return s.echo
}

// GitHandler exposes only GitHub smart-HTTP routes on the dedicated listener.
func (s *Server) GitHandler() (http.Handler, error) {
	return gitserver.New("github", s.control.Clients, s.echo, githubGitRoute, nil)
}

func githubGitRoute(method, requestPath string) bool {
	parts := strings.Split(strings.TrimPrefix(requestPath, "/"), "/")
	if len(parts) < 3 || parts[0] == "" || parts[1] == "" {
		return false
	}
	tail := strings.Join(parts[2:], "/")
	switch tail {
	case "info/refs":
		return method == http.MethodGet
	case "git-upload-pack", "git-receive-pack":
		return method == http.MethodPost
	}
	if !strings.HasPrefix(tail, "info/lfs/") {
		return false
	}
	switch method {
	case http.MethodGet, http.MethodHead, http.MethodPost, http.MethodPut, http.MethodPatch:
		return true
	default:
		return false
	}
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
	body, request, err := s.readReceivePackBody(c)
	if err != nil {
		return err
	}
	if len(request.Commands) == 0 {
		c.Request().Body = io.NopCloser(bytes.NewReader(body))
		c.Request().ContentLength = int64(len(body))
		return s.authorizeBrokerRequest(c, s.repoRequest(c, policy.OperationGitPushAdvertise, nil), s.proxyGit)
	}
	authorized, approval, err := s.authorizeReceivePackCommands(c, body, request.Commands, request.Pack)
	if err != nil {
		return err
	}
	if approval != nil {
		return writeReceivePackApprovalRequired(c, request.Protocol, *approval)
	}
	return s.proxyAuthorizedReceivePack(c, body, authorized)
}

func (s *Server) readReceivePackBody(c echo.Context) ([]byte, receivePackRequest, error) {
	body, err := httpx.ReadLimited(c.Request().Body, s.maxReceivePackBytes)
	if err != nil {
		return nil, receivePackRequest{}, echo.NewHTTPError(http.StatusRequestEntityTooLarge, "git receive-pack request is too large")
	}
	request, err := receivePackRequestFromBody(body)
	if err != nil {
		return nil, receivePackRequest{}, echo.NewHTTPError(http.StatusBadRequest, "parse git receive-pack request")
	}
	return body, request, nil
}

func (s *Server) authorizeReceivePackCommands(c echo.Context, body []byte, commands []receivePackCommand, pack []byte) ([]authorizedReceivePackRequest, *receivePackApproval, error) {
	authorized := make([]authorizedReceivePackRequest, 0, len(commands))
	requestable := make([]requestableReceivePackRequest, 0, len(commands))
	for _, command := range commands {
		operation, err := s.classifyReceivePackCommand(c, command, pack)
		if err != nil {
			return nil, nil, err
		}
		request := s.repoRequest(c, operation, map[string]string{"ref": command.Ref})
		decision, approvalDecision, err := s.evaluateGitMutation(request)
		if err != nil {
			return nil, nil, err
		}
		if !decision.Allowed {
			if approvalDecision.Effect == policy.EffectRequest && approvalDecision.GrantPolicy != nil {
				requestable = append(requestable, requestableReceivePackRequest{Request: request, Decision: approvalDecision})
				authorized = append(authorized, authorizedReceivePackRequest{Request: request})
				continue
			}
			s.audit(c, request, outcomeForDecision(decision), decision.Reason, 0, decision.MatchedRuleIDs)
			return nil, nil, echo.NewHTTPError(statusForDecision(decision), decision.Reason)
		}
		authorized = append(authorized, authorizedReceivePackRequest{Request: request, Decision: decision})
	}
	if len(requestable) > 0 {
		return s.authorizeReceivePackTransaction(c, body, commands, authorized, requestable)
	}
	return authorized, nil, nil
}

func (s *Server) proxyAuthorizedReceivePack(c echo.Context, body []byte, authorized []authorizedReceivePackRequest) error {
	reserved, err := s.reserveAuthorizedGrants(authorized)
	if err != nil {
		s.releaseGrantUses(reserved)
		return echo.NewHTTPError(http.StatusConflict, "grant is no longer active")
	}
	c.Set(githubOperationContextKey, string(authorized[0].Request.Operation))
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
		for _, key := range []string{"owner", "repo", "repoGit", "oid", "size", "lockID"} {
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

func (s *Server) classifyReceivePackCommand(c echo.Context, command receivePackCommand, pack []byte) (policy.Operation, error) {
	switch {
	case isZeroOID(command.NewOID):
		return policy.OperationGitRefDelete, nil
	case strings.HasPrefix(command.Ref, "refs/tags/"):
		return policy.OperationGitTagUpdate, nil
	case !strings.HasPrefix(command.Ref, "refs/heads/"):
		return "", echo.NewHTTPError(http.StatusForbidden, "unsupported git ref update")
	case isZeroOID(command.OldOID):
		return policy.OperationGitPushBranchCreate, nil
	case receivePackProvesFastForward(c.Request().Context(), command.OldOID, command.NewOID, pack, s.maxReceivePackBytes):
		return policy.OperationGitPushFastForward, nil
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

func copyUpstreamResponse(c echo.Context, response *http.Response) error {
	c.Response().WriteHeader(response.StatusCode)
	_, err := io.Copy(c.Response(), response.Body)
	return err
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
	return strings.TrimPrefix(owner+"/"+repo, "/")
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
