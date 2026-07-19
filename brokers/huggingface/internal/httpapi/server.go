// Package httpapi exposes the broker HTTP surface.
package httpapi

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/labstack/echo/v4"
	"github.com/osolmaz/brokerkit/admission"
	"github.com/osolmaz/brokerkit/agentapi"
	"github.com/osolmaz/brokerkit/agentops"
	bkapprovalnotify "github.com/osolmaz/brokerkit/approvalnotify"
	"github.com/osolmaz/brokerkit/audit"
	bkauth "github.com/osolmaz/brokerkit/auth"
	bkauthorization "github.com/osolmaz/brokerkit/authorization"
	"github.com/osolmaz/brokerkit/brokers/huggingface/internal/approval"
	"github.com/osolmaz/brokerkit/brokers/huggingface/internal/config"
	"github.com/osolmaz/brokerkit/brokers/huggingface/internal/credentialauth"
	"github.com/osolmaz/brokerkit/brokers/huggingface/internal/hfgrant"
	"github.com/osolmaz/brokerkit/brokers/huggingface/internal/hfplan"
	"github.com/osolmaz/brokerkit/brokers/huggingface/internal/hubclient"
	"github.com/osolmaz/brokerkit/brokers/huggingface/internal/mirror"
	"github.com/osolmaz/brokerkit/brokers/huggingface/internal/opcatalog"
	"github.com/osolmaz/brokerkit/brokers/huggingface/internal/operations"
	"github.com/osolmaz/brokerkit/brokers/huggingface/internal/policy"
	"github.com/osolmaz/brokerkit/controlplane"
	"github.com/osolmaz/brokerkit/credentialstore"
	"github.com/osolmaz/brokerkit/gitserver"
	"github.com/osolmaz/brokerkit/grants"
	"github.com/osolmaz/brokerkit/internal/slicex"
	bknotify "github.com/osolmaz/brokerkit/notify"
	bktelegram "github.com/osolmaz/brokerkit/notify/telegram"
	"github.com/osolmaz/brokerkit/operatorapi"
	corepolicy "github.com/osolmaz/brokerkit/policy"
	"github.com/osolmaz/brokerkit/providercredential"
	"github.com/osolmaz/brokerkit/sealedpayload"
	"github.com/osolmaz/brokerkit/sealedstore"
	"github.com/osolmaz/brokerkit/state"
)

const (
	lfsActionQuery = "hf_broker_lfs_action"
	lfsActionTTL   = time.Hour
)

const (
	grantNotificationClaimLease = 2 * time.Minute
	grantNotificationClaimWait  = 10 * time.Second
	grantNotificationClaimPoll  = 50 * time.Millisecond
	grantReservationGrace       = 30 * time.Second
)

const maxLFSBatchBytes = 1 << 20
const maxReceivePackReportBytes = 4 << 20

var (
	errInvalidLFSAction             = errors.New("LFS action is no longer valid")
	errGrantStoreUnavailable        = errors.New("grant store unavailable")
	errGrantNotificationStillQueued = errors.New("grant notification is still being created")
	errGrantNotificationCanceled    = errors.New("grant notification was canceled")
	errGrantNotificationUnresolved  = errors.New("grant notification delivery is unresolved")
)

// Options configures a broker HTTP server.
type Options struct {
	Config                config.Config
	Scope                 policy.Policy
	Audit                 audit.Recorder
	UpstreamBaseURL       string
	UpstreamRouterBaseURL string
	Context               context.Context
	GrantNotifier         bkapprovalnotify.Notifier
	TelegramBaseURL       string
	OperatorAudit         operatorapi.AuditRecorder
	Now                   func() time.Time
	NewLFSActionID        func() (string, error)
	Credential            *providercredential.Service
}

// Server is an Echo-backed http.Handler for the broker.
type Server struct {
	router *echo.Echo

	control             *controlplane.Runtime
	authorization       *bkauthorization.Coordinator
	policy              policy.Policy
	audit               audit.Recorder
	mirrors             *mirror.Manager
	upstream            *url.URL
	routerUpstream      *url.URL
	httpClient          *http.Client
	inferenceHTTPClient *http.Client
	hfToken             string
	maxBody             int64
	grants              *grants.Store
	plans               *hfplan.Store
	operations          *agentops.Store
	admission           *admission.Controller
	operationRegistry   *operations.Registry
	operationRuntime    *operations.Runtime
	hubClient           *hubclient.Client
	sealedStore         *sealedstore.Store
	sealedPayloads      *sealedpayload.Service
	credentialStore     *credentialstore.Store
	agentAPI            *agentapi.Handler
	database            *state.Database
	planValidator       hfplan.Validator
	credential          *providercredential.Service
	notifier            bkapprovalnotify.Notifier
	operatorConfigured  bool
	lifecycleContext    context.Context
	lifecycleCancel     context.CancelFunc
	backgroundWorkers   sync.WaitGroup
	closeOnce           sync.Once
	closeErr            error
	now                 func() time.Time
	newLFSActionID      func() (string, error)

	lfsMu      sync.Mutex
	lfsActions map[string]lfsAction
}

type route struct {
	repoType policy.RepoType
	owner    string
	name     string
	tail     string
}

type classifiedRequest struct {
	route     route
	operation policy.Operation
	attrs     map[string]any
	body      []byte
	bodyRead  bool
}

type lfsAction struct {
	url     string
	headers http.Header
	route   route
	client  string
	created time.Time
}

type grantUse struct {
	grant grants.Grant
	ref   string
}

type lockedPushResult struct {
	upstreamStatus         int
	grantsToNotify         []grants.Grant
	retainedGrantsToNotify []grants.Grant
}

// New builds a broker HTTP handler.
func New(opts Options) (*Server, error) {
	if opts.Now == nil {
		opts.Now = time.Now
	}
	if opts.NewLFSActionID == nil {
		opts.NewLFSActionID = randomLFSActionID
	}
	server, ctx, err := prepareServer(opts)
	if err != nil {
		return nil, err
	}
	return startServer(ctx, server, opts)
}

func prepareServer(opts Options) (*Server, context.Context, error) {
	ctx := opts.Context
	if ctx == nil {
		ctx = context.Background()
	}
	upstream, err := parseUpstreamBase(opts.UpstreamBaseURL)
	if err != nil {
		return nil, nil, err
	}
	routerUpstream, err := parseRouterUpstreamBase(opts.UpstreamRouterBaseURL)
	if err != nil {
		return nil, nil, err
	}
	clients := configClients(opts.Config.Clients)
	auditLogger, err := prepareAuditRecorders(&opts)
	if err != nil {
		return nil, nil, errors.New("audit recorder is required")
	}
	server, err := newServer(opts, upstream, routerUpstream, clients, auditLogger)
	if err != nil {
		return nil, nil, err
	}
	return server, ctx, nil
}

func configClients(configured []config.Client) map[string]string {
	clients := map[string]string{}
	for _, client := range configured {
		clients[client.Name] = client.Secret
	}
	return clients
}

func prepareAuditRecorders(opts *Options) (audit.Recorder, error) {
	if opts.Audit == nil {
		return nil, errors.New("audit recorder is required")
	}
	if opts.OperatorAudit == nil {
		opts.OperatorAudit = opts.Audit
	}
	return opts.Audit, nil
}

func startServer(ctx context.Context, server *Server, opts Options) (*Server, error) {
	lifecycleContext, cancel := context.WithCancel(ctx)
	server.lifecycleContext = lifecycleContext
	server.lifecycleCancel = cancel
	if err := server.startTelegram(lifecycleContext, opts); err != nil {
		cancel()
		_ = server.database.Close()
		return nil, err
	}
	server.startGrantNotificationSweeper(lifecycleContext)
	server.sealedPayloads.Start(lifecycleContext)
	server.operationRuntime.Start(lifecycleContext)
	go func() {
		<-lifecycleContext.Done()
		_ = server.database.Close()
	}()
	return server, nil
}

// OperatorHandler builds the shared inbox over the same canonical grant store.
func (s *Server) OperatorHandler() http.Handler { return s.control.OperatorHandler }

// GitHandler exposes only Hugging Face smart-HTTP and LFS routes.
func (s *Server) GitHandler() (http.Handler, error) {
	return gitserver.New("huggingface", s.control.Clients, s.router, huggingFaceGitRoute, huggingFaceDelegatesAuthentication)
}

func huggingFaceDelegatesAuthentication(request *http.Request) bool {
	return request.Header.Get("Authorization") == "" && request.URL.Query().Get(lfsActionQuery) != ""
}

func huggingFaceGitRoute(method, requestPath string) bool {
	route, ok := parseRepoRoute(requestPath)
	if !ok {
		return false
	}
	switch route.tail {
	case "info/refs":
		return method == http.MethodGet
	case "git-upload-pack", "git-receive-pack":
		return method == http.MethodPost
	}
	if !strings.HasPrefix(route.tail, "info/lfs/") {
		return false
	}
	switch method {
	case http.MethodGet, http.MethodHead, http.MethodPost, http.MethodPut, http.MethodPatch:
		return true
	default:
		return false
	}
}

func (s *Server) utcNow() time.Time {
	if s.now == nil {
		return time.Now().UTC()
	}
	return s.now().UTC()
}

func (s *Server) nextLFSActionID() (string, error) {
	if s.newLFSActionID == nil {
		return randomLFSActionID()
	}
	return s.newLFSActionID()
}

// Close releases the broker state lease and database resources.
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

func namedSecrets(identities []config.Client) map[string]string {
	secrets := make(map[string]string, len(identities))
	for _, identity := range identities {
		secrets[identity.Name] = identity.Secret
	}
	return secrets
}

func parseUpstreamBase(upstreamBase string) (*url.URL, error) {
	return parseUpstreamOrigin(upstreamBase, config.DefaultUpstreamHubURL, "Hub")
}

func parseRouterUpstreamBase(upstreamBase string) (*url.URL, error) {
	return parseUpstreamOrigin(upstreamBase, config.DefaultUpstreamRouterURL, "Router")
}

func parseUpstreamOrigin(value, fallback, name string) (*url.URL, error) {
	if value == "" {
		value = fallback
	}
	upstream, err := url.Parse(value)
	if err != nil || !validUpstreamOrigin(upstream) {
		return nil, fmt.Errorf("invalid upstream %s URL", name)
	}
	upstream.Path = ""
	return upstream, nil
}

func validUpstreamOrigin(upstream *url.URL) bool {
	if upstream.Scheme != "http" && upstream.Scheme != "https" {
		return false
	}
	if upstream.Host == "" || upstream.User != nil {
		return false
	}
	if upstream.RawQuery != "" || upstream.Fragment != "" {
		return false
	}
	return upstream.Path == "" || upstream.Path == "/"
}

func newServer(opts Options, upstream, routerUpstream *url.URL, clients map[string]string, auditLogger audit.Recorder) (*Server, error) {
	resources, err := newServerResources(opts, upstream, clients)
	if err != nil {
		return nil, err
	}
	server := resources.newServer(opts, upstream, routerUpstream, auditLogger)
	if err := server.attachServices(opts, resources); err != nil {
		_ = resources.database.Close()
		return nil, err
	}
	server.router = newRouter(server)
	return server, nil
}

type serverResources struct {
	inferenceTimeout    time.Duration
	inferenceTransport  *http.Transport
	database            *state.Database
	sealedPayloadStore  *sealedstore.Store
	credentialSlots     *credentialstore.Store
	grantStore          *grants.Store
	plans               *hfplan.Store
	planValidator       hfplan.Validator
	hub                 *hubclient.Client
	operationRegistry   *operations.Registry
	control             *controlplane.Runtime
	operationStore      *agentops.Store
	admissionController *admission.Controller
}

func newServerResources(opts Options, upstream *url.URL, clients map[string]string) (*serverResources, error) {
	resources := &serverResources{}
	resources.inferenceTimeout, resources.inferenceTransport = inferenceTransport(opts.Config.HFTimeout)
	database, err := state.Open(context.Background(), opts.Config.StateDir, state.Options{})
	if err != nil {
		return nil, err
	}
	resources.database = database
	if err := resources.configureStores(opts); err != nil {
		_ = database.Close()
		return nil, err
	}
	if err := resources.configureOperations(opts, upstream, clients); err != nil {
		_ = database.Close()
		return nil, err
	}
	return resources, nil
}

func inferenceTransport(timeout time.Duration) (time.Duration, *http.Transport) {
	if timeout <= 0 {
		timeout = config.DefaultHFTimeout
	}
	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.DialContext = (&net.Dialer{
		Timeout:   min(timeout, 10*time.Second),
		KeepAlive: 30 * time.Second,
	}).DialContext
	transport.ResponseHeaderTimeout = min(timeout, 30*time.Second)
	transport.TLSHandshakeTimeout = min(timeout, 10*time.Second)
	return timeout, transport
}

func (r *serverResources) configureStores(opts Options) error {
	var err error
	r.sealedPayloadStore, err = sealedstore.Open(opts.Config.StateDir)
	if err != nil {
		return err
	}
	r.credentialSlots, err = credentialstore.Open(opts.Config.StateDir)
	if err != nil {
		return err
	}
	r.grantStore = grants.NewDatabase(r.database, grants.Options{
		PendingTimeout: hfgrant.DefaultPendingTimeout, DefaultDuration: hfgrant.DefaultDuration,
		MaxDuration: hfgrant.MaxDuration, ReservationTimeout: grantReservationTimeout(opts.Config.HFTimeout),
		Now: opts.Now,
	})
	r.plans, err = hfplan.NewStoreWithClock(r.database, opts.Now)
	r.plans.SetCredentialService(opts.Credential)
	r.planValidator = hfplan.Validator{Store: r.plans, Credential: opts.Credential, Requirement: (credentialauth.Adapter{}).Requirement}
	return err
}

func (r *serverResources) configureOperations(opts Options, upstream *url.URL, clients map[string]string) error {
	var err error
	r.hub, err = hubclient.New(upstream.String(), opts.Config.HFToken, hubclient.WithTimeout(opts.Config.HFTimeout))
	if err != nil {
		return err
	}
	authorize := func(client string, operation policy.Operation, target policy.Target, authority *grants.Grant) bool {
		return policyAllowsRepositoryResult(client, opts.Scope, target, operation, authority, r.planValidator, opts.Now())
	}
	r.operationRegistry, err = newOperationRegistry(r.hub, upstream.String(), r.sealedPayloadStore, r.credentialSlots, authorize)
	if err != nil {
		return err
	}
	r.control, err = controlplane.New(controlplane.Options{
		Broker: "hf-broker", ApprovalBroker: "Hugging Face", Store: r.grantStore, ClientSecrets: clients,
		OperatorSecrets: namedSecrets(opts.Config.Operators), Presenter: approval.Presenter{}, Audit: opts.OperatorAudit,
		ActivationValidator: r.planValidator, State: r.database,
	})
	if err != nil {
		return err
	}
	r.operationStore = agentops.New(r.database)
	r.admissionController, err = admission.NewConfigured(slicex.Keys(clients), opts.Config.Admission, r.operationStore.AdmissionUsage)
	if err != nil {
		return err
	}
	r.admissionController.SetObserver(r.control.Metrics)
	return nil
}

func newOperationRegistry(hub *hubclient.Client, upstream string, sealed *sealedstore.Store, credentialSlots *credentialstore.Store, authorize operations.RepositoryAuthorization) (*operations.Registry, error) {
	providerAdapters, err := providerAdapters(hub, upstream, sealed, credentialSlots, authorize)
	if err != nil {
		return nil, err
	}
	registry, err := operations.NewRegistry(providerAdapters...)
	if err != nil {
		return nil, err
	}
	if err := registry.ValidateCoverage(); err != nil {
		return nil, err
	}
	return registry, nil
}

func providerAdapters(hub *hubclient.Client, upstream string, sealed *sealedstore.Store, credentialSlots *credentialstore.Store, authorize operations.RepositoryAuthorization) ([]operations.Adapter, error) {
	factories := []func() ([]operations.Adapter, error){
		func() ([]operations.Adapter, error) { return operations.NewRepositoryReadAdapters(hub, authorize) },
		func() ([]operations.Adapter, error) { return operations.NewRepositoryAdapters(hub, upstream) },
		func() ([]operations.Adapter, error) { return operations.NewRepositorySettingsAdapters(hub) },
		func() ([]operations.Adapter, error) { return operations.NewRefsAdapters(hub) },
		func() ([]operations.Adapter, error) { return operations.NewSpaceAdapters(hub) },
		func() ([]operations.Adapter, error) { return operations.NewBoundAdapters(hub) },
		func() ([]operations.Adapter, error) { return operations.NewBucketAdapters(hub) },
		func() ([]operations.Adapter, error) { return operations.NewRepositoryContentAdapters(hub) },
		func() ([]operations.Adapter, error) { return operations.NewSealedBoundAdapters(hub, sealed) },
		func() ([]operations.Adapter, error) {
			return operations.NewCredentialOutputAdapters(hub, sealed, credentialSlots)
		},
		func() ([]operations.Adapter, error) { return operations.NewSandboxAdapters(hub, sealed) },
	}
	var adapters []operations.Adapter
	for _, factory := range factories {
		next, err := factory()
		if err != nil {
			return nil, err
		}
		adapters = append(adapters, next...)
	}
	return adapters, nil
}

func (r *serverResources) newServer(opts Options, upstream, routerUpstream *url.URL, auditLogger audit.Recorder) *Server {
	return &Server{
		control:        r.control,
		policy:         opts.Scope,
		audit:          auditLogger,
		mirrors:        mirror.New(opts.Config.StateDir, opts.Config.HFToken, opts.Config.HFTimeout),
		upstream:       upstream,
		routerUpstream: routerUpstream,
		httpClient:     &http.Client{Timeout: opts.Config.HFTimeout},
		inferenceHTTPClient: &http.Client{
			Transport: r.inferenceTransport,
			Timeout:   r.inferenceTimeout,
			CheckRedirect: func(*http.Request, []*http.Request) error {
				return errors.New("inference upstream redirect refused")
			},
		},
		hfToken:            opts.Config.HFToken,
		maxBody:            opts.Config.MaxPackBytes,
		grants:             r.grantStore,
		plans:              r.plans,
		operations:         r.operationStore,
		admission:          r.admissionController,
		operationRegistry:  r.operationRegistry,
		hubClient:          r.hub,
		sealedStore:        r.sealedPayloadStore,
		credentialStore:    r.credentialSlots,
		database:           r.database,
		planValidator:      r.planValidator,
		credential:         opts.Credential,
		notifier:           opts.GrantNotifier,
		operatorConfigured: len(opts.Config.Operators) > 0,
		lfsActions:         map[string]lfsAction{},
		now:                opts.Now,
		newLFSActionID:     opts.NewLFSActionID,
	}
}

func (s *Server) attachServices(opts Options, resources *serverResources) error {
	sealedPayloadService, sealedPayloadErr := sealedpayload.New(sealedpayload.Options{
		Store: resources.sealedPayloadStore, Descriptor: opcatalog.ByName, Authenticate: s.authenticateAPI,
		WriteFailure: func(response http.ResponseWriter, status int, reason, message string) {
			writeJSendFail(response, status, reason, message)
		},
		Now: opts.Now,
	})
	s.sealedPayloads = sealedPayloadService
	authorization, authorizationErr := bkauthorization.New(bkauthorization.Options{
		Registry: policy.AuthorizationRegistry(), Decide: s.policy.DecideAuthorization,
		Grants: resources.grantStore, ActiveGrants: s.activeAuthorizationGrants, Now: opts.Now,
	})
	s.authorization = authorization
	operationRuntime, operationRuntimeErr := s.newOperationRuntime()
	s.operationRuntime = operationRuntime
	agentAPI, agentAPIErr := agentapi.New(agentapi.Options{
		Store: s.operations, Authenticate: resources.control.Clients.AuthenticateHeader,
		Submit: s.submitAgentOperation, Cancel: s.cancelAgentOperation, Realm: "hf-broker",
		Discover: s.discoverAgent,
		AuthFailure: func() {
			s.record("system", "agent.authenticate", "", audit.DecisionRefused, "authentication failed", 0)
		},
	})
	if err := errors.Join(sealedPayloadErr, authorizationErr, operationRuntimeErr, agentAPIErr); err != nil {
		return err
	}
	s.agentAPI = agentAPI
	return nil
}

func (s *Server) activeAuthorizationGrants(request corepolicy.Request) ([]corepolicy.Grant, error) {
	rules, err := s.activeGrantRules(request.Client)
	if err != nil {
		return nil, err
	}
	return policy.AuthorizationGrants(rules), nil
}

func newRouter(server *Server) *echo.Echo {
	router := echo.New()
	router.HideBanner = true
	router.HidePort = true
	server.agentAPI.Register(router)
	router.POST("/api/agent/v1/sealed-payloads", server.uploadSealedPayload)
	router.GET("/healthz", func(c echo.Context) error {
		c.Response().Header().Set("Content-Type", "application/json")
		if server.credential != nil {
			snapshot, err := server.credential.Snapshot()
			if err != nil || snapshot.VerificationState != providercredential.VerificationValid || snapshot.ExpiresAt != nil && !snapshot.ExpiresAt.After(server.utcNow()) {
				return c.JSON(http.StatusServiceUnavailable, map[string]bool{"ok": false})
			}
		}
		_, err := c.Response().Write([]byte(`{"ok": true}`))
		return err
	})
	dispatch := func(c echo.Context) error {
		server.serveHTTP(c.Response(), c.Request())
		return nil
	}
	router.POST("/api/grants", dispatch)
	router.GET("/api/grants", dispatch)
	router.GET("/api/grants/:id", dispatch)
	router.GET("/api/repos", dispatch)
	router.Any("/*", dispatch)
	return router
}

func grantReservationTimeout(hfTimeout time.Duration) time.Duration {
	if hfTimeout <= 0 {
		return hfgrant.DefaultReservationTimeout
	}
	return hfTimeout + grantReservationGrace
}

func (s *Server) startTelegram(_ context.Context, opts Options) error {
	if opts.Config.TelegramBotToken == "" {
		return nil
	}
	telegram, err := bktelegram.NewWithOptions(opts.Config.TelegramBotToken, opts.Config.TelegramChatID, nil, opts.TelegramBaseURL, bktelegram.Options{
		Route: bktelegram.RouteHuggingFace,
	})
	if err != nil {
		return fmt.Errorf("configure Telegram notifier: %w", err)
	}
	s.notifier = telegram
	return nil
}

func (s *Server) handleTelegramDecision(ctx context.Context, decision bknotify.Decision) bknotify.DecisionResult {
	return s.control.HandleDecision(ctx, decision)
}

func writeHealth(w http.ResponseWriter, r *http.Request) bool {
	if r.Method != http.MethodGet || r.URL.Path != "/healthz" {
		return false
	}
	w.Header().Set("Content-Type", "application/json")
	_, _ = w.Write([]byte(`{"ok": true}`))
	return true
}

func isAPIPath(path string) bool {
	return path == "/api" || strings.HasPrefix(path, "/api/")
}

func (s *Server) authenticate(w http.ResponseWriter, r *http.Request) (string, bool) {
	client, err := s.control.Clients.AuthenticateHeader(r.Header.Get("Authorization"))
	if err == nil {
		return client, true
	}
	if errors.Is(err, bkauth.ErrMissing) {
		if client, handled := s.authenticateLFSAction(w, r); handled {
			return client, client != ""
		}
	}
	status := http.StatusForbidden
	if errors.Is(err, bkauth.ErrMissing) {
		status = http.StatusUnauthorized
		w.Header().Set("WWW-Authenticate", `Basic realm="hf-broker"`)
	}
	writePlain(w, status, "hf-broker: authentication failed\n")
	s.recordAudit(audit.Event{Operation: "unknown", Decision: audit.DecisionRefused, Reason: "authentication failed"})
	return "", false
}

func (s *Server) authenticateLFSAction(w http.ResponseWriter, r *http.Request) (string, bool) {
	actionID := r.URL.Query().Get(lfsActionQuery)
	if actionID == "" {
		return "", false
	}
	action, ok := s.lookupLFSAction(actionID)
	rt, routeOK := parseRepoRoute(r.URL.Path)
	if !ok || !routeOK || !sameRoute(action.route, rt) || action.client == "" {
		writePlain(w, http.StatusForbidden, "hf-broker: "+errInvalidLFSAction.Error()+"\n")
		s.recordAudit(audit.Event{Operation: "unknown", Decision: audit.DecisionRefused, Reason: errInvalidLFSAction.Error()})
		return "", true
	}
	return action.client, true
}

func (s *Server) authenticateAPI(w http.ResponseWriter, r *http.Request) (string, bool) {
	client, err := s.control.Clients.AuthenticateHeader(r.Header.Get("Authorization"))
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
		w.Header().Set("WWW-Authenticate", `Basic realm="hf-broker"`)
	}
	writeJSendFail(w, status, reason, message)
	s.recordAudit(audit.Event{Operation: "api", Decision: audit.DecisionRefused, Reason: "authentication failed"})
	return "", false
}
