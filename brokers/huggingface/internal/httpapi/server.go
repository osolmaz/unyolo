// Package httpapi exposes the broker HTTP surface.
package httpapi

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/labstack/echo/v4"
	"github.com/osolmaz/brokerkit/agentapi"
	"github.com/osolmaz/brokerkit/agentops"
	"github.com/osolmaz/brokerkit/audit"
	bkauth "github.com/osolmaz/brokerkit/auth"
	bkauthorization "github.com/osolmaz/brokerkit/authorization"
	"github.com/osolmaz/brokerkit/brokers/huggingface/internal/approval"
	"github.com/osolmaz/brokerkit/brokers/huggingface/internal/config"
	"github.com/osolmaz/brokerkit/brokers/huggingface/internal/hfgrant"
	"github.com/osolmaz/brokerkit/brokers/huggingface/internal/hfplan"
	"github.com/osolmaz/brokerkit/brokers/huggingface/internal/hubclient"
	"github.com/osolmaz/brokerkit/brokers/huggingface/internal/mirror"
	"github.com/osolmaz/brokerkit/brokers/huggingface/internal/operations"
	"github.com/osolmaz/brokerkit/brokers/huggingface/internal/policy"
	"github.com/osolmaz/brokerkit/brokers/huggingface/internal/sealedstore"
	"github.com/osolmaz/brokerkit/controlplane"
	"github.com/osolmaz/brokerkit/grants"
	bknotify "github.com/osolmaz/brokerkit/notify"
	bktelegram "github.com/osolmaz/brokerkit/notify/telegram"
	"github.com/osolmaz/brokerkit/operatorapi"
	corepolicy "github.com/osolmaz/brokerkit/policy"
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
	GrantNotifier         bknotify.Notifier
	TelegramBaseURL       string
	OperatorAudit         operatorapi.AuditRecorder
	Now                   func() time.Time
	NewLFSActionID        func() (string, error)
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
	operationRegistry   *operations.Registry
	hubClient           *hubclient.Client
	sealedStore         *sealedstore.Store
	agentAPI            *agentapi.Handler
	database            *state.Database
	planValidator       hfplan.Validator
	notifier            bknotify.Notifier
	operatorConfigured  bool
	lifecycleContext    context.Context
	lifecycleCancel     context.CancelFunc
	backgroundWorkers   sync.WaitGroup
	closeOnce           sync.Once
	closeErr            error
	operationAuthLocks  [64]sync.Mutex
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
	clients := map[string]string{}
	for _, client := range opts.Config.Clients {
		clients[client.Name] = client.Secret
	}
	auditLogger := opts.Audit
	if auditLogger == nil {
		auditLogger = audit.New(io.Discard)
	}
	server, err := newServer(opts, upstream, routerUpstream, clients, auditLogger)
	if err != nil {
		return nil, nil, err
	}
	return server, ctx, nil
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
	server.startOperationWorker(lifecycleContext)
	go func() {
		<-lifecycleContext.Done()
		_ = server.database.Close()
	}()
	return server, nil
}

// OperatorHandler builds the shared inbox over the same canonical grant store.
func (s *Server) OperatorHandler() http.Handler { return s.control.OperatorHandler }

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
	inferenceTimeout := opts.Config.HFTimeout
	if inferenceTimeout <= 0 {
		inferenceTimeout = config.DefaultHFTimeout
	}
	inferenceTransport := http.DefaultTransport.(*http.Transport).Clone()
	inferenceTransport.DialContext = (&net.Dialer{
		Timeout:   min(inferenceTimeout, 10*time.Second),
		KeepAlive: 30 * time.Second,
	}).DialContext
	inferenceTransport.ResponseHeaderTimeout = min(inferenceTimeout, 30*time.Second)
	inferenceTransport.TLSHandshakeTimeout = min(inferenceTimeout, 10*time.Second)
	database, err := state.Open(context.Background(), opts.Config.StateDir, state.Options{})
	if err != nil {
		return nil, err
	}
	sealedPayloads, err := sealedstore.Open(opts.Config.StateDir)
	if err != nil {
		_ = database.Close()
		return nil, err
	}
	store := grants.NewDatabase(database, grants.Options{
		PendingTimeout: hfgrant.DefaultPendingTimeout, DefaultDuration: hfgrant.DefaultDuration,
		MaxDuration: hfgrant.MaxDuration, ReservationTimeout: grantReservationTimeout(opts.Config.HFTimeout),
		Now: opts.Now,
	})
	plans, err := hfplan.NewStoreWithClock(database, opts.Now)
	if err != nil {
		_ = database.Close()
		return nil, err
	}
	planValidator := hfplan.Validator{Store: plans}
	hub, err := hubclient.New(upstream.String(), opts.Config.HFToken, hubclient.WithTimeout(opts.Config.HFTimeout))
	if err != nil {
		_ = database.Close()
		return nil, err
	}
	providerAdapters, err := operations.NewRepositoryAdapters(hub, upstream.String())
	if err != nil {
		_ = database.Close()
		return nil, err
	}
	settingsAdapters, err := operations.NewRepositorySettingsAdapters(hub)
	if err != nil {
		_ = database.Close()
		return nil, err
	}
	refsAdapters, err := operations.NewRefsAdapters(hub)
	if err != nil {
		_ = database.Close()
		return nil, err
	}
	spaceAdapters, err := operations.NewSpaceAdapters(hub)
	if err != nil {
		_ = database.Close()
		return nil, err
	}
	boundAdapters, err := operations.NewBoundAdapters(hub)
	if err != nil {
		_ = database.Close()
		return nil, err
	}
	bucketAdapters, err := operations.NewBucketAdapters(hub)
	if err != nil {
		_ = database.Close()
		return nil, err
	}
	contentAdapters, err := operations.NewRepositoryContentAdapters(hub)
	if err != nil {
		_ = database.Close()
		return nil, err
	}
	sealedAdapters, err := operations.NewSealedBoundAdapters(hub, sealedPayloads)
	if err != nil {
		_ = database.Close()
		return nil, err
	}
	providerAdapters = append(providerAdapters, settingsAdapters...)
	providerAdapters = append(providerAdapters, refsAdapters...)
	providerAdapters = append(providerAdapters, spaceAdapters...)
	providerAdapters = append(providerAdapters, boundAdapters...)
	providerAdapters = append(providerAdapters, bucketAdapters...)
	providerAdapters = append(providerAdapters, contentAdapters...)
	providerAdapters = append(providerAdapters, sealedAdapters...)
	operationRegistry, err := operations.NewRegistry(providerAdapters...)
	if err != nil {
		_ = database.Close()
		return nil, err
	}
	runtime, err := controlplane.New(controlplane.Options{
		Broker: "hf-broker", Store: store, ClientSecrets: clients,
		OperatorSecrets: namedSecrets(opts.Config.Operators), Presenter: approval.Presenter{}, Audit: opts.OperatorAudit,
		ActivationValidator: planValidator,
	})
	if err != nil {
		_ = database.Close()
		return nil, err
	}
	server := &Server{
		control:        runtime,
		policy:         opts.Scope,
		audit:          auditLogger,
		mirrors:        mirror.New(opts.Config.StateDir, opts.Config.HFToken, opts.Config.HFTimeout),
		upstream:       upstream,
		routerUpstream: routerUpstream,
		httpClient:     &http.Client{Timeout: opts.Config.HFTimeout},
		inferenceHTTPClient: &http.Client{
			Transport: inferenceTransport,
			Timeout:   inferenceTimeout,
			CheckRedirect: func(*http.Request, []*http.Request) error {
				return errors.New("inference upstream redirect refused")
			},
		},
		hfToken:            opts.Config.HFToken,
		maxBody:            opts.Config.MaxPackBytes,
		grants:             store,
		plans:              plans,
		operations:         agentops.New(database),
		operationRegistry:  operationRegistry,
		hubClient:          hub,
		sealedStore:        sealedPayloads,
		database:           database,
		planValidator:      planValidator,
		notifier:           opts.GrantNotifier,
		operatorConfigured: len(opts.Config.Operators) > 0,
		lfsActions:         map[string]lfsAction{},
		now:                opts.Now,
		newLFSActionID:     opts.NewLFSActionID,
	}
	authorization, authorizationErr := bkauthorization.New(bkauthorization.Options{
		Registry: policy.AuthorizationRegistry(), Decide: server.policy.DecideAuthorization,
		Grants: store, ActiveGrants: server.activeAuthorizationGrants, Now: opts.Now,
	})
	agentAPI, agentAPIErr := agentapi.New(agentapi.Options{
		Store: server.operations, Authenticate: runtime.Clients.AuthenticateHeader,
		Submit: server.submitAgentOperation, Realm: "hf-broker",
		AuthFailure: func() {
			server.record("system", "agent.authenticate", "", audit.DecisionRefused, "authentication failed", 0)
		},
	})
	if err := errors.Join(authorizationErr, agentAPIErr); err != nil {
		_ = database.Close()
		return nil, err
	}
	server.authorization = authorization
	server.agentAPI = agentAPI
	server.router = newRouter(server)
	return server, nil
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

func (s *Server) startTelegram(ctx context.Context, opts Options) error {
	if opts.Config.TelegramBotToken == "" {
		return nil
	}
	telegram, err := bktelegram.NewWithOptions(opts.Config.TelegramBotToken, opts.Config.TelegramChatID, nil, opts.TelegramBaseURL, bktelegram.Options{
		IgnoredAnswer: "Grant decision ignored",
		ApproveText:   "✅ Approve",
		DenyText:      "❌ Deny",
	})
	if err != nil {
		return fmt.Errorf("configure Telegram notifier: %w", err)
	}
	s.notifier = telegram
	go telegram.Poll(ctx, s.control.HandleDecision)
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
	status := http.StatusForbidden
	if errors.Is(err, bkauth.ErrMissing) {
		status = http.StatusUnauthorized
		w.Header().Set("WWW-Authenticate", `Basic realm="hf-broker"`)
	}
	writePlain(w, status, "hf-broker: authentication failed\n")
	s.recordAudit(audit.Event{Operation: "unknown", Decision: audit.DecisionRefused, Reason: "authentication failed"})
	return "", false
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
