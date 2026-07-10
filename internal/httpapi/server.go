// Package httpapi exposes the broker HTTP surface.
package httpapi

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/labstack/echo/v4"
	bknotify "github.com/osolmaz/brokerkit/notify"
	bktelegram "github.com/osolmaz/brokerkit/notify/telegram"
	"github.com/osolmaz/brokerkit/operatorapi"
	"github.com/osolmaz/brokerkit/operatorauth"
	"github.com/osolmaz/brokerkit/operatorinbox"
	"github.com/osolmaz/hf-broker/internal/approval"
	"github.com/osolmaz/hf-broker/internal/audit"
	"github.com/osolmaz/hf-broker/internal/auth"
	"github.com/osolmaz/hf-broker/internal/config"
	"github.com/osolmaz/hf-broker/internal/gitproxy"
	"github.com/osolmaz/hf-broker/internal/grants"
	"github.com/osolmaz/hf-broker/internal/jsend"
	"github.com/osolmaz/hf-broker/internal/mirror"
	"github.com/osolmaz/hf-broker/internal/policy"
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
	Audit                 *audit.Logger
	UpstreamBaseURL       string
	UpstreamRouterBaseURL string
	Context               context.Context
	GrantNotifier         bknotify.Notifier
	TelegramBaseURL       string
}

// Server is an Echo-backed http.Handler for the broker.
type Server struct {
	router *echo.Echo

	auth                *auth.Authenticator
	policy              policy.Policy
	audit               *audit.Logger
	mirrors             *mirror.Manager
	upstream            *url.URL
	routerUpstream      *url.URL
	httpClient          *http.Client
	inferenceHTTPClient *http.Client
	hfToken             string
	maxBody             int64
	grants              *grants.Store
	notifier            bknotify.Notifier
	operatorConfigured  bool

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
	ctx := opts.Context
	if ctx == nil {
		ctx = context.Background()
	}
	upstream, err := parseUpstreamBase(opts.UpstreamBaseURL)
	if err != nil {
		return nil, err
	}
	routerUpstream, err := parseRouterUpstreamBase(opts.UpstreamRouterBaseURL)
	if err != nil {
		return nil, err
	}
	clients := map[string]string{}
	for _, client := range opts.Config.Clients {
		clients[client.Name] = client.Secret
	}
	auditLogger := opts.Audit
	if auditLogger == nil {
		auditLogger = audit.New(io.Discard)
	}
	server := newServer(opts, upstream, routerUpstream, clients, auditLogger)
	if err := server.startTelegram(ctx, opts); err != nil {
		return nil, err
	}
	if opts.Config.TelegramBotToken != "" {
		server.startGrantNotificationSweeper(ctx)
	}
	return server, nil
}

// OperatorHandler builds the shared inbox over the same canonical grant store.
func (s *Server) OperatorHandler(cfg config.Config, recorder operatorapi.AuditRecorder) (http.Handler, error) {
	clientSecrets := namedSecrets(cfg.Clients)
	authenticator, err := operatorauth.New(namedSecrets(cfg.Operators), operatorauth.Options{ClientSecrets: clientSecrets})
	if err != nil {
		return nil, err
	}
	inbox, err := operatorinbox.New(s.grants.Core(), approval.Presenter{})
	if err != nil {
		return nil, err
	}
	return operatorapi.New(operatorapi.Options{
		Inbox: inbox, Authorize: authenticator.AuthenticateRequest, Broker: "hf-broker", Audit: recorder,
	})
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

func newServer(opts Options, upstream, routerUpstream *url.URL, clients map[string]string, auditLogger *audit.Logger) *Server {
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
	server := &Server{
		auth:           auth.New(clients),
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
		hfToken: opts.Config.HFToken,
		maxBody: opts.Config.MaxPackBytes,
		grants: grants.New(filepath.Join(opts.Config.StateDir, "grants", "grants.json"), grants.Options{
			ReservationTimeout: grantReservationTimeout(opts.Config.HFTimeout),
		}),
		notifier:           opts.GrantNotifier,
		operatorConfigured: len(opts.Config.Operators) > 0,
		lfsActions:         map[string]lfsAction{},
	}
	server.router = newRouter(server)
	return server
}

func newRouter(server *Server) *echo.Echo {
	router := echo.New()
	router.HideBanner = true
	router.HidePort = true
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
		return grants.DefaultReservationTimeout
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
	go telegram.Poll(ctx, s.handleTelegramDecision)
	return nil
}

func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if s.router != nil {
		s.router.ServeHTTP(w, r)
		return
	}
	s.serveHTTP(w, r)
}

// serveHTTP routes one broker request after Echo dispatch.
func (s *Server) serveHTTP(w http.ResponseWriter, r *http.Request) {
	if writeHealth(w, r) {
		return
	}
	if isAPIPath(r.URL.Path) {
		s.serveAPI(w, r)
		return
	}
	client, ok := s.authenticate(w, r)
	if !ok {
		return
	}
	if isInferencePath(r.URL.Path) {
		s.serveInference(w, r, client)
		return
	}
	if strings.HasPrefix(r.URL.Path, "/v1/") {
		writeInferenceError(w, http.StatusNotFound, "unsupported_inference_route")
		s.record(client, "inference.unknown", "", audit.DecisionRefused, "unsupported_inference_route", 0)
		return
	}
	s.serveAuthenticated(w, r, client)
}

func (s *Server) serveAuthenticated(w http.ResponseWriter, r *http.Request, client string) {
	classified, status, reason := s.classify(r)
	if reason != "" {
		writePlain(w, status, "hf-broker: "+reason+"\n")
		s.record(client, "unknown", "", audit.DecisionRefused, reason, 0)
		return
	}
	target := targetName(classified.route)
	if classified.operation == policy.OpGitPushAppend && r.Method == http.MethodPost && classified.route.tail == "git-receive-pack" {
		s.handleReceivePack(w, r, client, classified.route, target)
		return
	}
	if receivePackDiscoveryRequest(r, classified) {
		s.handleReceivePackDiscovery(w, r, client, classified, target)
		return
	}
	decision, err := s.decideForwardRepo(client, r, classified)
	if err != nil {
		s.writeGrantStoreError(w, client, string(classified.operation), target)
		return
	}
	if s.forwardAllowedDecision(w, r, client, classified, target, decision) {
		return
	}
	writePlain(w, http.StatusForbidden, "hf-broker: "+decision.Reason+"\n")
	s.recordPolicyDecision(client, string(classified.operation), target, audit.DecisionRefused, decision.Reason, 0, decision)
}

func (s *Server) forwardAllowedDecision(w http.ResponseWriter, r *http.Request, client string, classified classifiedRequest, target string, decision policy.Decision) bool {
	if decision.Effect != policy.EffectAllow {
		return false
	}
	if decision.Reason == "grant_allowed" {
		return s.handleForwardWithActiveGrant(w, r, client, classified, target, decision, consumeForwardGrantUse(r, classified))
	}
	s.handleForward(w, r, client, classified, target, decision)
	return true
}

func receivePackDiscoveryRequest(r *http.Request, classified classifiedRequest) bool {
	return gitServiceDiscoveryRequest(r, classified, policy.OpGitPushAppend, "git-receive-pack")
}

func uploadPackDiscoveryRequest(r *http.Request, classified classifiedRequest) bool {
	return gitServiceDiscoveryRequest(r, classified, policy.OpGitFetch, "git-upload-pack")
}

func consumeForwardGrantUse(r *http.Request, classified classifiedRequest) bool {
	return !uploadPackDiscoveryRequest(r, classified) &&
		!lfsBatchRequest(r, classified) &&
		!lfsUploadRequest(r, classified)
}

func lfsBatchRequest(r *http.Request, classified classifiedRequest) bool {
	return r.Method == http.MethodPost && classified.route.tail == "info/lfs/objects/batch"
}

func lfsUploadRequest(r *http.Request, classified classifiedRequest) bool {
	if classified.operation != policy.OpGitPushAppend {
		return false
	}
	if r.Method == http.MethodPost && classified.route.tail == "info/lfs/objects/batch" {
		return true
	}
	return isLFSObjectUpload(r.Method, classified.route.tail)
}

func gitServiceDiscoveryRequest(r *http.Request, classified classifiedRequest, operation policy.Operation, service string) bool {
	return r.Method == http.MethodGet &&
		classified.operation == operation &&
		classified.route.tail == "info/refs" &&
		r.URL.Query().Get("service") == service
}

func (s *Server) handleReceivePackDiscovery(w http.ResponseWriter, r *http.Request, client string, classified classifiedRequest, target string) {
	decision, err := s.decideReceivePackDiscovery(client, classified.route)
	if err != nil {
		s.writeGrantStoreError(w, client, string(classified.operation), target)
		return
	}
	if receivePackDiscoveryPermitted(decision) {
		s.handleForward(w, r, client, classified, target, decision)
		return
	}
	writePlain(w, http.StatusForbidden, "hf-broker: "+decision.Reason+"\n")
	s.recordPolicyDecision(client, string(classified.operation), target, audit.DecisionRefused, decision.Reason, 0, decision)
}

func receivePackDiscoveryPermitted(decision policy.Decision) bool {
	return decision.Effect == policy.EffectAllow
}

func (s *Server) decideReceivePackDiscovery(client string, rt route) (policy.Decision, error) {
	target := routeTarget(rt, nil)
	now := time.Now().UTC()
	activeGrants, err := s.activeGrantRules(client)
	if err != nil {
		return policy.Decision{}, err
	}
	var fallback policy.Decision
	for _, operation := range receivePackDiscoveryOperations() {
		decision := s.policy.DecideReceivePackDiscovery(policy.Request{
			Client:    client,
			Operation: operation,
			Target:    target,
		}, activeGrants, now)
		if receivePackDiscoveryPermitted(decision) {
			return decision, nil
		}
		fallback = receivePackDiscoveryFallback(fallback, decision)
	}
	if fallback.Reason == "" {
		return policy.Decision{Effect: policy.EffectNoMatch, Reason: "no_matching_rule"}, nil
	}
	return fallback, nil
}

func receivePackDiscoveryFallback(current, next policy.Decision) policy.Decision {
	if current.Reason == "" {
		return next
	}
	if next.Reason == "approval_required" {
		return next
	}
	if current.Reason == "approval_required" {
		return current
	}
	if current.Reason == "no_matching_rule" {
		return next
	}
	return current
}

func receivePackDiscoveryOperations() []policy.Operation {
	return []policy.Operation{
		policy.OpGitPushAppend,
		policy.OpGitPushForce,
		policy.OpGitRefDelete,
		policy.OpGitTagUpdate,
	}
}

func (s *Server) decideRepo(client string, operation policy.Operation, rt route, refs []string, attrs map[string]any, grantRequest bool) (policy.Decision, error) {
	return s.decideRepoWithOptions(client, operation, rt, refs, attrs, grantRequest, false)
}

func (s *Server) decideForwardRepo(client string, r *http.Request, classified classifiedRequest) (policy.Decision, error) {
	return s.decideRepoWithOptions(client, classified.operation, classified.route, nil, classified.attrs, false, lfsUploadRequest(r, classified))
}

func (s *Server) decideRepoWithOptions(client string, operation policy.Operation, rt route, refs []string, attrs map[string]any, grantRequest bool, ignoreRefs bool) (policy.Decision, error) {
	activeGrants, err := s.activeGrantRules(client)
	if err != nil {
		return policy.Decision{}, err
	}
	return s.policy.Decide(policy.Request{
		Client:         client,
		Operation:      operation,
		Target:         routeTarget(rt, refs),
		Attrs:          attrs,
		IgnoreRepoRefs: ignoreRefs,
	}, activeGrants, time.Now().UTC(), grantRequest), nil
}

func (s *Server) activeGrantRules(client string) ([]policy.Rule, error) {
	values, err := s.grants.ListForClient(client)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", errGrantStoreUnavailable, err)
	}
	out := make([]policy.Rule, 0, len(values))
	for _, grant := range values {
		rule, ok := activeGrantRule(grant)
		if ok {
			out = append(out, rule)
		}
	}
	return out, nil
}

func (s *Server) writeGrantStoreError(w http.ResponseWriter, client, operation, target string) {
	writePlain(w, http.StatusInternalServerError, "hf-broker: could not inspect grants\n")
	s.record(client, operation, target, audit.DecisionRefused, "could not inspect grants", 0)
}

func activeGrantRule(grant grants.Grant) (policy.Rule, bool) {
	if grant.Status != grants.StatusActive || grant.ReservationRetained || !runtimeWindowGrant(grant) || grantUsesRemaining(grant) <= 0 {
		return policy.Rule{}, false
	}
	target := targetFromGrant(grant)
	if target.Kind == "" {
		return policy.Rule{}, false
	}
	attrs, err := policy.AttrConstraintsFromValues(grant.Attrs)
	if err != nil {
		return policy.Rule{}, false
	}
	rule := policy.GeneratedGrantRule(
		grant.ID, grant.Client, policy.Operation(grant.Operation), target, grant.ExpiresAt, grantUsesRemaining(grant),
	)
	rule.Attrs = attrs
	return rule, true
}

func routeTarget(rt route, refs []string) policy.Target {
	return policy.Target{
		Kind:  policy.KindRepo,
		Type:  rt.repoType,
		Owner: rt.owner,
		Name:  rt.name,
		Refs:  refs,
	}
}

func (s *Server) handleForward(w http.ResponseWriter, r *http.Request, client string, classified classifiedRequest, target string, decision policy.Decision) {
	s.forwardAndRecord(w, r, client, classified, target, audit.DecisionAllowed, "", decision)
}

func (s *Server) handleForwardWithActiveGrant(w http.ResponseWriter, r *http.Request, client string, classified classifiedRequest, target string, decision policy.Decision, consumeUse bool) bool {
	if policyDenyRefusesGrant(decision) {
		return false
	}
	grant, matched, err := s.matchForwardActiveGrant(r, client, classified, target)
	if err != nil {
		writePlain(w, http.StatusInternalServerError, "hf-broker: could not inspect grants\n")
		s.record(client, string(classified.operation), target, audit.DecisionRefused, "could not inspect grants", 0)
		return true
	}
	if !matched {
		return false
	}
	if !consumeUse {
		s.forwardWithMatchedGrant(w, r, client, classified, target)
		return true
	}
	s.forwardWithReservedGrant(w, r, client, classified, target, grant)
	return true
}

func (s *Server) matchForwardActiveGrant(r *http.Request, client string, classified classifiedRequest, target string) (grants.Grant, bool, error) {
	if lfsUploadRequest(r, classified) {
		return s.matchActiveGrantIgnoringRef(client, classified.operation, target, classified.attrs)
	}
	return s.matchActiveGrant(client, classified.operation, target, "", classified.attrs)
}

func (s *Server) matchActiveGrantIgnoringRef(client string, operation policy.Operation, target string, attrs map[string]any) (grants.Grant, bool, error) {
	clientGrants, err := s.grants.ListForClient(client)
	if err != nil {
		return grants.Grant{}, false, err
	}
	for _, grant := range clientGrants {
		if activeGrantMatchesIgnoringRef(grant, client, operation, target, attrs) {
			return grant, true, nil
		}
	}
	return grants.Grant{}, false, nil
}

func activeGrantMatchesIgnoringRef(grant grants.Grant, client string, operation policy.Operation, target string, attrs map[string]any) bool {
	return grant.Status == grants.StatusActive &&
		!grant.ReservationRetained &&
		runtimeWindowGrant(grant) &&
		grant.Client == client &&
		grant.Operation == string(operation) &&
		grant.Target == target &&
		grantUsesRemaining(grant) > 0 &&
		policy.AttrValuesMatch(refLessSupportGrantAttrs(grant.Attrs), attrs)
}

func refLessSupportGrantAttrs(attrs map[string]any) map[string]any {
	if _, ok := attrs["ref_change"]; !ok {
		return attrs
	}
	out := make(map[string]any, len(attrs)-1)
	for key, value := range attrs {
		if key != "ref_change" {
			out[key] = value
		}
	}
	return out
}

func (s *Server) forwardWithMatchedGrant(w http.ResponseWriter, r *http.Request, client string, classified classifiedRequest, target string) {
	s.forwardAndRecord(w, r, client, classified, target, audit.DecisionAllowed, "operator grant discovery", policy.Decision{})
}

func (s *Server) forwardAndRecord(w http.ResponseWriter, r *http.Request, client string, classified classifiedRequest, target, decision, reason string, policyDecision policy.Decision) {
	statusCode, err := s.forward(w, r, classified.route, classified.body, classified.bodyRead)
	if s.recordForwardError(w, client, classified, target, statusCode, err, policyDecision) {
		return
	}
	s.recordPolicyDecision(client, string(classified.operation), target, decision, reason, statusCode, policyDecision)
}

func (s *Server) forwardWithReservedGrant(w http.ResponseWriter, r *http.Request, client string, classified classifiedRequest, target string, grant grants.Grant) {
	reserved, err := s.grants.ReserveUse(grant.ID)
	if err != nil {
		writePlain(w, http.StatusForbidden, "hf-broker: grant is not active\n")
		s.record(client, string(classified.operation), target, audit.DecisionRefused, "grant is not active", 0)
		return
	}
	statusCode, err := s.forward(w, r, classified.route, classified.body, classified.bodyRead)
	if errors.Is(err, errInvalidLFSAction) {
		_, _ = s.grants.ReleaseUse(reserved.ID)
	} else if err != nil {
		s.closeForwardGrantReservation(reserved, err)
	}
	if s.recordForwardError(w, client, classified, target, statusCode, err, policy.Decision{}) {
		return
	}
	s.updateGrantMessages(s.commitGrantUses([]grants.Grant{reserved}), s.updateGrantUseMessage)
	s.recordGrantUsed(client, string(classified.operation), target, statusCode, []string{reserved.ID})
}

func (s *Server) recordForwardError(w http.ResponseWriter, client string, classified classifiedRequest, target string, statusCode int, err error, decision policy.Decision) bool {
	if errors.Is(err, errInvalidLFSAction) {
		s.recordPolicyDecision(client, string(classified.operation), target, audit.DecisionRefused, errInvalidLFSAction.Error(), statusCode, decision)
		return true
	}
	if err != nil {
		writePlain(w, http.StatusBadGateway, "hf-broker: upstream request failed\n")
		s.recordPolicyDecision(client, string(classified.operation), target, audit.DecisionRefused, "upstream request failed", statusCode, decision)
		return true
	}
	return false
}

func (s *Server) closeForwardGrantReservation(reserved grants.Grant, err error) {
	if forwardErrorBeforeUpstream(err) {
		_, _ = s.grants.ReleaseUse(reserved.ID)
		return
	}
	s.updateRetainedGrantReservationMessage(reserved)
}

func forwardErrorBeforeUpstream(err error) bool {
	return errors.Is(err, errInvalidLFSAction)
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
	client, err := s.auth.Authenticate(r.Header.Get("Authorization"))
	if err == nil {
		return client, true
	}
	status := http.StatusForbidden
	if errors.Is(err, auth.ErrMissing) {
		status = http.StatusUnauthorized
		w.Header().Set("WWW-Authenticate", `Basic realm="hf-broker"`)
	}
	writePlain(w, status, "hf-broker: authentication failed\n")
	s.audit.Record(audit.Entry{Operation: "unknown", Decision: audit.DecisionRefused, Reason: "authentication failed"})
	return "", false
}

func (s *Server) authenticateAPI(w http.ResponseWriter, r *http.Request) (string, bool) {
	client, err := s.auth.Authenticate(r.Header.Get("Authorization"))
	if err == nil {
		return client, true
	}
	status := http.StatusForbidden
	reason := "bad_auth"
	message := "Authentication failed"
	if errors.Is(err, auth.ErrMissing) {
		status = http.StatusUnauthorized
		reason = "missing_auth"
		message = "Authentication required"
		w.Header().Set("WWW-Authenticate", `Basic realm="hf-broker"`)
	}
	writeJSendFail(w, status, reason, message)
	s.audit.Record(audit.Entry{Operation: "api", Decision: audit.DecisionRefused, Reason: "authentication failed"})
	return "", false
}

type apiGrantRequestBody struct {
	Operation       policy.Operation `json:"operation"`
	Target          policy.Target    `json:"target"`
	Attrs           map[string]any   `json:"attrs"`
	Minutes         int              `json:"minutes"`
	MaxUses         int              `json:"max_uses"`
	Reason          string           `json:"reason"`
	ClientRequestID string           `json:"client_request_id"`
}

type apiGrantBody struct {
	ID              string           `json:"id"`
	Status          string           `json:"status"`
	Operation       string           `json:"operation"`
	Target          policy.Target    `json:"target"`
	Attrs           map[string]any   `json:"attrs"`
	Mode            policy.GrantMode `json:"mode"`
	Minutes         int              `json:"minutes"`
	MaxUses         int              `json:"max_uses"`
	UsesRemaining   int              `json:"uses_remaining"`
	UsedCount       int              `json:"used_count"`
	PendingUntil    *string          `json:"pending_until"`
	ExpiresAt       *string          `json:"expires_at"`
	ClientRequestID string           `json:"client_request_id,omitempty"`
}

type apiRepoBody struct {
	Type  string `json:"type"`
	Owner string `json:"owner"`
	Name  string `json:"name"`
}

type apiRouteHandler func(*Server, http.ResponseWriter, *http.Request, string)

type apiRoute struct {
	method string
	path   string
	prefix string
	handle apiRouteHandler
}

type repoListQuery struct {
	limit       int
	filterType  policy.RepoType
	filterOwner string
}

type pushPolicyCandidate struct {
	operation policy.Operation
	refChange string
}

var apiRoutes = []apiRoute{
	{method: http.MethodPost, path: "/api/grants", handle: (*Server).handleAPIGrantCreate},
	{method: http.MethodGet, path: "/api/grants", handle: (*Server).handleAPIGrantList},
	{method: http.MethodGet, prefix: "/api/grants/", handle: (*Server).handleAPIGrantGet},
	{method: http.MethodGet, path: "/api/repos", handle: (*Server).handleAPIRepos},
}

func (s *Server) serveAPI(w http.ResponseWriter, r *http.Request) {
	client, ok := s.authenticateAPI(w, r)
	if !ok {
		return
	}
	if handler := matchingAPIHandler(r); handler != nil {
		handler(s, w, r, client)
		return
	}
	reason := writeAPIUnknownRoute(w, r.URL.Path)
	s.record(client, "api", r.URL.Path, audit.DecisionRefused, reason, 0)
}

func matchingAPIHandler(r *http.Request) apiRouteHandler {
	for _, route := range apiRoutes {
		if route.matches(r) {
			return route.handle
		}
	}
	return nil
}

func (route apiRoute) matches(r *http.Request) bool {
	return route.method == r.Method && route.pathMatches(r.URL.Path)
}

func (route apiRoute) pathMatches(path string) bool {
	if route.path != "" {
		return path == route.path
	}
	return route.prefix != "" && strings.HasPrefix(path, route.prefix)
}

func writeAPIUnknownRoute(w http.ResponseWriter, path string) string {
	if apiKnownPath(path) {
		writeJSendFail(w, http.StatusMethodNotAllowed, "method_not_allowed", "Method not allowed")
		return "method_not_allowed"
	}
	writeJSendFail(w, http.StatusNotFound, "not_found", "API route not found")
	return "not_found"
}

func apiKnownPath(path string) bool {
	return path == "/api/grants" || path == "/api/repos" || strings.HasPrefix(path, "/api/grants/")
}

func (s *Server) handleAPIGrantCreate(w http.ResponseWriter, r *http.Request, client string) {
	if !s.requireApprovalChannel(w, client) {
		return
	}
	req, ok := readAPIGrantRequest(w, r)
	if !ok {
		s.record(client, "grant_request", "", audit.DecisionRefused, "could not parse grant request", 0)
		return
	}
	grantPolicy, status, reason, message := s.validateAPIGrantRequest(client, req)
	if reason != "" {
		writeJSendFail(w, status, reason, message)
		s.record(client, "grant_request", targetNameFromPolicy(req.Target), audit.DecisionRefused, reason, 0)
		return
	}
	grant, _, err := s.requestAPIGrant(client, req, grantPolicy)
	if err != nil {
		status, reason, message := grantRequestError(err)
		writeJSendFail(w, status, reason, message)
		s.record(client, "grant_request", targetNameFromPolicy(req.Target), audit.DecisionRefused, reason, 0)
		return
	}
	if s.notifier != nil && grantNeedsNotification(grant) {
		var notified bool
		grant, notified = s.notifyAPIGrantIfClaimed(w, r, client, grant)
		if !notified {
			return
		}
	}
	writeJSendSuccess(w, http.StatusAccepted, map[string]any{"grant": apiGrantFromStore(grant, req.Target)})
	s.record(client, "grant_request", grant.Target, audit.DecisionAllowed, "pending", 0)
}

func (s *Server) requireApprovalChannel(w http.ResponseWriter, client string) bool {
	if s.notifier != nil || s.operatorConfigured {
		return true
	}
	writeJSendError(w, http.StatusServiceUnavailable, "approval channel is not configured", "approval_channel_not_configured")
	s.record(client, "grant_request", "", audit.DecisionRefused, "approval channel is not configured", 0)
	return false
}

func readAPIGrantRequest(w http.ResponseWriter, r *http.Request) (apiGrantRequestBody, bool) {
	body, tooLarge, err := readLimited(r.Body, 4096)
	if err != nil {
		writeJSendFail(w, http.StatusBadRequest, "malformed_json", "Could not read grant request")
		return apiGrantRequestBody{}, false
	}
	if tooLarge {
		writeJSendFail(w, http.StatusRequestEntityTooLarge, "request_too_large", "Grant request is too large")
		return apiGrantRequestBody{}, false
	}
	var req apiGrantRequestBody
	decoder := json.NewDecoder(bytes.NewReader(body))
	decoder.DisallowUnknownFields()
	decoder.UseNumber()
	if err := decoder.Decode(&req); err != nil {
		writeJSendFail(w, http.StatusBadRequest, "malformed_json", "Could not parse grant request")
		return apiGrantRequestBody{}, false
	}
	var trailing struct{}
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		writeJSendFail(w, http.StatusBadRequest, "malformed_json", "Could not parse grant request")
		return apiGrantRequestBody{}, false
	}
	return req, true
}

func (s *Server) validateAPIGrantRequest(client string, req apiGrantRequestBody) (*policy.GrantPolicy, int, string, string) {
	if status, reason, message := validateAPIGrantRequestShape(req); reason != "" {
		return nil, status, reason, message
	}
	decision := s.policy.Decide(policy.Request{
		Client:    client,
		Operation: req.Operation,
		Target:    req.Target,
		Attrs:     req.Attrs,
	}, nil, time.Now().UTC(), true)
	return apiGrantDecisionResult(req, decision)
}

func apiGrantDecisionResult(req apiGrantRequestBody, decision policy.Decision) (*policy.GrantPolicy, int, string, string) {
	switch decision.Effect {
	case policy.EffectRequest:
		return requestableGrantDecisionResult(req, decision.GrantPolicy)
	case policy.EffectDeny:
		return deniedGrantDecisionResult(decision)
	default:
		return nil, http.StatusForbidden, "not_requestable", "No policy rule allows requesting this operation"
	}
}

func requestableGrantDecisionResult(req apiGrantRequestBody, grantPolicy *policy.GrantPolicy) (*policy.GrantPolicy, int, string, string) {
	if status, reason := validateAPIGrantPolicyBounds(req, grantPolicy); reason != "" {
		return nil, status, "validation_failed", reason
	}
	return grantPolicy, 0, "", ""
}

func deniedGrantDecisionResult(decision policy.Decision) (*policy.GrantPolicy, int, string, string) {
	if decision.Reason == "invalid_operation" {
		return nil, http.StatusBadRequest, "invalid_operation", "Invalid operation"
	}
	if decision.Reason == "invalid_target" {
		return nil, http.StatusBadRequest, "invalid_target", "Invalid target"
	}
	return nil, http.StatusForbidden, decision.Reason, policyReasonMessage(decision.Reason)
}

func validateGrantTargetForOperation(operation policy.Operation, target policy.Target) error {
	if err := validateGrantTargetIdentity(target); err != nil {
		return err
	}
	if grantTargetHasUnsupportedConstraints(target) {
		return errors.New("grant target path, key, and visibility constraints are not supported")
	}
	return validateGrantTargetRefForOperation(operation, target)
}

func validateGrantTargetRefForOperation(operation policy.Operation, target policy.Target) error {
	ref, err := grantRefFromTarget(target)
	if err != nil {
		return err
	}
	if operationNeedsRef(operation) {
		if ref == "" {
			return errors.New("grant target must include exactly one ref")
		}
		if !gitproxy.ValidRefName(ref) || !grantRefMatchesOperation(operation, ref) {
			return errors.New("grant target ref is invalid for operation")
		}
	} else if ref != "" {
		return errors.New("grant target ref is not supported for operation")
	}
	return nil
}

func validateGrantTargetIdentity(target policy.Target) error {
	if target.Kind != policy.KindRepo {
		return errors.New("grant target must be an exact repo")
	}
	if _, ok := parseGrantTarget(targetNameFromPolicy(target)); !ok {
		return errors.New("grant target must be an exact repo")
	}
	return nil
}

func grantTargetHasUnsupportedConstraints(target policy.Target) bool {
	return len(target.Paths) > 0 ||
		len(target.Keys) > 0 ||
		len(target.Visibility) > 0
}

func operationNeedsRef(operation policy.Operation) bool {
	switch operation {
	case policy.OpGitPushAppend, policy.OpGitPushForce, policy.OpGitRefDelete, policy.OpGitTagUpdate:
		return true
	default:
		return false
	}
}

func grantRefFromTarget(target policy.Target) (string, error) {
	if len(target.Refs) > 1 {
		return "", errors.New("grant target must include at most one ref")
	}
	if len(target.Refs) == 0 {
		return "", nil
	}
	return target.Refs[0], nil
}

func validateAPIGrantPolicyBounds(req apiGrantRequestBody, grantPolicy *policy.GrantPolicy) (int, string) {
	if grantPolicy == nil {
		return http.StatusForbidden, "No policy rule allows requesting this operation"
	}
	if req.Minutes > grantPolicy.MaxMinutes {
		return http.StatusBadRequest, fmt.Sprintf("Grant duration exceeds %d minutes", grantPolicy.MaxMinutes)
	}
	if req.MaxUses > grantPolicy.MaxUses {
		return http.StatusBadRequest, fmt.Sprintf("Grant max uses exceeds %d", grantPolicy.MaxUses)
	}
	return 0, ""
}

func (s *Server) requestAPIGrant(client string, req apiGrantRequestBody, grantPolicy *policy.GrantPolicy) (grants.Grant, bool, error) {
	minutes := req.Minutes
	if minutes == 0 {
		minutes = grantPolicy.DefaultMinutes
	}
	maxUses := req.MaxUses
	if maxUses == 0 {
		maxUses = grantPolicy.DefaultMaxUses
	}
	ref, _ := grantRefFromTarget(req.Target)
	return s.grants.Request(grants.Request{
		Client:            client,
		ClientRequestID:   req.ClientRequestID,
		Operation:         string(req.Operation),
		Mode:              string(grantPolicy.Mode),
		Target:            targetNameFromPolicy(req.Target),
		Ref:               ref,
		Attrs:             req.Attrs,
		Reason:            req.Reason,
		RequestedDuration: time.Duration(minutes) * time.Minute,
		PendingTimeout:    time.Duration(grantPolicy.RequestTTLMinutes) * time.Minute,
		MaxUses:           maxUses,
	})
}

func grantRequestError(err error) (int, string, string) {
	if errors.Is(err, grants.ErrIdempotencyConflict) {
		return http.StatusConflict, "idempotency_conflict", "Idempotency key was reused with a different request"
	}
	return http.StatusBadRequest, "validation_failed", err.Error()
}

func (s *Server) handleAPIGrantList(w http.ResponseWriter, r *http.Request, client string) {
	statusFilter, ok := parseGrantStatusFilter(r)
	if !ok {
		writeJSendFail(w, http.StatusBadRequest, "validation_failed", "Invalid grant status filter")
		s.record(client, "grant_list", "grants", audit.DecisionRefused, "validation_failed", 0)
		return
	}
	grantsForClient, err := s.grants.ListForClient(client)
	if err != nil {
		writeJSendError(w, http.StatusInternalServerError, "could not list grants", "internal_error")
		s.record(client, "grant_list", "grants", audit.DecisionRefused, "could not list grants", 0)
		return
	}
	out := apiGrantListFromStore(grantsForClient, statusFilter)
	writeJSendSuccess(w, http.StatusOK, map[string]any{"grants": out, "next_cursor": nil})
	s.record(client, "grant_list", "grants", audit.DecisionAllowed, "", 0)
}

func parseGrantStatusFilter(r *http.Request) (string, bool) {
	statusFilter := r.URL.Query().Get("status")
	return statusFilter, statusFilter == "" || validGrantStatusFilter(statusFilter)
}

func apiGrantListFromStore(grantsForClient []grants.Grant, statusFilter string) []apiGrantBody {
	out := make([]apiGrantBody, 0, len(grantsForClient))
	for _, grant := range grantsForClient {
		if grantStatusMatchesFilter(grant, statusFilter) {
			out = append(out, apiGrantFromStore(grant, targetFromGrant(grant)))
		}
	}
	return out
}

func (s *Server) notifyAPIGrantIfClaimed(w http.ResponseWriter, r *http.Request, client string, grant grants.Grant) (grants.Grant, bool) {
	claimedGrant, claimed, err := s.grants.ClaimNotifier(grant.ID, grantNotificationClaimLease)
	if err != nil {
		writeJSendError(w, http.StatusBadGateway, "could not claim operator notification", "internal_error")
		s.record(client, "grant_request", grant.Target, audit.DecisionRefused, "could not claim operator notification", 0)
		return grants.Grant{}, false
	}
	if !claimed {
		return s.waitForAPIGrantNotificationResponse(w, r, client, grant, grant.ID)
	}
	return s.notifyAPICreatedGrant(w, r, client, claimedGrant)
}

func (s *Server) cancelAPIGrantNotificationIfClaimed(w http.ResponseWriter, r *http.Request, client string, grant grants.Grant, reason string) (grants.Grant, bool) {
	updated, canceled, err := s.grants.CancelIfNotifierClaimed(grant.ID, grant.NotifierClaimedAt)
	if err != nil {
		writeJSendError(w, http.StatusBadGateway, reason, "internal_error")
		s.record(client, "grant_request", grant.Target, audit.DecisionRefused, reason, 0)
		return grants.Grant{}, false
	}
	if canceled || updated.Status == grants.StatusCanceled {
		writeJSendError(w, http.StatusBadGateway, reason, "upstream_error")
		s.record(client, "grant_request", grant.Target, audit.DecisionRefused, reason, 0)
		return grants.Grant{}, false
	}
	return s.resolveAPIPendingGrantNotification(w, r, client, grant, updated)
}

func (s *Server) retainAPIGrantNotificationIfClaimed(w http.ResponseWriter, r *http.Request, client string, grant grants.Grant, reason string) (grants.Grant, bool) {
	updated, retained, err := s.grants.RetainNotifierClaim(grant.ID, grant.NotifierClaimedAt)
	if err != nil {
		writeJSendError(w, http.StatusBadGateway, reason, "internal_error")
		s.record(client, "grant_request", grant.Target, audit.DecisionRefused, reason, 0)
		return grants.Grant{}, false
	}
	if retained || updated.NotifierUnresolved {
		writeJSendError(w, http.StatusBadGateway, reason, "upstream_error")
		s.record(client, "grant_request", grant.Target, audit.DecisionRefused, reason, 0)
		return grants.Grant{}, false
	}
	return s.resolveAPIPendingGrantNotification(w, r, client, grant, updated)
}

func (s *Server) resolveAPIPendingGrantNotification(w http.ResponseWriter, r *http.Request, client string, original, current grants.Grant) (grants.Grant, bool) {
	if !grantNeedsNotification(current) {
		return current, true
	}
	return s.waitForAPIGrantNotificationResponse(w, r, client, original, original.ID)
}

func (s *Server) waitForAPIGrantNotificationResponse(w http.ResponseWriter, r *http.Request, client string, grant grants.Grant, id string) (grants.Grant, bool) {
	current, err := s.waitForGrantNotification(r.Context(), id)
	if err != nil {
		status, message, code := apiGrantNotificationWaitError(err)
		writeJSendError(w, status, message, code)
		s.record(client, "grant_request", grant.Target, audit.DecisionRefused, message, 0)
		return grants.Grant{}, false
	}
	return current, true
}

func apiGrantNotificationWaitError(err error) (int, string, string) {
	switch {
	case errors.Is(err, errGrantNotificationCanceled):
		return http.StatusBadGateway, "could not notify operator", "upstream_error"
	case errors.Is(err, errGrantNotificationUnresolved):
		return http.StatusBadGateway, "could not notify operator", "upstream_error"
	case errors.Is(err, errGrantNotificationStillQueued):
		return http.StatusBadGateway, "operator notification is still pending", "internal_error"
	default:
		return http.StatusBadGateway, "could not confirm operator notification", "internal_error"
	}
}

func (s *Server) handleAPIGrantGet(w http.ResponseWriter, r *http.Request, client string) {
	id := strings.TrimPrefix(r.URL.Path, "/api/grants/")
	if id == "" || strings.Contains(id, "/") {
		writeJSendFail(w, http.StatusNotFound, "grant_not_found", "Grant not found")
		s.record(client, "grant_read", "grant", audit.DecisionRefused, "grant_not_found", 0)
		return
	}
	grant, err := s.grants.GetForClient(client, id)
	if err != nil {
		writeJSendFail(w, http.StatusNotFound, "grant_not_found", "Grant not found")
		s.record(client, "grant_read", id, audit.DecisionRefused, "grant_not_found", 0)
		return
	}
	writeJSendSuccess(w, http.StatusOK, map[string]any{"grant": apiGrantFromStore(grant, targetFromGrant(grant))})
	s.record(client, "grant_read", id, audit.DecisionAllowed, "", 0)
}

func (s *Server) handleAPIRepos(w http.ResponseWriter, r *http.Request, client string) {
	query, reason, ok := readRepoListQuery(w, r)
	if !ok {
		s.record(client, string(policy.OpRepoList), "repos", audit.DecisionRefused, reason, 0)
		return
	}
	repos := s.listReposForClient(client, query)
	writeJSendSuccess(w, http.StatusOK, map[string]any{"repos": repos, "next_cursor": nil})
	s.record(client, string(policy.OpRepoList), "repos", audit.DecisionAllowed, "", 0)
}

func readRepoListQuery(w http.ResponseWriter, r *http.Request) (repoListQuery, string, bool) {
	if cursor := r.URL.Query().Get("cursor"); cursor != "" {
		writeJSendFail(w, http.StatusBadRequest, "invalid_cursor", "Invalid cursor")
		return repoListQuery{}, "invalid_cursor", false
	}
	limit, ok := parseRepoListLimit(r.URL.Query().Get("limit"))
	if !ok {
		writeJSendFail(w, http.StatusBadRequest, "invalid_limit", "Invalid limit")
		return repoListQuery{}, "invalid_limit", false
	}
	return repoListQuery{
		limit:       limit,
		filterType:  policy.RepoType(r.URL.Query().Get("type")),
		filterOwner: r.URL.Query().Get("owner"),
	}, "", true
}

func (s *Server) listReposForClient(client string, query repoListQuery) []apiRepoBody {
	repos := make([]apiRepoBody, 0)
	seen := map[string]bool{}
	for _, rule := range s.policy.Rules() {
		repos = s.appendReposFromRule(client, rule, query, repos, seen)
		if len(repos) >= query.limit {
			return repos
		}
	}
	return repos
}

func (s *Server) appendReposFromRule(client string, rule policy.Rule, query repoListQuery, repos []apiRepoBody, seen map[string]bool) []apiRepoBody {
	if !ruleMayDiscloseRepoListTarget(rule, client) {
		return repos
	}
	for _, target := range rule.Targets {
		repos = s.appendListedRepo(client, target, query, repos, seen)
		if len(repos) >= query.limit {
			return repos
		}
	}
	return repos
}

func (s *Server) appendListedRepo(client string, target policy.TargetMatcher, query repoListQuery, repos []apiRepoBody, seen map[string]bool) []apiRepoBody {
	repo, ok := listedRepoForTarget(client, s.policy, target, query)
	if !ok || seen[repoKey(repo)] {
		return repos
	}
	seen[repoKey(repo)] = true
	return append(repos, repo)
}

func ruleMayDiscloseRepoListTarget(rule policy.Rule, client string) bool {
	return rule.Effect == policy.EffectAllow &&
		stringListContains(rule.Clients, "*", client) &&
		(operationListContains(rule.Operations, policy.OpRepoList) ||
			operationListContains(rule.Operations, policy.OpRepoMetadataRead))
}

func stringListContains(values []string, wants ...string) bool {
	for _, value := range values {
		for _, want := range wants {
			if value == want {
				return true
			}
		}
	}
	return false
}

func operationListContains(values []policy.Operation, want policy.Operation) bool {
	for _, value := range values {
		if value == want {
			return true
		}
	}
	return false
}

func parseRepoListLimit(value string) (int, bool) {
	if value == "" {
		return 100, true
	}
	limit, err := strconv.Atoi(value)
	if err != nil || !repoListLimitInBounds(limit) {
		return 0, false
	}
	return limit, true
}

func repoListLimitInBounds(limit int) bool {
	return limit >= 1 && limit <= 100
}

func listedRepoForTarget(client string, pol policy.Policy, target policy.TargetMatcher, query repoListQuery) (apiRepoBody, bool) {
	if !targetIsListCandidate(target, query) {
		return apiRepoBody{}, false
	}
	reqTarget := repoTargetFromMatcher(target)
	if !policyAllowsListedRepo(client, pol, reqTarget) {
		return apiRepoBody{}, false
	}
	return apiRepoBody{Type: string(target.Type), Owner: target.Owner, Name: target.Name}, true
}

func targetIsListCandidate(target policy.TargetMatcher, query repoListQuery) bool {
	return target.Kind == policy.KindRepo &&
		exactRepoTarget(target) &&
		repoTargetMatchesListQuery(target, query)
}

func repoTargetMatchesListQuery(target policy.TargetMatcher, query repoListQuery) bool {
	if query.filterType != "" && target.Type != query.filterType {
		return false
	}
	return query.filterOwner == "" || target.Owner == query.filterOwner
}

func repoTargetFromMatcher(target policy.TargetMatcher) policy.Target {
	return policy.Target{Kind: policy.KindRepo, Type: target.Type, Owner: target.Owner, Name: target.Name}
}

func policyAllowsListedRepo(client string, pol policy.Policy, target policy.Target) bool {
	return policyAllowsRepoOperation(client, pol, target, policy.OpRepoList) &&
		policyAllowsRepoOperation(client, pol, target, policy.OpRepoMetadataRead)
}

func policyAllowsRepoOperation(client string, pol policy.Policy, target policy.Target, operation policy.Operation) bool {
	req := policy.Request{Client: client, Operation: operation, Target: target}
	return pol.Decide(req, nil, time.Now().UTC(), false).Effect == policy.EffectAllow
}

func repoKey(repo apiRepoBody) string {
	return repo.Type + "/" + repo.Owner + "/" + repo.Name
}

func exactRepoTarget(target policy.TargetMatcher) bool {
	return target.Type != policy.TypeAny &&
		target.Owner != "" &&
		target.Name != "" &&
		!strings.ContainsAny(string(target.Type), "*?") &&
		!strings.ContainsAny(target.Owner, "*?") &&
		!strings.ContainsAny(target.Name, "*?")
}

func validGrantStatusFilter(value string) bool {
	switch value {
	case string(grants.StatusPending), string(grants.StatusActive), string(grants.StatusExpired), string(grants.StatusConsumed), string(grants.StatusDenied), string(grants.StatusCanceled), retainedGrantStatus, "revoked":
		return true
	default:
		return false
	}
}

func grantStatusMatchesFilter(grant grants.Grant, filter string) bool {
	if matched, handled := retainedGrantMatchesFilter(grant, filter); handled {
		return matched
	}
	if filter == "revoked" {
		return grant.Status == grants.StatusCanceled
	}
	return filter == "" || string(grant.Status) == filter
}

func apiGrantFromStore(grant grants.Grant, target policy.Target) apiGrantBody {
	pendingUntil := timeStringPtr(grant.PendingExpiresAt)
	expiresAt := grantExpiresAtStringPtr(grant)
	return apiGrantBody{
		ID:              grant.ID,
		Status:          apiGrantStatus(grant),
		Operation:       grant.Operation,
		Target:          target,
		Attrs:           attrsOrEmpty(grant.Attrs),
		Mode:            grantModeFromStore(grant),
		Minutes:         grant.RequestedMinutes,
		MaxUses:         grant.MaxUses,
		UsesRemaining:   grantUsesRemaining(grant),
		UsedCount:       grant.UsedCount,
		PendingUntil:    pendingUntil,
		ExpiresAt:       expiresAt,
		ClientRequestID: grant.ClientRequestID,
	}
}

func grantExpiresAtStringPtr(grant grants.Grant) *string {
	switch grant.Status {
	case grants.StatusActive, grants.StatusConsumed:
		return timeStringPtr(grant.ExpiresAt)
	case grants.StatusExpired:
		if grant.ExpiredFrom == grants.StatusActive {
			return timeStringPtr(grant.ExpiresAt)
		}
		return nil
	default:
		return nil
	}
}

func grantModeFromStore(grant grants.Grant) policy.GrantMode {
	switch grant.Mode {
	case grants.ModeExecution:
		return policy.GrantModeExecution
	default:
		return policy.GrantModeWindow
	}
}

func attrsOrEmpty(attrs map[string]any) map[string]any {
	if attrs == nil {
		return map[string]any{}
	}
	return attrs
}

func grantUsesRemaining(grant grants.Grant) int {
	if !grantIsActive(grant) || grantIsRetained(grant) {
		return 0
	}
	return nonNegativeUses(defaultedGrantMaxUses(grant) - grant.UsedCount - grant.ReservedCount)
}

func grantIsActive(grant grants.Grant) bool {
	return grant.Status == grants.StatusActive
}

func defaultedGrantMaxUses(grant grants.Grant) int {
	if grant.MaxUses > 0 {
		return grant.MaxUses
	}
	return 1
}

func nonNegativeUses(value int) int {
	if value < 0 {
		return 0
	}
	return value
}

func timeStringPtr(value time.Time) *string {
	if value.IsZero() {
		return nil
	}
	formatted := value.Format(time.RFC3339)
	return &formatted
}

func targetFromGrant(grant grants.Grant) policy.Target {
	rt, ok := parseGrantTarget(grant.Target)
	if !ok {
		return policy.Target{}
	}
	target := routeTarget(rt, nil)
	if grant.Ref != "" {
		target.Refs = []string{grant.Ref}
	}
	return target
}

func targetNameFromPolicy(target policy.Target) string {
	if target.Kind != policy.KindRepo {
		return ""
	}
	return string(target.Type) + "/" + target.Owner + "/" + target.Name
}

func policyReasonMessage(reason string) string {
	message := policyReasonMessages[reason]
	if message == "" {
		return reason
	}
	return message
}

var policyReasonMessages = map[string]string{
	"approval_required": "Approval required",
	"policy_denied":     "Policy denied",
	"no_matching_rule":  "No matching policy rule",
}

func writeJSendSuccess(w http.ResponseWriter, status int, data any) {
	writeJSON(w, status, jsend.Success(data))
}

func writeJSendFail(w http.ResponseWriter, status int, reason, message string) {
	writeJSON(w, status, jsend.Fail(map[string]any{"reason": reason, "message": message}))
}

func writeJSendError(w http.ResponseWriter, status int, message, code string) {
	writeJSON(w, status, jsend.Error(message, code))
}

func grantNeedsNotification(grant grants.Grant) bool {
	return grant.Status == grants.StatusPending && grant.Notifier == nil
}

func (s *Server) supersedeGrantMessage(ctx context.Context, ref bknotify.MessageRef) {
	if ref.MessageID == 0 {
		return
	}
	_ = s.updateNotifierStatus(ctx, ref, "⚠️ Superseded. Use the latest approval message.")
}

func (s *Server) waitForGrantNotification(ctx context.Context, id string) (grants.Grant, error) {
	ctx, cancel := context.WithTimeout(ctx, grantNotificationClaimWait)
	defer cancel()
	ticker := time.NewTicker(grantNotificationClaimPoll)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return grants.Grant{}, errGrantNotificationStillQueued
		case <-ticker.C:
			grant, err := s.grants.Get(id)
			if err != nil {
				return grants.Grant{}, err
			}
			if state := grantNotificationWaitState(grant); !errors.Is(state, errGrantNotificationStillQueued) {
				return grant, state
			}
		}
	}
}

func grantNotificationWaitState(grant grants.Grant) error {
	switch {
	case grant.Status == grants.StatusCanceled:
		return errGrantNotificationCanceled
	case grant.NotifierUnresolved:
		return errGrantNotificationUnresolved
	case grantNeedsNotification(grant):
		return errGrantNotificationStillQueued
	default:
		return nil
	}
}

func grantRefMatchesOperation(operation policy.Operation, ref string) bool {
	switch operation {
	case policy.OpGitPushAppend:
		return !isReplaceRef(ref)
	case policy.OpGitPushForce:
		return !isTagRef(ref) && !isReplaceRef(ref)
	case policy.OpGitRefDelete:
		return !isTagRef(ref) && !isReplaceRef(ref)
	case policy.OpGitTagUpdate:
		return isTagRef(ref)
	default:
		return false
	}
}

func parseGrantTarget(target string) (route, bool) {
	parts := strings.Split(target, "/")
	if len(parts) != 3 || strings.Contains(target, "..") {
		return route{}, false
	}
	repoType, ok := grantRepoType(parts[0])
	if !ok || invalidGrantTargetSegment(parts[1]) || invalidGrantTargetSegment(parts[2]) {
		return route{}, false
	}
	return route{repoType: repoType, owner: parts[1], name: parts[2]}, true
}

func grantRepoType(value string) (policy.RepoType, bool) {
	switch value {
	case string(policy.TypeModel):
		return policy.TypeModel, true
	case string(policy.TypeDataset):
		return policy.TypeDataset, true
	case string(policy.TypeSpace):
		return policy.TypeSpace, true
	default:
		return "", false
	}
}

func invalidGrantTargetSegment(value string) bool {
	return value == "" || strings.ContainsAny(value, " \t\r\n/\x00*?")
}

func grantApprovalMessage(grant grants.Grant) bknotify.ApprovalMessage {
	message := approval.Message{
		Client:           grant.Client,
		Operation:        grant.Operation,
		Mode:             grant.Mode,
		Target:           grant.Target,
		Ref:              grant.Ref,
		Attrs:            grant.Attrs,
		Reason:           grant.Reason,
		RequestedMinutes: grant.RequestedMinutes,
		MaxUses:          grant.MaxUses,
		PendingExpiresAt: grant.PendingExpiresAt,
	}
	return bknotify.ApprovalMessage{
		GrantID:          grant.ID,
		DecisionToken:    grant.DecisionToken,
		Text:             approval.Text(message),
		Client:           grant.Client,
		Operation:        grant.Operation,
		Target:           grant.Target,
		Reason:           grant.Reason,
		RequestedMinutes: grant.RequestedMinutes,
		MaxUses:          grant.MaxUses,
	}
}

func (s *Server) classify(r *http.Request) (classifiedRequest, int, string) {
	rt, ok := parseRepoRoute(r.URL.Path)
	if !ok {
		return classifiedRequest{}, http.StatusForbidden, "request is outside configured git routes"
	}
	op, body, bodyRead, status, reason := classifyOperation(r, rt)
	if reason != "" {
		return classifiedRequest{}, status, reason
	}
	return classifiedRequest{route: rt, operation: op, attrs: maxBytesAttrsForRequest(r, body, bodyRead), body: body, bodyRead: bodyRead}, 0, ""
}

func parseRepoRoute(requestPath string) (route, bool) {
	trimmed := strings.TrimPrefix(requestPath, "/")
	parts := strings.Split(trimmed, "/")
	if len(parts) < 3 {
		return route{}, false
	}
	repoType, prefixOffset := routePrefix(parts[0])
	if len(parts) < prefixOffset+3 {
		return route{}, false
	}
	owner := parts[prefixOffset]
	name := strings.TrimSuffix(parts[prefixOffset+1], ".git")
	tail := strings.Join(parts[prefixOffset+2:], "/")
	if owner == "" || name == "" || tail == "" {
		return route{}, false
	}
	return route{repoType: repoType, owner: owner, name: name, tail: tail}, true
}

func routePrefix(firstSegment string) (policy.RepoType, int) {
	switch firstSegment {
	case "datasets":
		return policy.TypeDataset, 1
	case "spaces":
		return policy.TypeSpace, 1
	default:
		return policy.TypeModel, 0
	}
}

func classifyOperation(r *http.Request, rt route) (policy.Operation, []byte, bool, int, string) {
	switch {
	case r.Method == http.MethodGet && rt.tail == "info/refs":
		return classifyInfoRefs(r.URL.Query().Get("service"))
	case strings.HasPrefix(rt.tail, "info/lfs/"):
		return classifyLFS(r, rt.tail)
	case r.Method == http.MethodPost:
		return classifyGitPost(rt.tail)
	default:
		return "", nil, false, http.StatusForbidden, "unsupported git route"
	}
}

func classifyInfoRefs(service string) (policy.Operation, []byte, bool, int, string) {
	return classifyGitService(service, "unsupported git service")
}

func classifyGitPost(tail string) (policy.Operation, []byte, bool, int, string) {
	return classifyGitService(tail, "unsupported git route")
}

func classifyGitService(value, unsupported string) (policy.Operation, []byte, bool, int, string) {
	switch value {
	case "git-upload-pack":
		return policy.OpGitFetch, nil, false, 0, ""
	case "git-receive-pack":
		return policy.OpGitPushAppend, nil, false, 0, ""
	default:
		return "", nil, false, http.StatusForbidden, unsupported
	}
}

func classifyLFS(r *http.Request, tail string) (policy.Operation, []byte, bool, int, string) {
	if r.Method == http.MethodPost && tail == "info/lfs/objects/batch" {
		return classifyLFSBatch(r)
	}
	if r.Method == http.MethodPost && tail == "info/lfs/locks/verify" {
		return policy.OpRepoContentsRead, nil, false, 0, ""
	}
	if isLFSObjectDownload(r.Method, tail) {
		return policy.OpRepoContentsRead, nil, false, 0, ""
	}
	if isLFSObjectUpload(r.Method, tail) {
		return policy.OpGitPushAppend, nil, false, 0, ""
	}
	return "", nil, false, http.StatusForbidden, "unsupported LFS route"
}

func classifyLFSBatch(r *http.Request) (policy.Operation, []byte, bool, int, string) {
	body, tooLarge, err := readLimited(r.Body, maxLFSBatchBytes)
	if err != nil {
		return "", nil, false, http.StatusBadRequest, "could not read LFS batch request"
	}
	if tooLarge {
		return "", nil, false, http.StatusRequestEntityTooLarge, "LFS batch request is too large"
	}
	var payload struct {
		Operation string `json:"operation"`
	}
	if err := json.Unmarshal(body, &payload); err != nil {
		return "", nil, false, http.StatusBadRequest, "could not parse LFS batch request"
	}
	return classifyLFSOperation(payload.Operation, body)
}

func classifyLFSOperation(operation string, body []byte) (policy.Operation, []byte, bool, int, string) {
	switch operation {
	case "download":
		return policy.OpRepoContentsRead, body, true, 0, ""
	case "upload":
		return policy.OpGitPushAppend, body, true, 0, ""
	default:
		return "", nil, false, http.StatusForbidden, "unsupported LFS operation"
	}
}

func isLFSObjectDownload(method, tail string) bool {
	if method != http.MethodGet && method != http.MethodHead {
		return false
	}
	oid, ok := strings.CutPrefix(tail, "info/lfs/objects/")
	return ok && isLFSOID(oid)
}

func isLFSObjectUpload(method, tail string) bool {
	rest, ok := strings.CutPrefix(tail, "info/lfs/objects/")
	if !ok {
		return false
	}
	switch method {
	case http.MethodPost:
		return isLFSObjectVerify(rest)
	case http.MethodPut, http.MethodPatch:
		return isLFSObjectBodyUpload(rest)
	default:
		return false
	}
}

func isLFSObjectVerify(rest string) bool {
	oid, ok := strings.CutSuffix(rest, "/verify")
	return ok && isLFSOID(oid)
}

func isLFSObjectBodyUpload(rest string) bool {
	oid, size, ok := strings.Cut(rest, "/")
	return ok && isLFSOID(oid) && isDecimal(size)
}

func isLFSOID(value string) bool {
	if len(value) != 64 {
		return false
	}
	_, err := hex.DecodeString(value)
	return err == nil
}

func isDecimal(value string) bool {
	if value == "" {
		return false
	}
	for _, r := range value {
		if r < '0' || r > '9' {
			return false
		}
	}
	return true
}

func (s *Server) handleReceivePack(w http.ResponseWriter, r *http.Request, client string, rt route, target string) {
	if status, operation, reason, ok := s.receivePackMayRead(client, rt); !ok {
		writePlain(w, status, "hf-broker: "+reason+"\n")
		s.record(client, operation, target, audit.DecisionRefused, reason, 0)
		return
	}
	req, body, ok := s.readReceivePack(w, r, client, target)
	if !ok {
		return
	}
	operation, reason, ok, inspectErr := s.receivePackMayInspect(client, rt, target, req)
	if inspectErr != nil {
		s.writeGrantStoreError(w, client, operation, target)
		return
	}
	if !ok {
		writePlain(w, http.StatusForbidden, "hf-broker: "+reason+"\n")
		s.record(client, operation, target, audit.DecisionRefused, reason, 0)
		return
	}
	repo := mirror.Repo{Kind: string(rt.repoType), Owner: rt.owner, Name: rt.name, UpstreamURL: s.upstreamRepoURL(rt)}
	upstreamStatus, lockErr := s.withLockedPush(w, r, rt, repo, req, body, client, target)
	if lockErr != nil {
		s.handleReceivePackError(w, client, target, upstreamStatus, lockErr)
	}
}

func (s *Server) handleReceivePackError(w http.ResponseWriter, client, target string, upstreamStatus int, err error) {
	if upstreamStatus == 0 {
		status, message := receivePackErrorResponse(err)
		writePlain(w, status, message)
	}
	s.record(client, string(policy.OpGitPushAppend), target, audit.DecisionRefused, "push enforcement failed: "+err.Error(), upstreamStatus)
}

func receivePackErrorResponse(err error) (int, string) {
	if errors.Is(err, errGrantStoreUnavailable) {
		return http.StatusInternalServerError, "hf-broker: could not inspect grants\n"
	}
	return http.StatusForbidden, "hf-broker: push refused\n"
}

func (s *Server) receivePackMayRead(client string, rt route) (int, string, string, bool) {
	decision, err := s.decideReceivePackDiscovery(client, rt)
	if err != nil {
		return http.StatusInternalServerError, "git.push", "could not inspect grants", false
	}
	if receivePackDiscoveryPermitted(decision) {
		return 0, "", "", true
	}
	return http.StatusForbidden, "git.push", pushFailureReason(decision), false
}

func (s *Server) receivePackMayInspect(client string, rt route, target string, req gitproxy.ReceivePackRequest) (string, string, bool, error) {
	packSize := int64(len(req.Pack))
	for _, command := range req.Commands {
		operation, reason, ok, err := s.commandMayInspect(client, rt, target, command, packSize)
		if err != nil || !ok {
			return operation, reason, false, err
		}
	}
	return "", "", true, nil
}

func (s *Server) commandMayInspect(client string, rt route, target string, command gitproxy.Command, packSize int64) (string, string, bool, error) {
	candidates := preflightPushCandidates(command)
	if len(candidates) == 0 {
		return "", "", true, nil
	}
	operation := preflightAuditOperation(candidates)
	reason := "no matching policy rule"
	for _, candidate := range candidates {
		ok, candidateReason, err := s.pushCandidateMayInspect(client, rt, target, command.Ref, candidate, packSize)
		if err != nil {
			return operation, "could not inspect grants", false, err
		}
		if ok {
			return "", "", true, nil
		}
		if candidateReason != "" {
			reason = candidateReason
		}
	}
	return operation, reason, false, nil
}

func (s *Server) pushCandidateMayInspect(client string, rt route, target, ref string, candidate pushPolicyCandidate, packSize int64) (bool, string, error) {
	attrs := pushAttrsForChange(candidate.refChange, packSize)
	decision, err := s.decideRepo(client, candidate.operation, rt, []string{ref}, attrs, false)
	if err != nil {
		return false, "could not inspect grants", err
	}
	if policyDenyRefusesGrant(decision) {
		return false, pushFailureReason(decision), nil
	}
	if decision.Effect == policy.EffectAllow || decision.Reason == "approval_required" {
		return true, "", nil
	}
	return false, pushFailureReason(decision), nil
}

func preflightPushCandidates(command gitproxy.Command) []pushPolicyCandidate {
	if isReplaceRef(command.Ref) {
		return nil
	}
	if gitproxy.IsZeroSHA(command.New) {
		return deletePushCandidates(command.Ref)
	}
	if updatesExistingTag(command) {
		return []pushPolicyCandidate{{operation: policy.OpGitTagUpdate, refChange: "tag_update"}}
	}
	if createsRef(command) {
		return []pushPolicyCandidate{{operation: policy.OpGitPushAppend, refChange: "create"}}
	}
	return branchUpdatePushCandidates()
}

func updatesExistingTag(command gitproxy.Command) bool {
	return isTagRef(command.Ref) && !gitproxy.IsZeroSHA(command.Old)
}

func createsRef(command gitproxy.Command) bool {
	return gitproxy.IsZeroSHA(command.Old) || isTagRef(command.Ref)
}

func branchUpdatePushCandidates() []pushPolicyCandidate {
	return []pushPolicyCandidate{
		{operation: policy.OpGitPushAppend, refChange: "fast_forward"},
		{operation: policy.OpGitPushForce, refChange: "non_fast_forward"},
	}
}

func deletePushCandidates(ref string) []pushPolicyCandidate {
	if isTagRef(ref) {
		return []pushPolicyCandidate{{operation: policy.OpGitTagUpdate, refChange: "tag_update"}}
	}
	return []pushPolicyCandidate{{operation: policy.OpGitRefDelete, refChange: "delete"}}
}

func preflightAuditOperation(candidates []pushPolicyCandidate) string {
	if len(candidates) == 0 {
		return string(policy.OpGitPushAppend)
	}
	operation := candidates[0].operation
	for _, candidate := range candidates[1:] {
		if candidate.operation != operation {
			return "git.push"
		}
	}
	return string(operation)
}

func (s *Server) readReceivePack(w http.ResponseWriter, r *http.Request, client, target string) (gitproxy.ReceivePackRequest, []byte, bool) {
	body, tooLarge, err := readLimited(r.Body, s.maxBody)
	if err != nil {
		writePlain(w, http.StatusBadRequest, "hf-broker: could not read push\n")
		s.record(client, string(policy.OpGitPushAppend), target, audit.DecisionRefused, "could not read push", 0)
		return gitproxy.ReceivePackRequest{}, nil, false
	}
	if tooLarge {
		writePlain(w, http.StatusRequestEntityTooLarge, "hf-broker: push pack exceeds configured limit\n")
		s.record(client, string(policy.OpGitPushAppend), target, audit.DecisionRefused, "push pack exceeds configured limit", 0)
		return gitproxy.ReceivePackRequest{}, nil, false
	}
	req, err := gitproxy.ParseReceivePack(body)
	if err != nil {
		writePlain(w, http.StatusBadRequest, "hf-broker: could not parse push\n")
		s.record(client, string(policy.OpGitPushAppend), target, audit.DecisionRefused, "could not parse push", 0)
		return gitproxy.ReceivePackRequest{}, nil, false
	}
	if len(req.Commands) == 0 {
		writePlain(w, http.StatusBadRequest, "hf-broker: empty push\n")
		s.record(client, string(policy.OpGitPushAppend), target, audit.DecisionRefused, "empty receive-pack command list", 0)
		return gitproxy.ReceivePackRequest{}, nil, false
	}
	return req, body, true
}

func (s *Server) withLockedPush(w http.ResponseWriter, r *http.Request, rt route, repo mirror.Repo, req gitproxy.ReceivePackRequest, body []byte, client, target string) (int, error) {
	var result lockedPushResult
	lockErr := s.mirrors.WithLock(repo, func(mir *mirror.Repository) error {
		var err error
		result, err = s.processLockedPush(w, r, rt, req, body, mir, client, target)
		return err
	})
	s.updateGrantMessages(result.retainedGrantsToNotify, s.updateRetainedGrantReservationMessage)
	s.updateGrantMessages(result.grantsToNotify, s.updateGrantUseMessage)
	return result.upstreamStatus, lockErr
}

func (s *Server) processLockedPush(w http.ResponseWriter, r *http.Request, rt route, req gitproxy.ReceivePackRequest, body []byte, mir *mirror.Repository, client, target string) (lockedPushResult, error) {
	refused, usedGrants, classes, err := s.refuseInvalidPush(w, r, req, mir, client, target)
	if err != nil || refused {
		return lockedPushResult{}, err
	}
	reservedGrants, err := s.reserveGrantUses(usedGrants)
	if err != nil {
		return lockedPushResult{}, err
	}
	return s.forwardReservedPush(w, r, rt, req, body, mir, client, target, usedGrants, reservedGrants, classes)
}

func (s *Server) forwardReservedPush(w http.ResponseWriter, r *http.Request, rt route, req gitproxy.ReceivePackRequest, body []byte, mir *mirror.Repository, client, target string, usedGrants []grantUse, reservedGrants []grants.Grant, classes []gitproxy.ClassifiedCommand) (lockedPushResult, error) {
	statusCode, accepted, reason, definitiveReject, err := s.forwardReceivePack(w, r, rt, req, body)
	result := lockedPushResult{upstreamStatus: statusCode}
	if err != nil {
		retainedGrants, retainErr := s.retainGrantUseReservations(reservedGrants)
		result.retainedGrantsToNotify = retainedGrants
		if retainErr != nil {
			return result, fmt.Errorf("%w; %v", err, retainErr)
		}
		return result, err
	}
	if !accepted {
		retainedGrants, err := s.handleRejectedReservedPush(client, target, pushAuditOperation(classes), reason, statusCode, definitiveReject, reservedGrants)
		result.retainedGrantsToNotify = retainedGrants
		return result, err
	}
	s.acceptReservedPush(req, mir, client, target, statusCode, usedGrants, reservedGrants, classes, &result)
	return result, nil
}

func (s *Server) handleRejectedReservedPush(client, target, operation, reason string, statusCode int, definitiveReject bool, reservedGrants []grants.Grant) ([]grants.Grant, error) {
	var retainedGrants []grants.Grant
	var err error
	if definitiveReject {
		s.releaseGrantUses(reservedGrants)
	} else {
		retainedGrants, err = s.retainGrantUseReservations(reservedGrants)
	}
	s.record(client, operation, target, audit.DecisionRefused, reason, statusCode)
	return retainedGrants, err
}

func (s *Server) acceptReservedPush(req gitproxy.ReceivePackRequest, mir *mirror.Repository, client, target string, statusCode int, usedGrants []grantUse, reservedGrants []grants.Grant, classes []gitproxy.ClassifiedCommand, result *lockedPushResult) {
	_ = gitproxy.AdvanceAccepted(context.Background(), req, mir)
	result.grantsToNotify = s.commitGrantUses(reservedGrants)
	operation := pushAuditOperation(classes)
	if len(usedGrants) > 0 {
		s.recordGrantUsed(client, grantAuditOperation(usedGrants), target, statusCode, grantUseIDs(usedGrants))
		return
	}
	s.record(client, operation, target, audit.DecisionAllowed, "", statusCode)
}

func (s *Server) refuseInvalidPush(w http.ResponseWriter, r *http.Request, req gitproxy.ReceivePackRequest, mir *mirror.Repository, client, target string) (bool, []grantUse, []gitproxy.ClassifiedCommand, error) {
	used := map[string]grantUse{}
	classes, failures, err := gitproxy.ClassifyPush(r.Context(), req, mir)
	if err == nil && len(failures) == 0 {
		failures, err = s.refusePolicyDeniedPush(classes, client, target, int64(len(req.Pack)), used)
	}
	if len(failures) > 0 {
		w.Header().Set("Content-Type", "application/x-git-receive-pack-result")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(gitproxy.BuildRefusalReport(req, failures))
		s.record(client, pushAuditOperation(classes), target, audit.DecisionRefused, failures[0].Reason, 0)
		return true, nil, nil, nil
	}
	if err != nil {
		return false, nil, nil, err
	}
	return false, grantUses(used), classes, nil
}

func (s *Server) refusePolicyDeniedPush(classes []gitproxy.ClassifiedCommand, client, target string, packSize int64, used map[string]grantUse) ([]gitproxy.RefFailure, error) {
	rt, ok := parseGrantTarget(target)
	if !ok {
		return refFailuresForClasses(classes, "invalid target"), nil
	}
	var failures []gitproxy.RefFailure
	for _, class := range classes {
		failure, refused, err := s.refusalForClassifiedPush(class, client, rt, target, packSize, used)
		if err != nil {
			return nil, err
		}
		if refused {
			failures = append(failures, failure)
		}
	}
	return failures, nil
}

func (s *Server) refusalForClassifiedPush(class gitproxy.ClassifiedCommand, client string, rt route, target string, packSize int64, used map[string]grantUse) (gitproxy.RefFailure, bool, error) {
	operation := operationForRefUpdate(class.Kind)
	attrs := pushAttrs(class, packSize)
	decision, err := s.decideRepo(client, operation, rt, []string{class.Command.Ref}, attrs, false)
	if err != nil {
		return gitproxy.RefFailure{}, false, err
	}
	if decision.Effect == policy.EffectAllow && decision.Reason != "grant_allowed" {
		return gitproxy.RefFailure{}, false, nil
	}
	if policyDenyRefusesGrant(decision) {
		return refFailureForDecision(class.Command.Ref, decision), true, nil
	}
	matched, err := s.useGrantAllowedDecision(decision, client, operation, target, class.Command.Ref, attrs, used)
	if err != nil || matched {
		return gitproxy.RefFailure{}, false, err
	}
	return refFailureForDecision(class.Command.Ref, decision), true, nil
}

func (s *Server) useGrantAllowedDecision(decision policy.Decision, client string, operation policy.Operation, target, ref string, attrs map[string]any, used map[string]grantUse) (bool, error) {
	if decision.Reason != "grant_allowed" {
		return false, nil
	}
	return s.useActiveGrant(client, operation, target, ref, attrs, used)
}

func pushAttrs(class gitproxy.ClassifiedCommand, packSize int64) map[string]any {
	return pushAttrsForChange(refChangeForClass(class), packSize)
}

func pushAttrsForChange(refChange string, packSize int64) map[string]any {
	attrs := refChangeAttrs(refChange)
	addMaxBytesAttr(attrs, packSize)
	return attrs
}

func refChangeAttrs(refChange string) map[string]any {
	return map[string]any{"ref_change": refChange}
}

func maxBytesAttrsForRequest(r *http.Request, body []byte, bodyRead bool) map[string]any {
	if bodyRead {
		return maxBytesAttrs(int64(len(body)))
	}
	if requestMayHaveBody(r.Method) && r.ContentLength >= 0 {
		return maxBytesAttrs(r.ContentLength)
	}
	return nil
}

func requestMayHaveBody(method string) bool {
	switch method {
	case http.MethodPost, http.MethodPut, http.MethodPatch:
		return true
	default:
		return false
	}
}

func maxBytesAttrs(size int64) map[string]any {
	attrs := map[string]any{}
	addMaxBytesAttr(attrs, size)
	return attrs
}

func addMaxBytesAttr(attrs map[string]any, size int64) {
	if size >= 0 {
		attrs["max_bytes"] = size
	}
}

func refChangeForClass(class gitproxy.ClassifiedCommand) string {
	switch class.Kind {
	case gitproxy.RefUpdateAppend:
		if gitproxy.IsZeroSHA(class.Command.Old) {
			return "create"
		}
		return "fast_forward"
	case gitproxy.RefUpdateHistoryRewrite:
		return "non_fast_forward"
	case gitproxy.RefUpdateRefDelete:
		return "delete"
	case gitproxy.RefUpdateTagUpdate:
		return "tag_update"
	default:
		return string(class.Kind)
	}
}

func policyDenyRefusesGrant(decision policy.Decision) bool {
	return decision.Effect == policy.EffectDeny && decision.Reason == "policy_denied"
}

func (s *Server) useActiveGrant(client string, operation policy.Operation, target, ref string, attrs map[string]any, used map[string]grantUse) (bool, error) {
	grant, matched, err := s.matchActiveGrant(client, operation, target, ref, attrs)
	if err != nil {
		return false, fmt.Errorf("%w: %v", errGrantStoreUnavailable, err)
	}
	if !matched {
		return false, nil
	}
	used[grant.ID] = grantUse{grant: grant, ref: ref}
	return true, nil
}

func (s *Server) matchActiveGrant(client string, operation policy.Operation, target, ref string, attrs map[string]any) (grants.Grant, bool, error) {
	return s.grants.MatchActiveFunc(client, string(operation), target, ref, func(grant grants.Grant) bool {
		return runtimeWindowGrant(grant) && policy.AttrValuesMatch(grant.Attrs, attrs)
	})
}

func runtimeWindowGrant(grant grants.Grant) bool {
	return grant.Mode == grants.ModeWindow
}

func refFailureForDecision(ref string, decision policy.Decision) gitproxy.RefFailure {
	return gitproxy.RefFailure{Ref: ref, Reason: pushFailureReason(decision)}
}

func refFailuresForClasses(classes []gitproxy.ClassifiedCommand, reason string) []gitproxy.RefFailure {
	failures := make([]gitproxy.RefFailure, 0, len(classes))
	for _, class := range classes {
		failures = append(failures, gitproxy.RefFailure{Ref: class.Command.Ref, Reason: reason})
	}
	return failures
}

func operationForRefUpdate(kind gitproxy.RefUpdateKind) policy.Operation {
	switch kind {
	case gitproxy.RefUpdateHistoryRewrite:
		return policy.OpGitPushForce
	case gitproxy.RefUpdateRefDelete:
		return policy.OpGitRefDelete
	case gitproxy.RefUpdateTagUpdate:
		return policy.OpGitTagUpdate
	default:
		return policy.OpGitPushAppend
	}
}

func pushFailureReason(decision policy.Decision) string {
	switch decision.Reason {
	case "approval_required":
		return "approval required"
	case "policy_denied":
		return "policy denied"
	case "no_matching_rule":
		return "no matching policy rule"
	default:
		return decision.Reason
	}
}

func isTagRef(ref string) bool {
	return strings.HasPrefix(ref, "refs/tags/")
}

func isReplaceRef(ref string) bool {
	return strings.HasPrefix(ref, "refs/replace/")
}

func grantUses(used map[string]grantUse) []grantUse {
	uses := make([]grantUse, 0, len(used))
	for _, use := range used {
		uses = append(uses, use)
	}
	return uses
}

func pushAuditOperation(classes []gitproxy.ClassifiedCommand) string {
	if len(classes) == 0 {
		return string(policy.OpGitPushAppend)
	}
	operation := operationForRefUpdate(classes[0].Kind)
	for _, class := range classes[1:] {
		if operationForRefUpdate(class.Kind) != operation {
			return "git.push"
		}
	}
	return string(operation)
}

func grantAuditOperation(used []grantUse) string {
	operation := used[0].grant.Operation
	for _, use := range used[1:] {
		if use.grant.Operation != operation {
			return "git.push"
		}
	}
	return operation
}

func grantUseIDs(used []grantUse) []string {
	ids := make([]string, 0, len(used))
	for _, use := range used {
		ids = append(ids, use.grant.ID)
	}
	sort.Strings(ids)
	return ids
}

func (s *Server) reserveGrantUses(uses []grantUse) ([]grants.Grant, error) {
	reserved := make([]grants.Grant, 0, len(uses))
	for _, use := range uses {
		grant, err := s.grants.ReserveUse(use.grant.ID)
		if err != nil {
			s.releaseGrantUses(reserved)
			return nil, err
		}
		reserved = append(reserved, grant)
	}
	return reserved, nil
}

func (s *Server) commitGrantUses(reserved []grants.Grant) []grants.Grant {
	updated := make([]grants.Grant, 0, len(reserved))
	for _, grant := range reserved {
		committed, err := s.grants.CommitUse(grant.ID)
		if err != nil {
			continue
		}
		updated = append(updated, committed)
	}
	return updated
}

func (s *Server) releaseGrantUses(reserved []grants.Grant) {
	for _, grant := range reserved {
		_, _ = s.grants.ReleaseUse(grant.ID)
	}
}

func (s *Server) retainGrantUseReservations(reserved []grants.Grant) ([]grants.Grant, error) {
	retained := make([]grants.Grant, 0, len(reserved))
	for _, grant := range reserved {
		current, err := s.grants.RetainUse(grant.ID)
		if err != nil {
			return retained, fmt.Errorf("retain grant reservation: %w", err)
		}
		retained = append(retained, current)
	}
	return retained, nil
}

func (s *Server) updateGrantMessages(updated []grants.Grant, update func(grants.Grant)) {
	for _, grant := range updated {
		update(grant)
	}
}

func (s *Server) startGrantNotificationSweeper(ctx context.Context) {
	if s.notifier == nil {
		return
	}
	go func() {
		s.sweepGrantNotifications(ctx)
		ticker := time.NewTicker(30 * time.Second)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				s.sweepGrantNotifications(ctx)
			}
		}
	}()
}

func (s *Server) sweepGrantNotifications(ctx context.Context) {
	updates, err := s.grants.StatusUpdatesDue()
	if err != nil {
		return
	}
	for _, item := range updates {
		status := grantStatusUpdateText(item)
		if err := s.updateGrantMessage(ctx, item.Grant, status); err == nil {
			_ = s.grants.MarkNotifierStatus(item.Grant.ID, item.NotifierStatusKey())
		}
	}
}

func grantStatusUpdateText(update grants.StatusUpdate) string {
	switch update.Status {
	case grants.StatusActive:
		return "✅ Approved. Access is active."
	case grants.StatusDenied:
		return "❌ Denied. Access was not granted."
	case grants.NotifierStatusReserved:
		return retainedGrantReservationStatus(update.Grant)
	case grants.StatusConsumed:
		return grantUseStatus(update.Grant)
	default:
		return pendingExpiredStatusForGrant(update.Grant)
	}
}

func (s *Server) updateGrantUseMessage(grant grants.Grant) {
	s.deliverGrantStatusUpdate(context.Background(), grant.ID)
}

func (s *Server) updateRetainedGrantReservationMessage(grant grants.Grant) {
	current, err := s.grants.RetainUse(grant.ID)
	if err != nil {
		return
	}
	s.deliverGrantStatusUpdate(context.Background(), current.ID)
}

func (s *Server) deliverGrantStatusUpdate(ctx context.Context, id string) {
	updates, err := s.grants.StatusUpdatesDue()
	if err != nil {
		return
	}
	for _, update := range updates {
		if update.Grant.ID != id {
			continue
		}
		if err := s.updateGrantMessage(ctx, update.Grant, grantStatusUpdateText(update)); err == nil {
			_ = s.grants.MarkNotifierStatus(id, update.NotifierStatusKey())
		}
		return
	}
}

func (s *Server) updateGrantMessage(ctx context.Context, grant grants.Grant, status string) error {
	if grant.Notifier == nil {
		return nil
	}
	return s.updateNotifierStatus(ctx, *grant.Notifier, status)
}

func (s *Server) updateNotifierStatus(ctx context.Context, ref bknotify.MessageRef, status string) error {
	if s.notifier == nil {
		return nil
	}
	return s.notifier.UpdateStatus(ctx, ref, status)
}

func pendingExpiredStatusForGrant(grant grants.Grant) string {
	if grant.ExpiredFrom == grants.StatusPending {
		return "⌛ Expired. Request was not approved in time."
	}
	return "⌛ Expired. Access window ended."
}

func grantUseStatus(grant grants.Grant) string {
	maxUses := grant.MaxUses
	if maxUses <= 0 {
		maxUses = 1
	}
	if grant.Status == grants.StatusConsumed {
		return "✅ Used. Access is now closed."
	}
	if grant.Status == grants.StatusExpired {
		return "✅ Used. Access is now closed."
	}
	heldUses := grant.ReservedCount
	remaining := maxUses - grant.UsedCount - heldUses
	if remaining < 0 {
		remaining = 0
	}
	if heldUses > 0 {
		if heldUses == 1 {
			return fmt.Sprintf("✅ Used %d of %d. 1 use is held; %d uses remain.", grant.UsedCount, maxUses, remaining)
		}
		return fmt.Sprintf("✅ Used %d of %d. %d uses are held; %d uses remain.", grant.UsedCount, maxUses, heldUses, remaining)
	}
	return fmt.Sprintf("✅ Used %d of %d. %d uses remain.", grant.UsedCount, maxUses, remaining)
}

func retainedGrantReservationStatus(grant grants.Grant) string {
	maxUses := grant.MaxUses
	if maxUses <= 0 {
		maxUses = 1
	}
	if grant.Status == grants.StatusExpired {
		return "⚠️ Push result is ambiguous. Access is closed; operator review is still needed."
	}
	heldUses := grant.UsedCount + grant.ReservedCount
	if heldUses <= grant.UsedCount {
		heldUses = grant.UsedCount + 1
	}
	if maxUses == 1 {
		return "⚠️ Push result is ambiguous. Access is closed until an operator reviews it."
	}
	if heldUses == 1 {
		return fmt.Sprintf("⚠️ Push result is ambiguous. 1 of %d uses is held; access is closed until an operator reviews it.", maxUses)
	}
	return fmt.Sprintf("⚠️ Push result is ambiguous. %d of %d uses are held; access is closed until an operator reviews it.", heldUses, maxUses)
}

func readLimited(r io.Reader, limit int64) ([]byte, bool, error) {
	var buf bytes.Buffer
	_, err := io.CopyN(&buf, r, limit+1)
	if err == nil {
		return buf.Bytes()[:limit], true, nil
	}
	if errors.Is(err, io.EOF) {
		return buf.Bytes(), false, nil
	}
	return nil, false, err
}

func (s *Server) forward(w http.ResponseWriter, r *http.Request, rt route, body []byte, bodyRead bool) (int, error) {
	if actionID := r.URL.Query().Get(lfsActionQuery); actionID != "" {
		action, ok := s.lookupLFSAction(actionID)
		if !ok || !sameRoute(action.route, rt) {
			writePlain(w, http.StatusForbidden, "hf-broker: "+errInvalidLFSAction.Error()+"\n")
			return 0, errInvalidLFSAction
		}
		return s.forwardToURL(w, r, rt, action.url, body, bodyRead, action.headers, s.lfsActionNeedsHFToken(action.url, rt))
	}
	upstreamURL := s.upstreamRequestURL(r, rt)
	return s.forwardToURL(w, r, rt, upstreamURL, body, bodyRead, nil, true)
}

func (s *Server) lfsActionNeedsHFToken(rawURL string, rt route) bool {
	parsed, err := url.Parse(rawURL)
	if err != nil {
		return false
	}
	repoPath := joinURLPath(s.upstream.Path, upstreamRepoPath(rt))
	return parsed.Scheme == s.upstream.Scheme &&
		parsed.Host == s.upstream.Host &&
		(parsed.Path == repoPath || strings.HasPrefix(parsed.Path, repoPath+"/"))
}

func (s *Server) forwardToURL(w http.ResponseWriter, r *http.Request, rt route, upstreamURL string, body []byte, bodyRead bool, extraHeaders http.Header, injectHFToken bool) (int, error) {
	req, err := s.newForwardRequest(r, upstreamURL, body, bodyRead, extraHeaders, injectHFToken)
	if err != nil {
		return 0, err
	}
	resp, err := s.httpClient.Do(req)
	if err != nil {
		return 0, err
	}
	defer func() {
		_ = resp.Body.Close()
	}()
	return s.writeForwardResponse(w, r, rt, resp)
}

func (s *Server) forwardReceivePack(w http.ResponseWriter, r *http.Request, rt route, push gitproxy.ReceivePackRequest, body []byte) (int, bool, string, bool, error) {
	req, err := s.newForwardRequest(r, s.upstreamRequestURL(r, rt), body, true, nil, true)
	if err != nil {
		return 0, false, "", false, err
	}
	resp, err := s.httpClient.Do(req)
	if err != nil {
		return 0, false, "", false, err
	}
	defer func() {
		_ = resp.Body.Close()
	}()
	responseBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return 0, false, "", false, err
	}
	accepted, reason, definitiveReject := receivePackAccepted(push, resp.StatusCode, responseBody)
	_ = writeBufferedResponse(w, resp, responseBody)
	return resp.StatusCode, accepted, reason, definitiveReject, nil
}

func receivePackAccepted(push gitproxy.ReceivePackRequest, statusCode int, body []byte) (bool, string, bool) {
	if statusCode < 200 || statusCode >= 300 {
		return false, fmt.Sprintf("upstream returned HTTP %d", statusCode), httpReceivePackRejectionDefinitive(statusCode)
	}
	accepted, reason, err := gitproxy.ReceivePackAccepted(push, body)
	if err != nil {
		return false, "could not parse upstream receive-pack report", false
	}
	return accepted, reason, false
}

func httpReceivePackRejectionDefinitive(statusCode int) bool {
	switch statusCode {
	case http.StatusUnauthorized, http.StatusForbidden, http.StatusNotFound, http.StatusMethodNotAllowed, http.StatusRequestEntityTooLarge, http.StatusUnsupportedMediaType:
		return true
	default:
		return false
	}
}

func writeBufferedResponse(w http.ResponseWriter, resp *http.Response, body []byte) error {
	copyResponseHeaders(w.Header(), resp.Header)
	w.WriteHeader(resp.StatusCode)
	_, err := w.Write(body)
	return err
}

func (s *Server) newForwardRequest(r *http.Request, upstreamURL string, body []byte, bodyRead bool, extraHeaders http.Header, injectHFToken bool) (*http.Request, error) {
	var reader io.Reader
	if bodyRead {
		reader = bytes.NewReader(body)
	} else if r.Body != nil {
		reader = r.Body
	}
	req, err := http.NewRequestWithContext(r.Context(), r.Method, upstreamURL, reader)
	if err != nil {
		return nil, err
	}
	copyForwardHeaders(req.Header, r.Header)
	copyHeaders(req.Header, extraHeaders, func(string) bool { return false })
	if injectHFToken {
		req.Header.Set("Authorization", "Basic "+base64.StdEncoding.EncodeToString([]byte("x-access-token:"+s.hfToken)))
	}
	setForwardContentLength(req, r, body, bodyRead)
	return req, nil
}

func setForwardContentLength(req, original *http.Request, body []byte, bodyRead bool) {
	if bodyRead {
		req.ContentLength = int64(len(body))
		return
	}
	if original.ContentLength >= 0 {
		req.ContentLength = original.ContentLength
	}
}

func (s *Server) writeForwardResponse(w http.ResponseWriter, r *http.Request, rt route, resp *http.Response) (int, error) {
	copyResponseHeaders(w.Header(), resp.Header)
	if shouldRewriteLFSBatchResponse(r, rt, resp.StatusCode) {
		body, err := s.rewriteLFSBatchResponse(r, rt, resp.Body)
		if err != nil {
			return resp.StatusCode, err
		}
		w.Header().Del("Content-Length")
		w.WriteHeader(resp.StatusCode)
		_, writeErr := w.Write(body)
		return resp.StatusCode, writeErr
	}
	w.WriteHeader(resp.StatusCode)
	_, copyErr := io.Copy(w, resp.Body)
	return resp.StatusCode, copyErr
}

func shouldRewriteLFSBatchResponse(r *http.Request, rt route, statusCode int) bool {
	return statusCode >= 200 && statusCode < 300 && r.Method == http.MethodPost && rt.tail == "info/lfs/objects/batch"
}

func (s *Server) rewriteLFSBatchResponse(r *http.Request, rt route, body io.Reader) ([]byte, error) {
	decoder := json.NewDecoder(body)
	decoder.UseNumber()
	var payload map[string]any
	if err := decoder.Decode(&payload); err != nil {
		return nil, fmt.Errorf("could not sanitize LFS batch response: %w", err)
	}
	s.rewriteLFSBatchActions(r, rt, payload)
	return json.Marshal(payload)
}

func (s *Server) rewriteLFSBatchActions(r *http.Request, rt route, payload map[string]any) {
	objects, ok := payload["objects"].([]any)
	if !ok {
		return
	}
	for _, rawObject := range objects {
		object, ok := rawObject.(map[string]any)
		if !ok {
			continue
		}
		s.rewriteLFSObjectActions(r, rt, object)
	}
}

func (s *Server) rewriteLFSObjectActions(r *http.Request, rt route, object map[string]any) {
	oid, _ := object["oid"].(string)
	size, _ := lfsObjectSizeString(object["size"])
	actions, ok := object["actions"].(map[string]any)
	if !ok {
		return
	}
	for name, rawAction := range actions {
		action, ok := rawAction.(map[string]any)
		if !ok {
			delete(actions, name)
			continue
		}
		actionID, ok := s.registerLFSAction(rt, oid, size, name, action)
		if !ok {
			delete(actions, name)
			continue
		}
		href, ok := brokerLFSActionHref(r, rt, oid, size, name, actionID)
		if !ok {
			delete(actions, name)
			continue
		}
		action["href"] = href
		delete(action, "header")
	}
}

func (s *Server) registerLFSAction(rt route, oid, size, name string, action map[string]any) (string, bool) {
	href, ok := action["href"].(string)
	if !ok {
		return "", false
	}
	parsed, err := url.Parse(href)
	if err != nil || parsed.Scheme == "" || parsed.Host == "" {
		return "", false
	}
	actionRoute, ok := brokerLFSActionRoute(rt, oid, size, name)
	if !ok {
		return "", false
	}
	id, err := randomLFSActionID()
	if err != nil {
		return "", false
	}
	s.lfsMu.Lock()
	defer s.lfsMu.Unlock()
	s.pruneExpiredLFSActions(time.Now())
	s.lfsActions[id] = lfsAction{url: href, headers: parseLFSActionHeaders(action["header"]), route: actionRoute, created: time.Now()}
	return id, true
}

func (s *Server) lookupLFSAction(id string) (lfsAction, bool) {
	s.lfsMu.Lock()
	defer s.lfsMu.Unlock()
	action, ok := s.lfsActions[id]
	if !ok || time.Since(action.created) > lfsActionTTL {
		delete(s.lfsActions, id)
		return lfsAction{}, false
	}
	return action, true
}

func (s *Server) pruneExpiredLFSActions(now time.Time) {
	for id, action := range s.lfsActions {
		if now.Sub(action.created) > lfsActionTTL {
			delete(s.lfsActions, id)
		}
	}
}

func randomLFSActionID() (string, error) {
	var raw [16]byte
	if _, err := rand.Read(raw[:]); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(raw[:]), nil
}

func parseLFSActionHeaders(value any) http.Header {
	headers := http.Header{}
	rawHeaders, ok := value.(map[string]any)
	if !ok {
		return headers
	}
	for key, rawValue := range rawHeaders {
		if value, ok := rawValue.(string); ok {
			headers.Set(key, value)
		}
	}
	return headers
}

func lfsObjectSizeString(value any) (string, bool) {
	switch v := value.(type) {
	case json.Number:
		return v.String(), isDecimal(v.String())
	case string:
		return v, isDecimal(v)
	default:
		return "", false
	}
}

func brokerLFSActionHref(r *http.Request, rt route, oid, size, action, actionID string) (string, bool) {
	actionRoute, ok := brokerLFSActionRoute(rt, oid, size, action)
	if !ok {
		return "", false
	}
	u := url.URL{Scheme: brokerRequestScheme(r), Host: brokerRequestHost(r), Path: joinURLPath("", upstreamRepoPath(actionRoute)+"/"+actionRoute.tail)}
	q := u.Query()
	q.Set(lfsActionQuery, actionID)
	u.RawQuery = q.Encode()
	return u.String(), true
}

func brokerLFSActionRoute(rt route, oid, size, action string) (route, bool) {
	if !isLFSOID(oid) {
		return route{}, false
	}
	tail := "info/lfs/objects/" + oid
	switch action {
	case "download":
	case "upload":
		if !isDecimal(size) {
			return route{}, false
		}
		tail += "/" + size
	case "verify":
		tail += "/verify"
	default:
		return route{}, false
	}
	return route{repoType: rt.repoType, owner: rt.owner, name: rt.name, tail: tail}, true
}

func sameRoute(a, b route) bool {
	return a.repoType == b.repoType && a.owner == b.owner && a.name == b.name && a.tail == b.tail
}

func brokerRequestScheme(r *http.Request) string {
	forwardedProto := r.Header.Get("X-Forwarded-Proto")
	if forwardedProto == "http" || forwardedProto == "https" {
		return forwardedProto
	}
	if r.TLS != nil {
		return "https"
	}
	return "http"
}

func brokerRequestHost(r *http.Request) string {
	if r.Host != "" {
		return r.Host
	}
	return r.URL.Host
}

func (s *Server) upstreamRequestURL(r *http.Request, rt route) string {
	u := *s.upstream
	u.Path = joinURLPath(s.upstream.Path, upstreamRepoPath(rt)+"/"+rt.tail)
	u.RawQuery = r.URL.RawQuery
	return u.String()
}

func (s *Server) upstreamRepoURL(rt route) string {
	u := *s.upstream
	u.Path = joinURLPath(s.upstream.Path, upstreamRepoPath(rt))
	u.RawQuery = ""
	return u.String()
}

func upstreamRepoPath(rt route) string {
	var repoPath string
	switch rt.repoType {
	case policy.TypeDataset:
		repoPath = "/datasets/" + rt.owner + "/" + rt.name + ".git"
	case policy.TypeSpace:
		repoPath = "/spaces/" + rt.owner + "/" + rt.name + ".git"
	default:
		repoPath = "/" + rt.owner + "/" + rt.name + ".git"
	}
	return repoPath
}

func joinURLPath(basePath, requestPath string) string {
	return strings.TrimRight(basePath, "/") + "/" + strings.TrimLeft(requestPath, "/")
}

func copyForwardHeaders(dst, src http.Header) {
	copyHeaders(dst, src, skipRequestHeader)
}

func copyResponseHeaders(dst, src http.Header) {
	copyHeaders(dst, src, skipResponseHeader)
}

func copyHeaders(dst, src http.Header, skip func(string) bool) {
	for key, values := range src {
		if skip(key) {
			continue
		}
		for _, value := range values {
			dst.Add(key, value)
		}
	}
}

func skipRequestHeader(key string) bool {
	switch strings.ToLower(key) {
	case "accept-encoding", "authorization", "proxy-authorization", "cookie", "connection", "proxy-connection", "keep-alive", "te", "trailer", "transfer-encoding", "upgrade":
		return true
	default:
		return false
	}
}

func skipResponseHeader(key string) bool {
	switch strings.ToLower(key) {
	case "connection", "proxy-connection", "keep-alive", "te", "trailer", "transfer-encoding", "upgrade", "set-cookie", "set-cookie2":
		return true
	default:
		return false
	}
}

func writePlain(w http.ResponseWriter, status int, message string) {
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.WriteHeader(status)
	_, _ = w.Write([]byte(message))
}

func writeJSON(w http.ResponseWriter, status int, payload any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(payload)
}

func targetName(rt route) string {
	return string(rt.repoType) + "/" + rt.owner + "/" + rt.name
}

func (s *Server) record(client, operation, target, decision, reason string, upstreamStatus int) {
	s.recordAudit(audit.Entry{
		Client:         client,
		Operation:      operation,
		Target:         target,
		Decision:       decision,
		Reason:         reason,
		UpstreamStatus: upstreamStatus,
	})
}

func (s *Server) recordGrantUsed(client, operation, target string, upstreamStatus int, grantIDs []string) {
	s.recordAudit(audit.Entry{
		Client:              client,
		Operation:           operation,
		Target:              target,
		Decision:            audit.DecisionGrantUsed,
		Reason:              "operator grant used",
		UpstreamStatus:      upstreamStatus,
		MatchedGrantRuleIDs: grantIDs,
		GrantID:             firstString(grantIDs),
	})
}

func (s *Server) recordPolicyDecision(client, operation, target, decision, reason string, upstreamStatus int, policyDecision policy.Decision) {
	s.recordAudit(audit.Entry{
		Client:                client,
		Operation:             operation,
		Target:                target,
		Decision:              decision,
		Reason:                reason,
		UpstreamStatus:        upstreamStatus,
		MatchedDenyRuleIDs:    policyDecision.MatchedDenyRuleIDs,
		MatchedGrantRuleIDs:   policyDecision.MatchedGrantRuleIDs,
		MatchedAllowRuleIDs:   policyDecision.MatchedAllowRuleIDs,
		MatchedRequestRuleIDs: policyDecision.MatchedRequestRuleIDs,
		GrantID:               policyDecision.GrantID,
	})
}

func (s *Server) recordAudit(entry audit.Entry) {
	s.audit.Record(entry)
}

func firstString(values []string) string {
	if len(values) == 0 {
		return ""
	}
	return values[0]
}

// HealthClientTimeout is exported only for tests that need a stable
// short timeout without depending on config defaults.
const HealthClientTimeout = 2 * time.Second
