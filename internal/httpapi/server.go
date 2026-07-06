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
	"net/http"
	"net/url"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/osolmaz/hf-broker/internal/audit"
	"github.com/osolmaz/hf-broker/internal/auth"
	"github.com/osolmaz/hf-broker/internal/config"
	"github.com/osolmaz/hf-broker/internal/gitproxy"
	"github.com/osolmaz/hf-broker/internal/grants"
	"github.com/osolmaz/hf-broker/internal/mirror"
	"github.com/osolmaz/hf-broker/internal/notify"
	"github.com/osolmaz/hf-broker/internal/scope"
)

const defaultUpstreamBase = "https://huggingface.co"

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
	errGrantNotificationStillQueued = errors.New("grant notification is still being created")
	errGrantNotificationCanceled    = errors.New("grant notification was canceled")
)

// Options configures a broker HTTP server.
type Options struct {
	Config          config.Config
	Scope           scope.Scope
	Audit           *audit.Logger
	UpstreamBaseURL string
	Context         context.Context
	GrantNotifier   GrantNotifier
	TelegramBaseURL string
}

// Server is an http.Handler for the broker.
type Server struct {
	auth       *auth.Authenticator
	scope      scope.Scope
	audit      *audit.Logger
	mirrors    *mirror.Manager
	upstream   *url.URL
	httpClient *http.Client
	hfToken    string
	maxBody    int64
	grants     *grants.Store
	notifier   GrantNotifier

	lfsMu      sync.Mutex
	lfsActions map[string]lfsAction
}

// GrantNotifier sends pending grants to an operator approval channel.
type GrantNotifier interface {
	SendGrantRequest(context.Context, notify.GrantMessage) (notify.MessageRef, error)
}

type GrantStatusNotifier interface {
	UpdateGrantStatus(context.Context, notify.MessageRef, string) error
}

type route struct {
	repoType scope.RepoType
	owner    string
	name     string
	tail     string
}

type classifiedRequest struct {
	route     route
	operation scope.Operation
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
	clients := map[string]string{}
	for _, client := range opts.Config.Clients {
		clients[client.Name] = client.Secret
	}
	auditLogger := opts.Audit
	if auditLogger == nil {
		auditLogger = audit.New(io.Discard)
	}
	server := newServer(opts, upstream, clients, auditLogger)
	server.startTelegram(ctx, opts)
	if opts.Config.TelegramBotToken != "" {
		server.startGrantNotificationSweeper(ctx)
	}
	return server, nil
}

func parseUpstreamBase(upstreamBase string) (*url.URL, error) {
	if upstreamBase == "" {
		upstreamBase = defaultUpstreamBase
	}
	upstream, err := url.Parse(upstreamBase)
	if err != nil || upstream.Scheme == "" || upstream.Host == "" {
		return nil, fmt.Errorf("invalid upstream base URL %q", upstreamBase)
	}
	return upstream, nil
}

func newServer(opts Options, upstream *url.URL, clients map[string]string, auditLogger *audit.Logger) *Server {
	return &Server{
		auth:       auth.New(clients),
		scope:      opts.Scope,
		audit:      auditLogger,
		mirrors:    mirror.New(opts.Config.StateDir, opts.Config.HFToken, opts.Config.HFTimeout),
		upstream:   upstream,
		httpClient: &http.Client{Timeout: opts.Config.HFTimeout},
		hfToken:    opts.Config.HFToken,
		maxBody:    opts.Config.MaxPackBytes,
		grants: grants.New(filepath.Join(opts.Config.StateDir, "grants", "grants.json"), grants.Options{
			ReservationTimeout: grantReservationTimeout(opts.Config.HFTimeout),
		}),
		notifier:   opts.GrantNotifier,
		lfsActions: map[string]lfsAction{},
	}
}

func grantReservationTimeout(hfTimeout time.Duration) time.Duration {
	if hfTimeout <= 0 {
		return grants.DefaultReservationTimeout
	}
	return hfTimeout + grantReservationGrace
}

func (s *Server) startTelegram(ctx context.Context, opts Options) {
	if opts.Config.TelegramBotToken != "" {
		telegram := notify.NewTelegram(opts.Config.TelegramBotToken, opts.Config.TelegramChatID, nil, opts.TelegramBaseURL)
		s.notifier = telegram
		go telegram.Poll(ctx, s.handleTelegramDecision)
	}
}

// ServeHTTP routes one broker request.
func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if writeHealth(w, r) {
		return
	}
	client, ok := s.authenticate(w, r)
	if !ok {
		return
	}
	s.serveAuthenticated(w, r, client)
}

func (s *Server) serveAuthenticated(w http.ResponseWriter, r *http.Request, client string) {
	if r.URL.Path == "/grants" {
		s.handleGrantRequest(w, r, client)
		return
	}
	classified, status, reason := s.classify(r)
	if reason != "" {
		writePlain(w, status, "hf-broker: "+reason+"\n")
		s.record(client, "unknown", "", audit.DecisionRefused, reason, 0)
		return
	}
	target := targetName(classified.route)
	decision := s.scope.DecideRepo(classified.route.repoType, classified.route.owner, classified.route.name, classified.operation)
	if !decision.Allowed {
		writePlain(w, http.StatusForbidden, "hf-broker: "+decision.Reason+"\n")
		s.record(client, string(classified.operation), target, audit.DecisionRefused, decision.Reason, 0)
		return
	}
	if classified.operation == scope.OpGitPush && r.Method == http.MethodPost && classified.route.tail == "git-receive-pack" {
		s.handleReceivePack(w, r, client, classified.route, target)
		return
	}
	s.handleForward(w, r, client, classified, target)
}

func (s *Server) handleForward(w http.ResponseWriter, r *http.Request, client string, classified classifiedRequest, target string) {
	statusCode, err := s.forward(w, r, classified.route, classified.body, classified.bodyRead)
	if errors.Is(err, errInvalidLFSAction) {
		s.record(client, string(classified.operation), target, audit.DecisionRefused, errInvalidLFSAction.Error(), statusCode)
		return
	}
	if err != nil {
		writePlain(w, http.StatusBadGateway, "hf-broker: upstream request failed\n")
		s.record(client, string(classified.operation), target, audit.DecisionRefused, "upstream request failed", statusCode)
		return
	}
	s.record(client, string(classified.operation), target, audit.DecisionAllowed, "", statusCode)
}

func writeHealth(w http.ResponseWriter, r *http.Request) bool {
	if r.Method != http.MethodGet || r.URL.Path != "/healthz" {
		return false
	}
	w.Header().Set("Content-Type", "application/json")
	_, _ = w.Write([]byte(`{"ok": true}`))
	return true
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

type grantRequestBody struct {
	Operation       string `json:"operation"`
	Target          string `json:"target"`
	Ref             string `json:"ref"`
	Reason          string `json:"reason"`
	Minutes         int    `json:"minutes"`
	MaxUses         int    `json:"max_uses"`
	ClientRequestID string `json:"client_request_id"`
}

type grantResponseBody struct {
	ID               string `json:"id"`
	Status           string `json:"status"`
	PendingExpiresAt string `json:"pending_expires_at"`
	Minutes          int    `json:"minutes"`
	MaxUses          int    `json:"max_uses"`
	UsedCount        int    `json:"used_count"`
}

func (s *Server) handleGrantRequest(w http.ResponseWriter, r *http.Request, client string) {
	if !s.acceptGrantRequestRoute(w, r, client) {
		return
	}
	req, ok := s.readGrantRequest(w, r, client)
	if !ok {
		return
	}
	rt, status, reason := s.validateGrantRequest(req)
	if reason != "" {
		writePlain(w, status, "hf-broker: "+reason+"\n")
		s.record(client, "grant_request", grantRequestAuditTarget(rt), audit.DecisionRefused, reason, 0)
		return
	}
	grant, _, err := s.requestGrant(client, req, rt)
	if err != nil {
		writePlain(w, http.StatusBadRequest, "hf-broker: "+err.Error()+"\n")
		s.record(client, "grant_request", targetName(rt), audit.DecisionRefused, err.Error(), 0)
		return
	}
	if grantNeedsNotification(grant) {
		var notified bool
		grant, notified = s.notifyGrantIfClaimed(w, r, client, grant)
		if !notified {
			return
		}
	}
	writeJSON(w, http.StatusAccepted, grantResponseBody{
		ID:               grant.ID,
		Status:           string(grant.Status),
		PendingExpiresAt: grant.PendingExpiresAt.Format(time.RFC3339),
		Minutes:          grant.RequestedMinutes,
		MaxUses:          grant.MaxUses,
		UsedCount:        grant.UsedCount,
	})
	s.record(client, "grant_request", grant.Target, audit.DecisionAllowed, "pending", 0)
}

func grantNeedsNotification(grant grants.Grant) bool {
	return grant.Status == grants.StatusPending && grant.Notifier == nil
}

func (s *Server) acceptGrantRequestRoute(w http.ResponseWriter, r *http.Request, client string) bool {
	if r.Method != http.MethodPost {
		writePlain(w, http.StatusMethodNotAllowed, "hf-broker: unsupported grant route\n")
		s.record(client, "grant_request", "", audit.DecisionRefused, "unsupported grant route", 0)
		return false
	}
	if s.notifier == nil {
		writePlain(w, http.StatusServiceUnavailable, "hf-broker: approval channel is not configured\n")
		s.record(client, "grant_request", "", audit.DecisionRefused, "approval channel is not configured", 0)
		return false
	}
	return true
}

func (s *Server) notifyCreatedGrant(w http.ResponseWriter, r *http.Request, client string, grant grants.Grant) (grants.Grant, bool) {
	messageRef, err := s.notifier.SendGrantRequest(r.Context(), grantMessage(grant))
	if err != nil {
		return s.rejectGrantNotificationIfClaimed(w, r, client, grant, "could not notify operator")
	}
	updated, recorded, err := s.grants.SetNotifierIfClaimed(grant.ID, grant.NotifierClaimedAt, grantNotifierMessage(messageRef))
	if err != nil {
		return s.rejectGrantNotificationIfClaimed(w, r, client, grant, "could not record operator notification")
	}
	if recorded {
		return updated, true
	}
	return s.resolveStaleGrantNotification(w, r, client, grant, updated, messageRef)
}

func (s *Server) resolveStaleGrantNotification(w http.ResponseWriter, r *http.Request, client string, grant, updated grants.Grant, messageRef notify.MessageRef) (grants.Grant, bool) {
	s.supersedeGrantMessage(r.Context(), messageRef)
	return s.resolvePendingGrantNotification(w, r, client, grant, updated)
}

func (s *Server) notifyGrantIfClaimed(w http.ResponseWriter, r *http.Request, client string, grant grants.Grant) (grants.Grant, bool) {
	claimedGrant, claimed, err := s.grants.ClaimNotifier(grant.ID, grantNotificationClaimLease)
	if err != nil {
		writePlain(w, http.StatusBadGateway, "hf-broker: could not notify operator\n")
		s.record(client, "grant_request", grant.Target, audit.DecisionRefused, "could not claim operator notification", 0)
		return grants.Grant{}, false
	}
	if !claimed {
		return s.resolvePendingGrantNotification(w, r, client, grant, claimedGrant)
	}
	return s.notifyCreatedGrant(w, r, client, claimedGrant)
}

func (s *Server) writeGrantNotificationWaitError(w http.ResponseWriter, client string, grant grants.Grant, err error) {
	status := http.StatusBadGateway
	reason := "could not notify operator"
	if errors.Is(err, errGrantNotificationStillQueued) {
		status = http.StatusConflict
		reason = "operator notification is still being created"
	}
	writePlain(w, status, "hf-broker: "+reason+"\n")
	s.record(client, "grant_request", grant.Target, audit.DecisionRefused, reason, 0)
}

func (s *Server) rejectGrantNotificationIfClaimed(w http.ResponseWriter, r *http.Request, client string, grant grants.Grant, reason string) (grants.Grant, bool) {
	updated, canceled, err := s.grants.CancelIfNotifierClaimed(grant.ID, grant.NotifierClaimedAt)
	if err != nil {
		writePlain(w, http.StatusBadGateway, "hf-broker: could not notify operator\n")
		s.record(client, "grant_request", grant.Target, audit.DecisionRefused, reason, 0)
		return grants.Grant{}, false
	}
	if canceled || updated.Status == grants.StatusCanceled {
		writePlain(w, http.StatusBadGateway, "hf-broker: could not notify operator\n")
		s.record(client, "grant_request", grant.Target, audit.DecisionRefused, reason, 0)
		return grants.Grant{}, false
	}
	return s.resolvePendingGrantNotification(w, r, client, grant, updated)
}

func (s *Server) resolvePendingGrantNotification(w http.ResponseWriter, r *http.Request, client string, original, current grants.Grant) (grants.Grant, bool) {
	if !grantNeedsNotification(current) {
		return current, true
	}
	return s.waitForGrantNotificationResponse(w, r, client, original, current.ID)
}

func (s *Server) waitForGrantNotificationResponse(w http.ResponseWriter, r *http.Request, client string, grant grants.Grant, id string) (grants.Grant, bool) {
	resolved, err := s.waitForGrantNotification(r.Context(), id)
	if err != nil {
		s.writeGrantNotificationWaitError(w, client, grant, err)
		return grants.Grant{}, false
	}
	return resolved, true
}

func (s *Server) supersedeGrantMessage(ctx context.Context, ref notify.MessageRef) {
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
			if grant.Status == grants.StatusCanceled {
				return grants.Grant{}, errGrantNotificationCanceled
			}
			if !grantNeedsNotification(grant) {
				return grant, nil
			}
		}
	}
}

func (s *Server) validateGrantRequest(req grantRequestBody) (route, int, string) {
	rt, status, reason := validateGrantRequestShape(req)
	if reason != "" {
		return rt, status, reason
	}
	policy, ok := s.repoGrantUsePolicy(rt, scope.Operation(req.Operation))
	if !ok {
		return rt, http.StatusForbidden, "git grants are not enabled for operation"
	}
	if status, reason := validateGrantPolicyBounds(req, policy); reason != "" {
		return rt, status, reason
	}
	decision := s.scope.DecideRepo(rt.repoType, rt.owner, rt.name, scope.OpGitPush)
	if !decision.Allowed {
		return rt, http.StatusForbidden, decision.Reason
	}
	return rt, 0, ""
}

func validateGrantRequestShape(req grantRequestBody) (route, int, string) {
	rt, ok := parseGrantTarget(req.Target)
	operation := scope.Operation(req.Operation)
	if !ok || !gitproxy.ValidRefName(req.Ref) || !isGitGrantOperation(operation) || !grantRefMatchesOperation(operation, req.Ref) {
		return rt, http.StatusBadRequest, "invalid grant request"
	}
	if req.Minutes < 0 {
		return rt, http.StatusBadRequest, "grant duration must be positive"
	}
	if req.MaxUses < 0 {
		return rt, http.StatusBadRequest, "grant max uses must be positive"
	}
	return rt, 0, ""
}

func isGitGrantOperation(operation scope.Operation) bool {
	switch operation {
	case scope.OpGitHistoryRewrite, scope.OpGitRefDelete, scope.OpGitTagUpdate:
		return true
	default:
		return false
	}
}

func grantRefMatchesOperation(operation scope.Operation, ref string) bool {
	switch operation {
	case scope.OpGitHistoryRewrite:
		return !isTagRef(ref) && !isReplaceRef(ref)
	case scope.OpGitRefDelete:
		return !isTagRef(ref) && !isReplaceRef(ref)
	case scope.OpGitTagUpdate:
		return isTagRef(ref)
	default:
		return false
	}
}

func validateGrantPolicyBounds(req grantRequestBody, policy scope.GrantUsePolicy) (int, string) {
	if req.Minutes > policy.MaxMinutes {
		return http.StatusBadRequest, fmt.Sprintf("grant duration exceeds %d minutes", policy.MaxMinutes)
	}
	if req.MaxUses > policy.MaxUses {
		return http.StatusBadRequest, fmt.Sprintf("grant max uses exceeds %d", policy.MaxUses)
	}
	return 0, ""
}

func (s *Server) requestGrant(client string, req grantRequestBody, rt route) (grants.Grant, bool, error) {
	policy, ok := s.repoGrantUsePolicy(rt, scope.Operation(req.Operation))
	if !ok {
		return grants.Grant{}, false, errors.New("git grants are not enabled for operation")
	}
	minutes := req.Minutes
	if minutes == 0 {
		minutes = policy.DefaultMinutes
	}
	maxUses := req.MaxUses
	if maxUses == 0 {
		maxUses = policy.DefaultMaxUses
	}
	return s.grants.Request(grants.Request{
		Client:            client,
		ClientRequestID:   req.ClientRequestID,
		Operation:         req.Operation,
		Target:            targetName(rt),
		Ref:               req.Ref,
		Reason:            req.Reason,
		RequestedDuration: time.Duration(minutes) * time.Minute,
		MaxUses:           maxUses,
	})
}

func (s *Server) repoGrantUsePolicy(rt route, operation scope.Operation) (scope.GrantUsePolicy, bool) {
	repo, ok := s.scope.Repo(rt.repoType, rt.owner, rt.name)
	if !ok {
		return scope.GrantUsePolicy{}, false
	}
	var policy *scope.GrantUsePolicy
	switch operation {
	case scope.OpGitHistoryRewrite:
		policy = repo.GrantPolicy.GitHistoryRewrite
	case scope.OpGitRefDelete:
		policy = repo.GrantPolicy.GitRefDelete
	case scope.OpGitTagUpdate:
		policy = repo.GrantPolicy.GitTagUpdate
	default:
		return scope.GrantUsePolicy{}, false
	}
	if policy == nil {
		return scope.GrantUsePolicy{}, false
	}
	return *policy, true
}

func grantRequestAuditTarget(rt route) string {
	if rt.owner != "" && rt.name != "" {
		return targetName(rt)
	}
	return ""
}

func (s *Server) readGrantRequest(w http.ResponseWriter, r *http.Request, client string) (grantRequestBody, bool) {
	body, tooLarge, err := readLimited(r.Body, 4096)
	if err != nil {
		writePlain(w, http.StatusBadRequest, "hf-broker: could not read grant request\n")
		s.record(client, "grant_request", "", audit.DecisionRefused, "could not read grant request", 0)
		return grantRequestBody{}, false
	}
	if tooLarge {
		writePlain(w, http.StatusRequestEntityTooLarge, "hf-broker: grant request is too large\n")
		s.record(client, "grant_request", "", audit.DecisionRefused, "grant request is too large", 0)
		return grantRequestBody{}, false
	}
	decoder := json.NewDecoder(bytes.NewReader(body))
	decoder.DisallowUnknownFields()
	var req grantRequestBody
	if err := decoder.Decode(&req); err != nil {
		writePlain(w, http.StatusBadRequest, "hf-broker: could not parse grant request\n")
		s.record(client, "grant_request", "", audit.DecisionRefused, "could not parse grant request", 0)
		return grantRequestBody{}, false
	}
	var trailing struct{}
	if err := decoder.Decode(&trailing); err != io.EOF {
		writePlain(w, http.StatusBadRequest, "hf-broker: could not parse grant request\n")
		s.record(client, "grant_request", "", audit.DecisionRefused, "could not parse grant request", 0)
		return grantRequestBody{}, false
	}
	return req, true
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

func grantRepoType(value string) (scope.RepoType, bool) {
	switch value {
	case string(scope.TypeModel):
		return scope.TypeModel, true
	case string(scope.TypeDataset):
		return scope.TypeDataset, true
	case string(scope.TypeSpace):
		return scope.TypeSpace, true
	default:
		return "", false
	}
}

func invalidGrantTargetSegment(value string) bool {
	return value == "" || strings.ContainsAny(value, " \t\r\n/")
}

func grantMessage(grant grants.Grant) notify.GrantMessage {
	return notify.GrantMessage{
		ID:               grant.ID,
		DecisionToken:    grant.DecisionToken,
		Client:           grant.Client,
		Operation:        grant.Operation,
		Target:           grant.Target,
		Ref:              grant.Ref,
		Reason:           grant.Reason,
		RequestedMinutes: grant.RequestedMinutes,
		MaxUses:          grant.MaxUses,
		PendingExpiresAt: grant.PendingExpiresAt,
	}
}

func grantNotifierMessage(ref notify.MessageRef) grants.NotifierMessage {
	return grants.NotifierMessage{Kind: ref.Kind, ChatID: ref.ChatID, MessageID: ref.MessageID, Text: ref.Text}
}

func notifyMessageRef(message *grants.NotifierMessage) notify.MessageRef {
	if message == nil {
		return notify.MessageRef{}
	}
	return notify.MessageRef{Kind: message.Kind, ChatID: message.ChatID, MessageID: message.MessageID, Text: message.Text}
}

func (s *Server) handleTelegramDecision(_ context.Context, decision notify.Decision) notify.DecisionResult {
	actor := telegramActor(decision)
	switch decision.Action {
	case notify.DecisionApprove:
		approved, err := s.grants.Approve(decision.ID, decision.Token, actor)
		if err != nil {
			return notify.DecisionResult{Answer: grantDecisionAnswer(err)}
		}
		return notify.DecisionResult{Answer: "Grant approved", ActiveExpiresAt: approved.ExpiresAt}
	case notify.DecisionDeny:
		if _, err := s.grants.Deny(decision.ID, decision.Token, actor); err != nil {
			return notify.DecisionResult{Answer: grantDecisionAnswer(err)}
		}
		return notify.DecisionResult{Answer: "Grant denied"}
	default:
		return notify.DecisionResult{Answer: "Grant decision ignored"}
	}
}

func telegramActor(decision notify.Decision) string {
	if decision.OperatorTag != "" {
		return "telegram:@" + decision.OperatorTag
	}
	return fmt.Sprintf("telegram:%d", decision.OperatorID)
}

func grantDecisionAnswer(err error) string {
	switch {
	case errors.Is(err, grants.ErrNotFound):
		return "Grant not found"
	case errors.Is(err, grants.ErrInvalidDecisionToken):
		return "Grant decision token did not match"
	case errors.Is(err, grants.ErrNotPending):
		return "Grant is no longer pending"
	default:
		return "Grant decision failed"
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
	return classifiedRequest{route: rt, operation: op, body: body, bodyRead: bodyRead}, 0, ""
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

func routePrefix(firstSegment string) (scope.RepoType, int) {
	switch firstSegment {
	case "datasets":
		return scope.TypeDataset, 1
	case "spaces":
		return scope.TypeSpace, 1
	default:
		return scope.TypeModel, 0
	}
}

func classifyOperation(r *http.Request, rt route) (scope.Operation, []byte, bool, int, string) {
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

func classifyInfoRefs(service string) (scope.Operation, []byte, bool, int, string) {
	return classifyGitService(service, "unsupported git service")
}

func classifyGitPost(tail string) (scope.Operation, []byte, bool, int, string) {
	return classifyGitService(tail, "unsupported git route")
}

func classifyGitService(value, unsupported string) (scope.Operation, []byte, bool, int, string) {
	switch value {
	case "git-upload-pack":
		return scope.OpGitFetch, nil, false, 0, ""
	case "git-receive-pack":
		return scope.OpGitPush, nil, false, 0, ""
	default:
		return "", nil, false, http.StatusForbidden, unsupported
	}
}

func classifyLFS(r *http.Request, tail string) (scope.Operation, []byte, bool, int, string) {
	if r.Method == http.MethodPost && tail == "info/lfs/objects/batch" {
		return classifyLFSBatch(r)
	}
	if r.Method == http.MethodPost && tail == "info/lfs/locks/verify" {
		return scope.OpLFSDownload, nil, false, 0, ""
	}
	if isLFSObjectDownload(r.Method, tail) {
		return scope.OpLFSDownload, nil, false, 0, ""
	}
	if isLFSObjectUpload(r.Method, tail) {
		return scope.OpLFSUpload, nil, false, 0, ""
	}
	return "", nil, false, http.StatusForbidden, "unsupported LFS route"
}

func classifyLFSBatch(r *http.Request) (scope.Operation, []byte, bool, int, string) {
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

func classifyLFSOperation(operation string, body []byte) (scope.Operation, []byte, bool, int, string) {
	switch operation {
	case "download":
		return scope.OpLFSDownload, body, true, 0, ""
	case "upload":
		return scope.OpLFSUpload, body, true, 0, ""
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
	req, body, ok := s.readReceivePack(w, r, client, target)
	if !ok {
		return
	}
	repo := mirror.Repo{Kind: string(rt.repoType), Owner: rt.owner, Name: rt.name, UpstreamURL: s.upstreamRepoURL(rt)}
	upstreamStatus, lockErr := s.withLockedPush(w, r, rt, repo, req, body, client, target)
	if lockErr != nil {
		if upstreamStatus == 0 {
			writePlain(w, http.StatusForbidden, "hf-broker: push refused\n")
		}
		s.record(client, string(scope.OpGitPush), target, audit.DecisionRefused, "push enforcement failed: "+lockErr.Error(), upstreamStatus)
	}
}

func (s *Server) readReceivePack(w http.ResponseWriter, r *http.Request, client, target string) (gitproxy.ReceivePackRequest, []byte, bool) {
	body, tooLarge, err := readLimited(r.Body, s.maxBody)
	if err != nil {
		writePlain(w, http.StatusBadRequest, "hf-broker: could not read push\n")
		s.record(client, string(scope.OpGitPush), target, audit.DecisionRefused, "could not read push", 0)
		return gitproxy.ReceivePackRequest{}, nil, false
	}
	if tooLarge {
		writePlain(w, http.StatusRequestEntityTooLarge, "hf-broker: push pack exceeds configured limit\n")
		s.record(client, string(scope.OpGitPush), target, audit.DecisionRefused, "push pack exceeds configured limit", 0)
		return gitproxy.ReceivePackRequest{}, nil, false
	}
	req, err := gitproxy.ParseReceivePack(body)
	if err != nil {
		writePlain(w, http.StatusBadRequest, "hf-broker: could not parse push\n")
		s.record(client, string(scope.OpGitPush), target, audit.DecisionRefused, "could not parse push", 0)
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
	refused, usedGrants, err := s.refuseInvalidPush(w, r, req, mir, client, target)
	if err != nil || refused {
		return lockedPushResult{}, err
	}
	reservedGrants, err := s.reserveGrantUses(usedGrants)
	if err != nil {
		return lockedPushResult{}, err
	}
	return s.forwardReservedPush(w, r, rt, req, body, mir, client, target, usedGrants, reservedGrants)
}

func (s *Server) forwardReservedPush(w http.ResponseWriter, r *http.Request, rt route, req gitproxy.ReceivePackRequest, body []byte, mir *mirror.Repository, client, target string, usedGrants []grantUse, reservedGrants []grants.Grant) (lockedPushResult, error) {
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
		retainedGrants, err := s.handleRejectedReservedPush(client, target, reason, statusCode, definitiveReject, reservedGrants)
		result.retainedGrantsToNotify = retainedGrants
		return result, err
	}
	s.acceptReservedPush(req, mir, client, target, statusCode, usedGrants, reservedGrants, &result)
	return result, nil
}

func (s *Server) handleRejectedReservedPush(client, target, reason string, statusCode int, definitiveReject bool, reservedGrants []grants.Grant) ([]grants.Grant, error) {
	var retainedGrants []grants.Grant
	var err error
	if definitiveReject {
		s.releaseGrantUses(reservedGrants)
	} else {
		retainedGrants, err = s.retainGrantUseReservations(reservedGrants)
	}
	s.record(client, string(scope.OpGitPush), target, audit.DecisionRefused, reason, statusCode)
	return retainedGrants, err
}

func (s *Server) acceptReservedPush(req gitproxy.ReceivePackRequest, mir *mirror.Repository, client, target string, statusCode int, usedGrants []grantUse, reservedGrants []grants.Grant, result *lockedPushResult) {
	_ = gitproxy.AdvanceAccepted(context.Background(), req, mir)
	result.grantsToNotify = s.commitGrantUses(reservedGrants)
	decision := audit.DecisionAllowed
	auditReason := ""
	operation := string(scope.OpGitPush)
	if len(usedGrants) > 0 {
		decision = audit.DecisionGrantUsed
		auditReason = "operator grant used"
		operation = grantAuditOperation(usedGrants)
	}
	s.record(client, operation, target, decision, auditReason, statusCode)
}

func (s *Server) refuseInvalidPush(w http.ResponseWriter, r *http.Request, req gitproxy.ReceivePackRequest, mir *mirror.Repository, client, target string) (bool, []grantUse, error) {
	used := map[string]grantUse{}
	failures, err := gitproxy.CheckPushWithOverrides(r.Context(), req, mir, func(command gitproxy.Command, reason string) bool {
		operation, ok := grantOperationForPushFailure(command, reason)
		if !ok {
			return false
		}
		grant, ok, err := s.grants.MatchActive(client, string(operation), target, command.Ref)
		if err != nil || !ok {
			return false
		}
		used[grant.ID] = grantUse{grant: grant, ref: command.Ref}
		return true
	})
	if len(failures) > 0 {
		w.Header().Set("Content-Type", "application/x-git-receive-pack-result")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(gitproxy.BuildRefusalReport(req, failures))
		s.record(client, string(scope.OpGitPush), target, audit.DecisionRefused, failures[0].Reason, 0)
		return true, nil, nil
	}
	if err != nil {
		return false, nil, err
	}
	return false, grantUses(used), nil
}

func grantOperationForPushFailure(command gitproxy.Command, reason string) (scope.Operation, bool) {
	switch reason {
	case "history rewrite refused":
		return scope.OpGitHistoryRewrite, true
	case "deletion refused":
		if isReplaceRef(command.Ref) {
			return "", false
		}
		if isTagRef(command.Ref) {
			return scope.OpGitTagUpdate, true
		}
		return scope.OpGitRefDelete, true
	case "tag update refused":
		return scope.OpGitTagUpdate, true
	default:
		return "", false
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

func grantAuditOperation(used []grantUse) string {
	operation := used[0].grant.Operation
	for _, use := range used[1:] {
		if use.grant.Operation != operation {
			return string(scope.OpGitPush)
		}
	}
	return operation
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
	if s.grantStatusNotifier() == nil {
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
	if grant.Notifier == nil {
		return
	}
	status := grantUseStatus(grant)
	if err := s.updateGrantMessage(context.Background(), grant, status); err == nil {
		_ = s.grants.MarkNotifierStatus(grant.ID, grantMessageStatusKey(grant))
	}
}

func (s *Server) updateRetainedGrantReservationMessage(grant grants.Grant) {
	current, err := s.grants.RetainUse(grant.ID)
	if err != nil || current.Notifier == nil {
		return
	}
	if err := s.updateGrantMessage(context.Background(), current, retainedGrantReservationStatus(current)); err == nil {
		_ = s.grants.MarkNotifierStatus(current.ID, (grants.StatusUpdate{Grant: current, Status: grants.NotifierStatusReserved}).NotifierStatusKey())
	}
}

func (s *Server) updateGrantMessage(ctx context.Context, grant grants.Grant, status string) error {
	if grant.Notifier == nil {
		return nil
	}
	return s.updateNotifierStatus(ctx, notifyMessageRef(grant.Notifier), status)
}

func (s *Server) updateNotifierStatus(ctx context.Context, ref notify.MessageRef, status string) error {
	notifier := s.grantStatusNotifier()
	if notifier == nil {
		return nil
	}
	return notifier.UpdateGrantStatus(ctx, ref, status)
}

func (s *Server) grantStatusNotifier() GrantStatusNotifier {
	notifier, ok := s.notifier.(GrantStatusNotifier)
	if !ok {
		return nil
	}
	return notifier
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
	remaining := maxUses - heldUses
	if remaining < 0 {
		remaining = 0
	}
	if maxUses == 1 {
		return "⚠️ Push result is ambiguous. Access is closed until an operator reviews it."
	}
	return fmt.Sprintf("⚠️ Push result is ambiguous. %d of %d uses are held; %d uses remain.", heldUses, maxUses, remaining)
}

func grantMessageStatusKey(grant grants.Grant) string {
	if grant.Status == grants.StatusConsumed {
		return string(grants.StatusConsumed)
	}
	if grant.Status == grants.StatusExpired {
		return string(grants.NotifierStatusUsedExpired)
	}
	return string(grants.NotifierStatusUsed)
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
		return s.forwardToURL(w, r, rt, action.url, body, bodyRead, action.headers, false)
	}
	upstreamURL := s.upstreamRequestURL(r, rt)
	return s.forwardToURL(w, r, rt, upstreamURL, body, bodyRead, nil, true)
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
	case scope.TypeDataset:
		repoPath = "/datasets/" + rt.owner + "/" + rt.name + ".git"
	case scope.TypeSpace:
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
	s.audit.Record(audit.Entry{
		Client:         client,
		Operation:      operation,
		Target:         target,
		Decision:       decision,
		Reason:         reason,
		UpstreamStatus: upstreamStatus,
	})
}

// HealthClientTimeout is exported only for tests that need a stable
// short timeout without depending on config defaults.
const HealthClientTimeout = 2 * time.Second
