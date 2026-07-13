// Package routes assembles sudo-broker's unprivileged HTTP frontend.
package routes

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/labstack/echo/v4"
	"github.com/labstack/echo/v4/middleware"
	"github.com/osolmaz/brokerkit/agentapi"
	"github.com/osolmaz/brokerkit/agentops"
	"github.com/osolmaz/brokerkit/audit"
	"github.com/osolmaz/brokerkit/brokers/sudo/internal/catalog"
	"github.com/osolmaz/brokerkit/brokers/sudo/internal/executorclient"
	"github.com/osolmaz/brokerkit/brokers/sudo/internal/executorprotocol"
	"github.com/osolmaz/brokerkit/brokers/sudo/internal/plan"
	"github.com/osolmaz/brokerkit/brokers/sudo/internal/presenter"
	"github.com/osolmaz/brokerkit/brokers/sudo/internal/sudopolicy"
	"github.com/osolmaz/brokerkit/controlplane"
	"github.com/osolmaz/brokerkit/grants"
	"github.com/osolmaz/brokerkit/httpx"
	"github.com/osolmaz/brokerkit/notify"
	corepolicy "github.com/osolmaz/brokerkit/policy"
	"github.com/osolmaz/brokerkit/state"
)

const maxBodyBytes int64 = 32 * 1024

type DecisionPoller interface {
	Poll(context.Context, func(context.Context, notify.Decision) notify.DecisionResult)
}

type Options struct {
	Policy             *corepolicy.Policy
	Catalog            *catalog.Snapshot
	Database           *state.Database
	Identities         plan.IdentityResolver
	Helper             *executorclient.Client
	ClientSecrets      map[string]string
	OperatorSecrets    map[string]string
	Notifier           notify.Notifier
	Poller             DecisionPoller
	Audit              *audit.Writer
	Now                func() time.Time
	OperatorConfigured bool
}

type Server struct {
	echo               *echo.Echo
	control            *controlplane.Runtime
	policy             *corepolicy.Policy
	catalog            *catalog.Snapshot
	grants             *grants.Store
	plans              *plan.Store
	identities         plan.IdentityResolver
	helper             *executorclient.Client
	validator          plan.Validator
	notifier           notify.Notifier
	poller             DecisionPoller
	audit              *audit.Writer
	now                func() time.Time
	operatorConfigured bool
	requestMu          sync.Mutex
	database           *state.Database
	operations         *agentops.Store
	agentAPI           *agentapi.Handler
	lifecycleContext   context.Context
	lifecycleCancel    context.CancelFunc
	backgroundWorkers  sync.WaitGroup
	workerOnce         sync.Once
	closeOnce          sync.Once
	closeErr           error
}

func New(opts Options) (*Server, error) {
	if opts.Policy == nil || opts.Catalog == nil || opts.Database == nil || opts.Identities == nil || opts.Helper == nil {
		return nil, errors.New("sudo broker dependencies are required")
	}
	plans, err := plan.NewStore(opts.Database)
	if err != nil {
		return nil, err
	}
	now := opts.Now
	if now == nil {
		now = time.Now
	}
	grantStore := grants.NewDatabase(opts.Database, grants.Options{Now: now})
	validator := plan.Validator{Store: plans, Catalog: opts.Catalog, Identities: opts.Identities, Helper: opts.Helper}
	control, err := controlplane.New(controlplane.Options{
		Broker: "sudo-broker", Store: grantStore, ClientSecrets: opts.ClientSecrets, OperatorSecrets: opts.OperatorSecrets,
		Presenter: presenter.Presenter{Catalog: opts.Catalog}, ActivationValidator: validator, Audit: opts.Audit,
	})
	if err != nil {
		return nil, err
	}
	auditWriter := opts.Audit
	if auditWriter == nil {
		auditWriter = audit.New(io.Discard)
	}
	e := echo.New()
	e.HideBanner = true
	e.HidePort = true
	e.Use(middleware.Recover(), noStore)
	server := &Server{echo: e, control: control, policy: opts.Policy, catalog: opts.Catalog, grants: grantStore, plans: plans,
		identities: opts.Identities, helper: opts.Helper, validator: validator, notifier: opts.Notifier, poller: opts.Poller,
		audit: auditWriter, now: now, operatorConfigured: opts.OperatorConfigured || len(opts.OperatorSecrets) > 0,
		database: opts.Database, operations: agentops.New(opts.Database)}
	server.agentAPI, err = agentapi.New(agentapi.Options{Store: server.operations, Authenticate: control.Clients.AuthenticateHeader,
		Submit: server.submitAgentOperation, Cancel: server.cancelAgentOperation, Realm: "sudo-broker"})
	if err != nil {
		return nil, err
	}
	server.registerRoutes()
	return server, nil
}

func (s *Server) Handler() http.Handler { return s.echo }

func (s *Server) OperatorHandler() http.Handler { return s.control.OperatorHandler }

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

func (s *Server) Start(ctx context.Context) {
	s.startOperationWorker(ctx)
	if s.poller != nil {
		go s.poller.Poll(ctx, s.control.HandleDecision)
	}
}

func (s *Server) registerRoutes() {
	s.agentAPI.Register(s.echo)
	s.echo.GET("/healthz", func(c echo.Context) error { return c.JSON(http.StatusOK, map[string]bool{"ok": true}) })
	s.echo.GET("/readyz", s.readiness)
}

func noStore(next echo.HandlerFunc) echo.HandlerFunc {
	return func(c echo.Context) error {
		httpx.NoStore(c.Response().Header())
		return next(c)
	}
}

func (s *Server) readiness(c echo.Context) error {
	if err := s.helper.Ready(c.Request().Context()); err != nil {
		return c.JSON(http.StatusServiceUnavailable, map[string]bool{"ok": false})
	}
	return c.JSON(http.StatusOK, map[string]bool{"ok": true})
}

type commandInput struct {
	CommandID  string                     `json:"command_id"`
	TargetUser string                     `json:"target_user"`
	Arguments  map[string]json.RawMessage `json:"arguments"`
}

func (s *Server) classify(client string, input commandInput) (catalog.Resolved, corepolicy.Request, error) {
	resolved, err := s.catalog.Resolve(strings.TrimSpace(input.CommandID), strings.TrimSpace(input.TargetUser), input.Arguments)
	if err != nil {
		return catalog.Resolved{}, corepolicy.Request{}, err
	}
	return resolved, sudopolicy.Request(client, resolved), nil
}

func (s *Server) notifyRequest(ctx context.Context, result grants.RequestResult) (grants.Grant, error) {
	grant := result.Grant
	if grant.Notification != nil || grant.Status != grants.StatusPending || s.notifier == nil {
		return grant, nil
	}
	claim, claimed, err := s.grants.ClaimNotification(grant.ID, 2*time.Minute)
	if err != nil {
		return grants.Grant{}, echo.NewHTTPError(http.StatusServiceUnavailable, "approval notification could not be claimed")
	}
	if !claimed {
		return s.grants.Get(grant.ID)
	}
	commandID := corepolicy.FirstValue(grant.Attrs[sudopolicy.AttrCommandID])
	target := corepolicy.FirstValue(grant.Target.Fields[sudopolicy.TargetName])
	ref, err := s.notifier.SendApproval(ctx, notify.ApprovalMessage{
		GrantID: claim.Grant.ID, DecisionToken: claim.DecisionToken,
		Text:   fmt.Sprintf("Approval needed for sudo-broker\n\n%s requests %s once as %s.", grant.Client, commandID, target),
		Client: grant.Client, Operation: grant.Operation, Target: target, Reason: grant.Reason,
		RequestedMinutes: int(grant.Duration / time.Minute), MaxUses: 1,
		Fields: []notify.Field{{Name: "command", Value: commandID}, {Name: "target user", Value: target}},
	})
	if err != nil || ref.MessageID <= 0 {
		if s.operatorConfigured {
			stored, _, retainErr := s.grants.RetainNotificationClaim(grant.ID, claim.Grant.NotificationClaimedAt)
			if retainErr == nil {
				return stored, nil
			}
		}
		_, _, _ = s.grants.CancelIfNotificationClaimed(grant.ID, claim.Grant.NotificationClaimedAt)
		return grants.Grant{}, echo.NewHTTPError(http.StatusServiceUnavailable, "operator could not be notified")
	}
	stored, recorded, err := s.grants.SetNotificationIfClaimed(grant.ID, claim.Grant.NotificationClaimedAt, ref)
	if err != nil || !recorded {
		return grants.Grant{}, echo.NewHTTPError(http.StatusServiceUnavailable, "approval notification could not be recorded")
	}
	return stored, nil
}

func grantBounds(policy *corepolicy.GrantPolicy, minutes int) (time.Duration, time.Duration, error) {
	if policy.Mode != string(corepolicy.GrantModeExecution) || policy.DefaultMaxUses != 1 || policy.MaxUses != 1 {
		return 0, 0, errors.New("sudo command policy must use one-shot execution grants")
	}
	if minutes == 0 {
		minutes = policy.DefaultMinutes
	}
	if minutes < 1 || minutes > policy.MaxMinutes {
		return 0, 0, errors.New("requested duration exceeds policy bounds")
	}
	return time.Duration(minutes) * time.Minute, time.Duration(policy.RequestTTLMinutes) * time.Minute, nil
}

func executionView(response executorprotocol.Response) map[string]any {
	outcome := response.Outcome
	return map[string]any{
		"id": response.ExecutionID, "started": outcome.Started, "exit_code": outcome.ExitCode, "signal": outcome.Signal,
		"timed_out": outcome.TimedOut, "truncated": outcome.Truncated, "duration_ns": outcome.Duration.Nanoseconds(),
		"stdout_base64": base64.StdEncoding.EncodeToString(outcome.Stdout), "stderr_base64": base64.StdEncoding.EncodeToString(outcome.Stderr),
	}
}

func (s *Server) record(request corepolicy.Request, decision string, reason string, grantID string, rules []string) {
	_ = s.audit.Record(audit.Event{Broker: "sudo-broker", Client: request.Client, Operation: request.Operation,
		Target: corepolicy.FirstValue(request.Target.Fields[sudopolicy.TargetName]), Decision: decision, Reason: reason,
		MatchedRuleIDs: rules, GrantID: grantID, Attrs: map[string]string{"command_id": corepolicy.FirstValue(request.Attrs[sudopolicy.AttrCommandID])}})
}
