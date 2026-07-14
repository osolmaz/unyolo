// Package routes assembles sudo-broker's unprivileged HTTP frontend.
package routes

import (
	"context"
	"errors"
	"net/http"
	"sync"
	"time"

	"github.com/labstack/echo/v4"
	"github.com/labstack/echo/v4/middleware"
	"github.com/osolmaz/brokerkit/admission"
	"github.com/osolmaz/brokerkit/agentapi"
	"github.com/osolmaz/brokerkit/agentops"
	"github.com/osolmaz/brokerkit/audit"
	bkauthorization "github.com/osolmaz/brokerkit/authorization"
	"github.com/osolmaz/brokerkit/brokers/sudo/internal/catalog"
	"github.com/osolmaz/brokerkit/brokers/sudo/internal/executorclient"
	"github.com/osolmaz/brokerkit/brokers/sudo/internal/operations"
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
	Admission          admission.Config
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
	database           *state.Database
	operations         *agentops.Store
	admission          *admission.Controller
	authorization      *bkauthorization.Coordinator
	operationRegistry  *operations.Registry
	operationRuntime   *operations.Runtime
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
	if opts.Audit == nil {
		return nil, errors.New("audit recorder is required")
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
	operationRegistry, err := operations.NewRegistry(opts.Catalog, opts.Helper)
	if err != nil {
		return nil, err
	}
	authorization, err := bkauthorization.New(bkauthorization.Options{Registry: sudopolicy.Registry(opts.Catalog),
		Decide: opts.Policy.Decide, Grants: grantStore, Now: now})
	if err != nil {
		return nil, err
	}
	control, err := controlplane.New(controlplane.Options{
		Broker: "sudo-broker", Store: grantStore, ClientSecrets: opts.ClientSecrets, OperatorSecrets: opts.OperatorSecrets,
		Presenter: presenter.Presenter{Catalog: opts.Catalog}, ActivationValidator: validator, Audit: opts.Audit,
	})
	if err != nil {
		return nil, err
	}
	e := echo.New()
	e.HideBanner = true
	e.HidePort = true
	e.Use(middleware.Recover(), noStore)
	operationStore := agentops.New(opts.Database)
	admissionController, err := admission.NewConfigured(secretNames(opts.ClientSecrets), opts.Admission, operationStore.AdmissionUsage)
	if err != nil {
		return nil, err
	}
	admissionController.SetObserver(control.Metrics)
	server := &Server{echo: e, control: control, policy: opts.Policy, catalog: opts.Catalog, grants: grantStore, plans: plans,
		identities: opts.Identities, helper: opts.Helper, validator: validator, notifier: opts.Notifier, poller: opts.Poller,
		audit: opts.Audit, now: now, operatorConfigured: opts.OperatorConfigured || len(opts.OperatorSecrets) > 0,
		database: opts.Database, operations: operationStore, admission: admissionController, authorization: authorization, operationRegistry: operationRegistry}
	server.operationRuntime, err = server.newOperationRuntime()
	if err != nil {
		return nil, err
	}
	server.agentAPI, err = agentapi.New(agentapi.Options{Store: server.operations, Authenticate: control.Clients.AuthenticateHeader,
		Submit: server.submitAgentOperation, Cancel: server.cancelAgentOperation, Realm: "sudo-broker"})
	if err != nil {
		return nil, err
	}
	server.registerRoutes()
	return server, nil
}

func secretNames(values map[string]string) []string {
	names := make([]string, 0, len(values))
	for name := range values {
		names = append(names, name)
	}
	return names
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
		if s.operationRuntime != nil {
			s.operationRuntime.Wait()
		}
		s.backgroundWorkers.Wait()
		s.closeErr = s.database.Close()
	})
	return s.closeErr
}

func (s *Server) Start(ctx context.Context) {
	s.startOperationRuntime(ctx)
	if s.poller != nil {
		s.backgroundWorkers.Add(1)
		go func() {
			defer s.backgroundWorkers.Done()
			s.poller.Poll(s.lifecycleContext, s.control.HandleDecision)
		}()
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

func (s *Server) record(request corepolicy.Request, decision string, reason string, grantID string, rules []string) {
	_ = s.audit.Record(audit.Event{Broker: "sudo-broker", Client: request.Client, Operation: request.Operation,
		Target: corepolicy.FirstValue(request.Target.Fields[sudopolicy.TargetName]), Decision: decision, Reason: reason,
		MatchedRuleIDs: rules, GrantID: grantID, Attrs: map[string]string{"command_id": corepolicy.FirstValue(request.Attrs[sudopolicy.AttrCommandID])}})
}
