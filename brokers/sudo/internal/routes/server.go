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
	"github.com/osolmaz/brokerkit/agent/api"
	"github.com/osolmaz/brokerkit/agent/runtime"
	"github.com/osolmaz/brokerkit/approval"
	"github.com/osolmaz/brokerkit/approval/notification"
	"github.com/osolmaz/brokerkit/approval/notifier"
	bkauthorization "github.com/osolmaz/brokerkit/authorization"
	"github.com/osolmaz/brokerkit/authorization/admission"
	"github.com/osolmaz/brokerkit/authorization/grants"
	corepolicy "github.com/osolmaz/brokerkit/authorization/policy"
	"github.com/osolmaz/brokerkit/broker/controlplane"
	"github.com/osolmaz/brokerkit/brokers/sudo/internal/catalog"
	"github.com/osolmaz/brokerkit/brokers/sudo/internal/executorclient"
	"github.com/osolmaz/brokerkit/brokers/sudo/internal/operations"
	"github.com/osolmaz/brokerkit/brokers/sudo/internal/plan"
	"github.com/osolmaz/brokerkit/brokers/sudo/internal/presenter"
	"github.com/osolmaz/brokerkit/brokers/sudo/internal/sudopolicy"
	"github.com/osolmaz/brokerkit/internal/clockx"
	"github.com/osolmaz/brokerkit/internal/slicex"
	"github.com/osolmaz/brokerkit/internal/storage/state"
	"github.com/osolmaz/brokerkit/telemetry/audit"
	"github.com/osolmaz/brokerkit/transport/http"
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
	Notifier           approvalnotify.Notifier
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
	notifier           approvalnotify.Notifier
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
	backgroundOnce     sync.Once
	closeOnce          sync.Once
	closeErr           error
}

func New(opts Options) (*Server, error) {
	if err := validateOptions(opts); err != nil {
		return nil, err
	}
	parts, err := newServerParts(opts)
	if err != nil {
		return nil, err
	}
	server := assembleServer(opts, parts)
	server.operationRuntime, err = server.newOperationRuntime()
	if err != nil {
		return nil, err
	}
	server.agentAPI, err = agentapi.New(agentapi.Options{Store: server.operations, Authenticate: server.control.Clients.AuthenticateHeader,
		Submit: server.submitAgentOperation, Cancel: server.cancelAgentOperation, Realm: "sudo-broker"})
	if err != nil {
		return nil, err
	}
	server.registerRoutes()
	return server, nil
}

type serverParts struct {
	echo              *echo.Echo
	plans             *plan.Store
	grantStore        *grants.Store
	validator         plan.Validator
	operationRegistry *operations.Registry
	authorization     *bkauthorization.Coordinator
	control           *controlplane.Runtime
	operationStore    *agentops.Store
	admission         *admission.Controller
	now               func() time.Time
}

func validateOptions(opts Options) error {
	if err := validateRequiredDependencies(opts); err != nil {
		return err
	}
	return validateRequiredAudit(opts)
}

func validateRequiredDependencies(opts Options) error {
	if opts.Policy == nil || opts.Catalog == nil || opts.Database == nil || opts.Identities == nil || opts.Helper == nil {
		return errors.New("sudo broker dependencies are required")
	}
	return nil
}

func validateRequiredAudit(opts Options) error {
	if opts.Audit == nil {
		return errors.New("audit recorder is required")
	}
	return nil
}

func newServerParts(opts Options) (serverParts, error) {
	plans, err := plan.NewStore(opts.Database)
	if err != nil {
		return serverParts{}, err
	}
	now := clockx.OrNow(opts.Now)
	grantStore := grants.NewDatabase(opts.Database, grants.Options{Now: now})
	validator := plan.Validator{Store: plans, Catalog: opts.Catalog, Identities: opts.Identities, Helper: opts.Helper}
	operationRegistry, err := operations.NewRegistry(opts.Catalog, opts.Helper)
	if err != nil {
		return serverParts{}, err
	}
	authorization, err := bkauthorization.New(bkauthorization.Options{Registry: sudopolicy.Registry(opts.Catalog),
		Decide: opts.Policy.Decide, Grants: grantStore, Now: now})
	if err != nil {
		return serverParts{}, err
	}
	control, err := controlplane.New(controlplane.Options{
		Broker: "sudo-broker", ApprovalBroker: "sudo", Store: grantStore, ClientSecrets: opts.ClientSecrets, OperatorSecrets: opts.OperatorSecrets,
		Presenter: presenter.Presenter{Catalog: opts.Catalog}, ActivationValidator: validator, Audit: opts.Audit, State: opts.Database,
	})
	if err != nil {
		return serverParts{}, err
	}
	e := echo.New()
	e.HideBanner = true
	e.HidePort = true
	e.Use(middleware.Recover(), noStore)
	operationStore := agentops.New(opts.Database)
	admissionController, err := admission.NewConfigured(slicex.Keys(opts.ClientSecrets), opts.Admission, operationStore.AdmissionUsage)
	if err != nil {
		return serverParts{}, err
	}
	admissionController.SetObserver(control.Metrics)
	return serverParts{echo: e, plans: plans, grantStore: grantStore, validator: validator, operationRegistry: operationRegistry,
		authorization: authorization, control: control, operationStore: operationStore, admission: admissionController, now: now}, nil
}

func assembleServer(opts Options, parts serverParts) *Server {
	return &Server{echo: parts.echo, control: parts.control, policy: opts.Policy, catalog: opts.Catalog, grants: parts.grantStore, plans: parts.plans,
		identities: opts.Identities, helper: opts.Helper, validator: parts.validator, notifier: opts.Notifier, poller: opts.Poller,
		audit: opts.Audit, now: parts.now, operatorConfigured: opts.OperatorConfigured || len(opts.OperatorSecrets) > 0,
		database: opts.Database, operations: parts.operationStore, admission: parts.admission, authorization: parts.authorization,
		operationRegistry: parts.operationRegistry}
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
	s.backgroundOnce.Do(func() {
		s.startDecisionPoller()
		s.startNotificationSweeper()
	})
}

func (s *Server) startDecisionPoller() {
	if s.poller == nil {
		return
	}
	s.backgroundWorkers.Add(1)
	go func() {
		defer s.backgroundWorkers.Done()
		s.poller.Poll(s.lifecycleContext, s.control.HandleDecision)
	}()
}

func (s *Server) startNotificationSweeper() {
	if s.notifier == nil {
		return
	}
	s.backgroundWorkers.Add(1)
	go func() {
		defer s.backgroundWorkers.Done()
		s.runNotificationSweeper(s.lifecycleContext)
	}()
}

func (s *Server) runNotificationSweeper(ctx context.Context) {
	s.deliverNotificationStatusUpdates(ctx)
	ticker := time.NewTicker(10 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			s.deliverNotificationStatusUpdates(ctx)
		}
	}
}

func (s *Server) deliverNotificationStatusUpdates(ctx context.Context) {
	updates, err := s.grants.StatusUpdatesDue()
	if err != nil {
		return
	}
	for _, update := range updates {
		if update.Grant.Notification == nil {
			continue
		}
		if err := s.notifier.UpdateStatus(ctx, *update.Grant.Notification, approval.StatusForUpdate(update)); err != nil {
			continue
		}
		_ = s.grants.MarkNotificationStatus(update.Grant.ID, update.NotificationStatusKey())
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
