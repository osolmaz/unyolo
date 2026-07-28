// Package executorserver validates and executes one-shot sudo plans.
package executorserver

import (
	"context"
	"errors"
	"net"
	"time"

	"github.com/osolmaz/unyolo/brokers/sudo/internal/catalog"
	"github.com/osolmaz/unyolo/brokers/sudo/internal/executorprotocol"
	"github.com/osolmaz/unyolo/brokers/sudo/internal/hostcheck"
	"github.com/osolmaz/unyolo/brokers/sudo/internal/plan"
	"github.com/osolmaz/unyolo/internal/clockx"
	"github.com/osolmaz/unyolo/operation/digest"
)

const defaultMaxConnections = 32

type Runner interface {
	Run(context.Context, plan.Plan) (executorprotocol.Outcome, error)
}

type PeerUID func(*net.UnixConn) (uint32, error)

type Config struct {
	Catalog         *catalog.Snapshot
	Identities      plan.IdentityResolver
	Runner          Runner
	StatePath       string
	ExpectedPeerUID uint32
	BrokerUID       uint32
	PeerUID         PeerUID
	Now             func() time.Time
	RequestTimeout  time.Duration
	MaxConnections  int
}

type Server struct {
	catalog         *catalog.Snapshot
	identities      plan.IdentityResolver
	runner          Runner
	state           *executionState
	expectedPeerUID uint32
	brokerUID       uint32
	peerUID         PeerUID
	now             func() time.Time
	requestTimeout  time.Duration
	connections     chan struct{}
}

func New(cfg Config) (*Server, error) {
	if cfg.Catalog == nil || cfg.Identities == nil || cfg.Runner == nil || cfg.PeerUID == nil {
		return nil, errors.New("executor server dependencies are required")
	}
	state, err := newExecutionState(cfg.StatePath, cfg.Now)
	if err != nil {
		return nil, err
	}
	now := clockx.OrNow(cfg.Now)
	requestTimeout := serverRequestTimeout(cfg.RequestTimeout)
	maxConnections, err := serverMaxConnections(cfg.MaxConnections)
	if err != nil {
		return nil, errors.New("executor maximum connections is too large")
	}
	return &Server{catalog: cfg.Catalog, identities: cfg.Identities, runner: cfg.Runner, state: state,
		expectedPeerUID: cfg.ExpectedPeerUID, brokerUID: cfg.BrokerUID, peerUID: cfg.PeerUID, now: now, requestTimeout: requestTimeout,
		connections: make(chan struct{}, maxConnections)}, nil
}

func serverRequestTimeout(value time.Duration) time.Duration {
	if value > 0 {
		return value
	}
	return 10 * time.Second
}

func serverMaxConnections(value int) (int, error) {
	if value <= 0 {
		value = defaultMaxConnections
	}
	if value > 1024 {
		return 0, errors.New("too large")
	}
	return value, nil
}

func (s *Server) Serve(ctx context.Context, listener *net.UnixListener) error {
	if listener == nil {
		return errors.New("executor Unix listener is required")
	}
	go func() {
		<-ctx.Done()
		_ = listener.Close()
	}()
	for {
		connection, err := listener.AcceptUnix()
		if err != nil {
			if ctx.Err() != nil {
				return nil //nolint:nilerr // listener closure is the expected context-cancellation path.
			}
			return err
		}
		select {
		case s.connections <- struct{}{}:
			go func() {
				defer func() { <-s.connections }()
				s.handleConnection(ctx, connection)
			}()
		default:
			_ = connection.SetWriteDeadline(time.Now().Add(time.Second))
			_ = executorprotocol.WriteResponse(connection, executorprotocol.NewRejected("server_busy"))
			_ = connection.Close()
		}
	}
}

func (s *Server) handleConnection(ctx context.Context, connection *net.UnixConn) {
	defer func() { _ = connection.Close() }()
	_ = connection.SetDeadline(time.Now().Add(s.requestTimeout))
	response := s.Handle(ctx, connection)
	_ = executorprotocol.WriteResponse(connection, response)
}

func (s *Server) Handle(ctx context.Context, connection *net.UnixConn) executorprotocol.Response {
	uid, err := s.peerUID(connection)
	if err != nil || !knownPeer(uid, s.expectedPeerUID) {
		return executorprotocol.NewRejected("peer_not_authorized")
	}
	request, err := executorprotocol.ReadRequest(connection)
	if err != nil {
		return executorprotocol.NewRejected("invalid_request")
	}
	if request.Type == executorprotocol.TypePing {
		return executorprotocol.Response{Version: executorprotocol.Version, Status: executorprotocol.StatusReady}
	}
	if !peerMayExecute(uid, s.expectedPeerUID) {
		return executorprotocol.NewRejected("peer_not_authorized")
	}
	return s.execute(ctx, request)
}

func knownPeer(uid uint32, expected uint32) bool { return uid == expected || uid == 0 }

func peerMayExecute(uid uint32, expected uint32) bool { return uid == expected }

func (s *Server) execute(ctx context.Context, request executorprotocol.Request) executorprotocol.Response {
	now := s.now().UTC()
	if rejection := validateRequestEnvelope(request, now); rejection != "" {
		return executorprotocol.NewRejected(rejection)
	}
	value, err := plan.DecodeCanonical(request.Plan)
	if err != nil {
		return executorprotocol.NewRejected("invalid_plan")
	}
	existing, found, rejection := s.lookupExistingExecution(request)
	if rejection != "" {
		return executorprotocol.NewRejected(rejection)
	}
	if found {
		return executionReplayResponse(request.ExecutionID, existing)
	}
	if rejection := s.validateExecutableRequest(request, value, now); rejection != "" {
		return executorprotocol.NewRejected(rejection)
	}
	return s.executeFresh(ctx, request, value, now)
}

func (s *Server) executeFresh(ctx context.Context, request executorprotocol.Request, value plan.Plan, now time.Time) executorprotocol.Response {
	record, claimed, rejection := s.claimExecution(request)
	if rejection != "" {
		return executorprotocol.NewRejected(rejection)
	}
	if !claimed {
		return executionReplayResponse(request.ExecutionID, record)
	}
	if err := s.state.markStarted(request.ExecutionID); err != nil {
		return executorprotocol.NewAmbiguous(request.ExecutionID, "state_unavailable")
	}
	outcome := s.runClaimedExecution(ctx, request, value, now)
	if err := s.state.complete(request.ExecutionID, outcome); err != nil {
		return executorprotocol.NewAmbiguous(request.ExecutionID, "result_unavailable")
	}
	return executorprotocol.NewCompleted(request.ExecutionID, outcome)
}

func validateRequestEnvelope(request executorprotocol.Request, now time.Time) string {
	if !request.ExpiresAt.After(now) {
		return "request_expired"
	}
	if plandigest.Digest(request.Plan) != request.PlanDigest {
		return "plan_digest_mismatch"
	}
	return ""
}

func (s *Server) validateExecutableRequest(request executorprotocol.Request, value plan.Plan, now time.Time) string {
	if request.ExpiresAt.Sub(now) > time.Duration(value.RequestedDurationSeconds)*time.Second {
		return "invalid_expiry"
	}
	if err := plan.ValidateForHelper(value, s.catalog, s.identities); err != nil {
		return "plan_drift"
	}
	if err := hostcheck.ValidateExecution(value, s.brokerUID); err != nil {
		return "unsafe_host_path"
	}
	return ""
}

func (s *Server) lookupExistingExecution(request executorprotocol.Request) (executionRecord, bool, string) {
	return executionStateResult(s.state.lookup(request.ExecutionID, request.PlanDigest, request.GrantID, request.ReservationID))
}

func (s *Server) claimExecution(request executorprotocol.Request) (executionRecord, bool, string) {
	return executionStateResult(s.state.claim(request.ExecutionID, request.PlanDigest, request.GrantID, request.ReservationID))
}

func executionStateResult(record executionRecord, current bool, err error) (executionRecord, bool, string) {
	if errors.Is(err, errExecutionConflict) {
		return executionRecord{}, false, "execution_id_conflict"
	}
	if err != nil {
		return executionRecord{}, false, "state_unavailable"
	}
	return record, current, ""
}

func executionReplayResponse(executionID string, record executionRecord) executorprotocol.Response {
	if record.Status == executionComplete && record.Outcome != nil {
		return executorprotocol.NewCompleted(executionID, *record.Outcome)
	}
	return executorprotocol.NewAmbiguous(executionID, "execution_incomplete")
}

func (s *Server) runClaimedExecution(ctx context.Context, request executorprotocol.Request, value plan.Plan, now time.Time) executorprotocol.Outcome {
	runCtx, cancel := context.WithDeadline(ctx, commandDeadline(request.ExpiresAt, value.TimeoutSeconds, now))
	outcome, runErr := s.runner.Run(runCtx, value)
	cancel()
	if runErr != nil && !outcome.Started {
		return executorprotocol.Outcome{Started: false}
	}
	return outcome
}

func commandDeadline(requestDeadline time.Time, timeoutSeconds uint32, now time.Time) time.Time {
	commandDeadline := now.Add(time.Duration(timeoutSeconds) * time.Second)
	if commandDeadline.Before(requestDeadline) {
		return commandDeadline
	}
	return requestDeadline
}
