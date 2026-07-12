// Package executorserver validates and executes one-shot sudo plans.
package executorserver

import (
	"context"
	"errors"
	"net"
	"time"

	"github.com/osolmaz/brokerkit/brokers/sudo/internal/catalog"
	"github.com/osolmaz/brokerkit/brokers/sudo/internal/executorprotocol"
	"github.com/osolmaz/brokerkit/brokers/sudo/internal/hostcheck"
	"github.com/osolmaz/brokerkit/brokers/sudo/internal/plan"
	"github.com/osolmaz/brokerkit/plandigest"
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
	now := cfg.Now
	if now == nil {
		now = time.Now
	}
	requestTimeout := cfg.RequestTimeout
	if requestTimeout <= 0 {
		requestTimeout = 10 * time.Second
	}
	maxConnections := cfg.MaxConnections
	if maxConnections <= 0 {
		maxConnections = defaultMaxConnections
	}
	if maxConnections > 1024 {
		return nil, errors.New("executor maximum connections is too large")
	}
	return &Server{catalog: cfg.Catalog, identities: cfg.Identities, runner: cfg.Runner, state: state,
		expectedPeerUID: cfg.ExpectedPeerUID, brokerUID: cfg.BrokerUID, peerUID: cfg.PeerUID, now: now, requestTimeout: requestTimeout,
		connections: make(chan struct{}, maxConnections)}, nil
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
	if !request.ExpiresAt.After(now) {
		return executorprotocol.NewRejected("request_expired")
	}
	if plandigest.Digest(request.Plan) != request.PlanDigest {
		return executorprotocol.NewRejected("plan_digest_mismatch")
	}
	value, err := plan.DecodeCanonical(request.Plan)
	if err != nil {
		return executorprotocol.NewRejected("invalid_plan")
	}
	existing, found, err := s.state.lookup(request.ExecutionID, request.PlanDigest, request.GrantID, request.ReservationID)
	if errors.Is(err, errExecutionConflict) {
		return executorprotocol.NewRejected("execution_id_conflict")
	}
	if err != nil {
		return executorprotocol.NewRejected("state_unavailable")
	}
	if found {
		if existing.Status == executionComplete && existing.Outcome != nil {
			return executorprotocol.NewCompleted(request.ExecutionID, *existing.Outcome)
		}
		return executorprotocol.NewAmbiguous(request.ExecutionID, "execution_incomplete")
	}
	if request.ExpiresAt.Sub(now) > time.Duration(value.RequestedDurationSeconds)*time.Second {
		return executorprotocol.NewRejected("invalid_expiry")
	}
	if err := plan.ValidateForHelper(value, s.catalog, s.identities); err != nil {
		return executorprotocol.NewRejected("plan_drift")
	}
	if err := hostcheck.ValidateExecution(value, s.brokerUID); err != nil {
		return executorprotocol.NewRejected("unsafe_host_path")
	}
	record, claimed, err := s.state.claim(request.ExecutionID, request.PlanDigest, request.GrantID, request.ReservationID)
	if errors.Is(err, errExecutionConflict) {
		return executorprotocol.NewRejected("execution_id_conflict")
	}
	if err != nil {
		return executorprotocol.NewRejected("state_unavailable")
	}
	if !claimed {
		if record.Status == executionComplete && record.Outcome != nil {
			return executorprotocol.NewCompleted(request.ExecutionID, *record.Outcome)
		}
		return executorprotocol.NewAmbiguous(request.ExecutionID, "execution_incomplete")
	}
	if err := s.state.markStarted(request.ExecutionID); err != nil {
		return executorprotocol.NewAmbiguous(request.ExecutionID, "state_unavailable")
	}
	deadline := request.ExpiresAt
	commandDeadline := now.Add(time.Duration(value.TimeoutSeconds) * time.Second)
	if commandDeadline.Before(deadline) {
		deadline = commandDeadline
	}
	runCtx, cancel := context.WithDeadline(ctx, deadline)
	outcome, runErr := s.runner.Run(runCtx, value)
	cancel()
	if runErr != nil && !outcome.Started {
		outcome = executorprotocol.Outcome{Started: false}
	}
	if err := s.state.complete(request.ExecutionID, outcome); err != nil {
		return executorprotocol.NewAmbiguous(request.ExecutionID, "result_unavailable")
	}
	return executorprotocol.NewCompleted(request.ExecutionID, outcome)
}
