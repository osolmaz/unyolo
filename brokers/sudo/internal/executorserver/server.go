// Package executorserver validates and executes one-shot sudo plans.
package executorserver

import (
	"context"
	"errors"
	"net"
	"time"

	"github.com/osolmaz/brokerkit/brokers/sudo/internal/catalog"
	"github.com/osolmaz/brokerkit/brokers/sudo/internal/executorprotocol"
	"github.com/osolmaz/brokerkit/brokers/sudo/internal/plan"
	"github.com/osolmaz/brokerkit/planstore"
)

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
	PeerUID         PeerUID
	Now             func() time.Time
	RequestTimeout  time.Duration
}

type Server struct {
	catalog         *catalog.Snapshot
	identities      plan.IdentityResolver
	runner          Runner
	state           *executionState
	expectedPeerUID uint32
	peerUID         PeerUID
	now             func() time.Time
	requestTimeout  time.Duration
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
	return &Server{catalog: cfg.Catalog, identities: cfg.Identities, runner: cfg.Runner, state: state,
		expectedPeerUID: cfg.ExpectedPeerUID, peerUID: cfg.PeerUID, now: now, requestTimeout: requestTimeout}, nil
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
				return nil
			}
			return err
		}
		go s.handleConnection(ctx, connection)
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
	if err != nil || uid != s.expectedPeerUID {
		return executorprotocol.NewRejected("peer_not_authorized")
	}
	request, err := executorprotocol.ReadRequest(connection)
	if err != nil {
		return executorprotocol.NewRejected("invalid_request")
	}
	if request.Type == executorprotocol.TypePing {
		return executorprotocol.Response{Version: executorprotocol.Version, Status: executorprotocol.StatusReady}
	}
	return s.execute(ctx, request)
}

func (s *Server) execute(ctx context.Context, request executorprotocol.Request) executorprotocol.Response {
	now := s.now().UTC()
	if !request.ExpiresAt.After(now) {
		return executorprotocol.NewRejected("request_expired")
	}
	if planstore.Digest(request.Plan) != request.PlanDigest {
		return executorprotocol.NewRejected("plan_digest_mismatch")
	}
	value, err := plan.DecodeCanonical(request.Plan)
	if err != nil {
		return executorprotocol.NewRejected("invalid_plan")
	}
	if request.ExpiresAt.Sub(now) > time.Duration(value.RequestedDurationSeconds)*time.Second {
		return executorprotocol.NewRejected("invalid_expiry")
	}
	if err := plan.ValidateForHelper(value, s.catalog, s.identities); err != nil {
		return executorprotocol.NewRejected("plan_drift")
	}
	record, claimed, err := s.state.claim(request.ExecutionID, request.PlanDigest)
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
