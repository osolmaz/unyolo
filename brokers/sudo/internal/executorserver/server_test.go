package executorserver

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/osolmaz/brokerkit/brokers/sudo/internal/catalog"
	"github.com/osolmaz/brokerkit/brokers/sudo/internal/executorprotocol"
	"github.com/osolmaz/brokerkit/brokers/sudo/internal/plan"
	"github.com/osolmaz/brokerkit/brokers/sudo/internal/sudopolicy"
	"github.com/osolmaz/brokerkit/grants"
	"github.com/osolmaz/brokerkit/planstore"
)

func TestServerExecutesAndReplaysExactlyOnce(t *testing.T) {
	t.Parallel()
	server, request, runner := testServerAndRequest(t)
	response := server.execute(t.Context(), request)
	if response.Status != executorprotocol.StatusCompleted || response.Outcome == nil || !response.Outcome.Started || runner.calls != 1 {
		t.Fatalf("first response=%+v calls=%d", response, runner.calls)
	}
	replay := server.execute(t.Context(), request)
	if replay.Status != executorprotocol.StatusCompleted || replay.Outcome == nil || runner.calls != 1 {
		t.Fatalf("replay response=%+v calls=%d", replay, runner.calls)
	}
	request.PlanDigest = strings.Repeat("f", 64)
	if response := server.execute(t.Context(), request); response.Status != executorprotocol.StatusRejected {
		t.Fatalf("changed plan response=%+v", response)
	}
}

func TestServerRejectsExpiredDriftedAndInterruptedExecution(t *testing.T) {
	t.Parallel()
	server, request, runner := testServerAndRequest(t)
	expired := request
	expired.ExpiresAt = time.Unix(1_700_000_000, 0).Add(-time.Second)
	if response := server.execute(t.Context(), expired); response.ErrorCode != "request_expired" {
		t.Fatalf("expired response=%+v", response)
	}
	changed := request
	var value map[string]any
	_ = json.Unmarshal(changed.Plan, &value)
	value["target_uid"] = float64(1)
	changed.Plan, _ = json.Marshal(value)
	changed.PlanDigest = planstore.Digest(changed.Plan)
	if response := server.execute(t.Context(), changed); response.ErrorCode != "plan_drift" {
		t.Fatalf("drift response=%+v", response)
	}
	_, _, _ = server.state.claim(request.ExecutionID, request.PlanDigest, request.GrantID, request.ReservationID)
	if response := server.execute(t.Context(), request); response.Status != executorprotocol.StatusAmbiguous || runner.calls != 0 {
		t.Fatalf("interrupted response=%+v calls=%d", response, runner.calls)
	}
}

func TestServerAuthenticatesUnixPeerBeforeReading(t *testing.T) {
	t.Parallel()
	server, _, _ := testServerAndRequest(t)
	server.expectedPeerUID = 1000
	server.peerUID = func(*net.UnixConn) (uint32, error) { return 1001, nil }
	response := server.Handle(context.Background(), nil)
	if response.ErrorCode != "peer_not_authorized" {
		t.Fatalf("response=%+v", response)
	}
}

func testServerAndRequest(t *testing.T) (*Server, executorprotocol.Request, *fakeRunner) {
	t.Helper()
	now := time.Unix(1_700_000_000, 0).UTC()
	directory := t.TempDir()
	snapshot, err := catalog.Parse([]byte(fmt.Sprintf(`{"version":1,"commands":[{
		"id":"echo","executable":"/usr/bin/printf","arguments":[{"literal":"ok"}],"target_users":["root"],
		"working_directory":"/","timeout_seconds":5,"max_output_bytes":100}]}`)))
	if err != nil {
		t.Fatal(err)
	}
	resolved, _ := snapshot.Resolve("echo", "root", nil)
	policyRequest := sudopolicy.Request("bob", resolved)
	grantRequest := grants.Request{Client: "bob", ClientRequestID: "request-1", Operation: policyRequest.Operation, Target: policyRequest.Target,
		Attrs: policyRequest.Attrs, Duration: 5 * time.Minute, MaxUses: 1}
	value, err := plan.Build(grantRequest, resolved, plan.Identity{Name: "root", UID: 0, GID: 0}, now)
	if err != nil {
		t.Fatal(err)
	}
	canonical, _ := plan.EncodeCanonical(value)
	runner := &fakeRunner{outcome: executorprotocol.Outcome{Started: true, ExitCode: 0, Stdout: []byte("ok")}}
	server, err := New(Config{Catalog: snapshot, Identities: fakeResolver{identity: plan.Identity{Name: "root", UID: 0, GID: 0}}, Runner: runner,
		StatePath: filepath.Join(directory, "executions.json"), ExpectedPeerUID: 1000,
		PeerUID: func(*net.UnixConn) (uint32, error) { return 1000, nil }, Now: func() time.Time { return now }})
	if err != nil {
		t.Fatal(err)
	}
	request := executorprotocol.Request{Version: executorprotocol.Version, Type: executorprotocol.TypeExecute, ExecutionID: "execution-1",
		Plan: canonical, PlanDigest: planstore.Digest(canonical), GrantID: "grant-1", ReservationID: "reservation-1", ExpiresAt: now.Add(time.Minute)}
	return server, request, runner
}

type fakeResolver struct{ identity plan.Identity }

func (f fakeResolver) Lookup(string) (plan.Identity, error) { return f.identity, nil }

type fakeRunner struct {
	calls   int
	outcome executorprotocol.Outcome
}

func (f *fakeRunner) Run(context.Context, plan.Plan) (executorprotocol.Outcome, error) {
	f.calls++
	return f.outcome, nil
}
