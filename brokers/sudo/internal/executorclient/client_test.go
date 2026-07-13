package executorclient

import (
	"context"
	"errors"
	"net"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/osolmaz/brokerkit/brokers/sudo/internal/executorprotocol"
	"github.com/osolmaz/brokerkit/brokers/sudo/internal/plan"
)

func TestClientReadinessOverProtocol(t *testing.T) {
	t.Parallel()
	client, server := net.Pipe()
	defer func() { _ = server.Close() }()
	value := &Client{SocketPath: "/test/socket", Dial: func(context.Context, string, string) (net.Conn, error) { return client, nil }}
	go func() {
		request, _ := executorprotocol.ReadRequest(server)
		if request.Type == executorprotocol.TypePing {
			_ = executorprotocol.WriteResponse(server, executorprotocol.Response{Version: executorprotocol.Version, Status: executorprotocol.StatusReady})
		}
	}()
	if err := value.Ready(t.Context()); err != nil {
		t.Fatal(err)
	}
}

func TestClientExecutesCanonicalPlanAndTracksCallError(t *testing.T) {
	t.Parallel()
	client, server := net.Pipe()
	defer func() { _ = server.Close() }()
	value := &Client{SocketPath: "/test/socket", Dial: func(context.Context, string, string) (net.Conn, error) { return client, nil }}
	go func() {
		request, _ := executorprotocol.ReadRequest(server)
		_ = executorprotocol.WriteResponse(server, executorprotocol.NewCompleted(request.ExecutionID, executorprotocol.Outcome{Started: true}))
	}()
	commandPlan := plan.Plan{Schema: plan.SchemaV1, RequestID: "request", ClientID: "bob", Operation: "exec.command", CommandID: "true", TargetUser: "root",
		Executable: "/usr/bin/true", WorkingDirectory: "/", Environment: []string{"LANG=C", "LC_ALL=C"}, TimeoutSeconds: 1,
		CatalogDigest: strings.Repeat("a", 64), RequestedDurationSeconds: 60, RequestedMaxUses: 1, CreatedAt: time.Now().UTC()}
	response, err := value.Execute(t.Context(), "execution", commandPlan, "grant", "reservation", time.Now().Add(time.Minute))
	if err != nil || response.Status != executorprotocol.StatusCompleted {
		t.Fatalf("Execute() = %+v, %v", response, err)
	}
	callErr := &CallError{Dispatched: true, cause: errors.New("cause")}
	if callErr.Error() != "cause" || !errors.Is(callErr, callErr.cause) {
		t.Fatalf("CallError = %v", callErr)
	}
}

func TestClientFailsClosedForUnavailableOrInvalidHelper(t *testing.T) {
	t.Parallel()
	if err := (&Client{}).Ready(t.Context()); err == nil {
		t.Fatal("empty client was ready")
	}
	if err := (&Client{SocketPath: filepath.Join(t.TempDir(), "missing.sock"), Timeout: time.Millisecond}).Ready(t.Context()); err == nil {
		t.Fatal("missing default-dial socket was ready")
	}
	client, server := net.Pipe()
	defer func() { _ = server.Close() }()
	value := &Client{SocketPath: "/test/socket", Timeout: time.Second, Dial: func(context.Context, string, string) (net.Conn, error) { return client, nil }}
	go func() {
		_, _ = executorprotocol.ReadRequest(server)
		_ = executorprotocol.WriteResponse(server, executorprotocol.NewRejected("not_ready"))
	}()
	if err := value.Ready(t.Context()); err == nil {
		t.Fatal("rejected helper was ready")
	}
}

func TestCallErrorTracksDispatchBoundary(t *testing.T) {
	t.Parallel()
	dialError := &CallError{cause: errors.New("dial")}
	readError := &CallError{Dispatched: true, cause: errors.New("read")}
	if WasDispatched(dialError) || !WasDispatched(readError) {
		t.Fatalf("dispatch flags dial=%v read=%v", WasDispatched(dialError), WasDispatched(readError))
	}
}

func TestClientRejectsMismatchedExecutionResponse(t *testing.T) {
	t.Parallel()
	client, server := net.Pipe()
	defer func() { _ = server.Close() }()
	value := &Client{SocketPath: "/test/socket", Dial: func(context.Context, string, string) (net.Conn, error) { return client, nil }}
	go func() {
		_, _ = executorprotocol.ReadRequest(server)
		_ = executorprotocol.WriteResponse(server, executorprotocol.NewCompleted("other-execution", executorprotocol.Outcome{Started: true}))
	}()
	_, err := value.exchange(t.Context(), executorprotocol.Request{
		Version: executorprotocol.Version, Type: executorprotocol.TypeExecute, ExecutionID: "execution-1",
		Plan: []byte(`{}`), PlanDigest: "digest", GrantID: "grant-1", ReservationID: "reservation-1", ExpiresAt: time.Now().Add(time.Minute),
	}, 0)
	if err == nil || !WasDispatched(err) {
		t.Fatalf("mismatched response error = %v", err)
	}
}
