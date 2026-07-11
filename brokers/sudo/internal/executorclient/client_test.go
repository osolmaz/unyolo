package executorclient

import (
	"context"
	"errors"
	"net"
	"testing"
	"time"

	"github.com/osolmaz/brokerkit/brokers/sudo/internal/executorprotocol"
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

func TestClientFailsClosedForUnavailableOrInvalidHelper(t *testing.T) {
	t.Parallel()
	if err := (&Client{}).Ready(t.Context()); err == nil {
		t.Fatal("empty client was ready")
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
	})
	if err == nil || !WasDispatched(err) {
		t.Fatalf("mismatched response error = %v", err)
	}
}
