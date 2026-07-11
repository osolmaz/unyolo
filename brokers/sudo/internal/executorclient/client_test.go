package executorclient

import (
	"context"
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
