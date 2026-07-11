// Package executorclient connects the unprivileged frontend to the Unix helper.
package executorclient

import (
	"context"
	"errors"
	"net"
	"time"

	"github.com/osolmaz/brokerkit/brokers/sudo/internal/executorprotocol"
	"github.com/osolmaz/brokerkit/brokers/sudo/internal/plan"
	"github.com/osolmaz/brokerkit/planstore"
)

type Client struct {
	SocketPath string
	Timeout    time.Duration
	Dial       func(context.Context, string, string) (net.Conn, error)
}

type CallError struct {
	Dispatched bool
	cause      error
}

func (e *CallError) Error() string { return e.cause.Error() }

func (e *CallError) Unwrap() error { return e.cause }

func WasDispatched(err error) bool {
	var callErr *CallError
	return errors.As(err, &callErr) && callErr.Dispatched
}

func (c *Client) Ready(ctx context.Context) error {
	response, err := c.exchange(ctx, executorprotocol.Ping())
	if err != nil {
		return err
	}
	if response.Status != executorprotocol.StatusReady {
		return errors.New("sudo helper is not ready")
	}
	return nil
}

func (c *Client) Execute(ctx context.Context, executionID string, value plan.Plan, grantID string, reservationID string, expiresAt time.Time) (executorprotocol.Response, error) {
	canonical, err := plan.EncodeCanonical(value)
	if err != nil {
		return executorprotocol.Response{}, err
	}
	request := executorprotocol.Request{
		Version: executorprotocol.Version, Type: executorprotocol.TypeExecute, ExecutionID: executionID,
		Plan: canonical, PlanDigest: planstore.Digest(canonical), GrantID: grantID, ReservationID: reservationID, ExpiresAt: expiresAt.UTC(),
	}
	return c.exchange(ctx, request)
}

func (c *Client) exchange(ctx context.Context, request executorprotocol.Request) (executorprotocol.Response, error) {
	if c == nil || c.SocketPath == "" {
		return executorprotocol.Response{}, errors.New("sudo helper socket is not configured")
	}
	timeout := c.Timeout
	if timeout <= 0 {
		timeout = 10 * time.Second
	}
	dial := c.Dial
	if dial == nil {
		dialer := &net.Dialer{Timeout: timeout}
		dial = dialer.DialContext
	}
	exchangeCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	connection, err := dial(exchangeCtx, "unix", c.SocketPath)
	if err != nil {
		return executorprotocol.Response{}, &CallError{cause: errors.New("sudo helper is unavailable")}
	}
	defer func() { _ = connection.Close() }()
	if deadline, ok := exchangeCtx.Deadline(); ok {
		_ = connection.SetDeadline(deadline)
	}
	if err := executorprotocol.WriteRequest(connection, request); err != nil {
		return executorprotocol.Response{}, &CallError{Dispatched: true, cause: err}
	}
	response, err := executorprotocol.ReadResponse(connection)
	if err != nil {
		return executorprotocol.Response{}, &CallError{Dispatched: true, cause: err}
	}
	return response, nil
}
