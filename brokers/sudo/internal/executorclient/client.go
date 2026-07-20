// Package executorclient connects the unprivileged frontend to the Unix helper.
package executorclient

import (
	"context"
	"errors"
	"net"
	"time"

	"github.com/osolmaz/brokerkit/brokers/sudo/internal/executorprotocol"
	"github.com/osolmaz/brokerkit/brokers/sudo/internal/plan"
	"github.com/osolmaz/brokerkit/operation/digest"
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
	response, err := c.exchange(ctx, executorprotocol.Ping(), 0)
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
		Plan: canonical, PlanDigest: plandigest.Digest(canonical), GrantID: grantID, ReservationID: reservationID, ExpiresAt: expiresAt.UTC(),
	}
	return c.exchange(ctx, request, time.Duration(value.TimeoutSeconds)*time.Second+5*time.Second)
}

func (c *Client) exchange(ctx context.Context, request executorprotocol.Request, minimumTimeout time.Duration) (executorprotocol.Response, error) {
	if c == nil || c.SocketPath == "" {
		return executorprotocol.Response{}, errors.New("sudo helper socket is not configured")
	}
	timeout := exchangeTimeout(c.Timeout, minimumTimeout)
	exchangeCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	connection, err := exchangeDial(c, exchangeCtx, timeout)
	if err != nil {
		return executorprotocol.Response{}, &CallError{cause: errors.New("sudo helper is unavailable")}
	}
	defer func() { _ = connection.Close() }()
	setExchangeDeadline(exchangeCtx, connection)
	if err := executorprotocol.WriteRequest(connection, request); err != nil {
		return executorprotocol.Response{}, &CallError{Dispatched: true, cause: err}
	}
	response, err := executorprotocol.ReadResponse(connection)
	if err != nil {
		return executorprotocol.Response{}, &CallError{Dispatched: true, cause: err}
	}
	if mismatchedExecutionID(request, response) {
		return executorprotocol.Response{}, &CallError{Dispatched: true, cause: errors.New("sudo helper returned a mismatched execution id")}
	}
	return response, nil
}

func exchangeTimeout(configured time.Duration, minimum time.Duration) time.Duration {
	if configured <= 0 {
		configured = 10 * time.Second
	}
	if configured < minimum {
		return minimum
	}
	return configured
}

func exchangeDial(c *Client, ctx context.Context, timeout time.Duration) (net.Conn, error) {
	dial := c.Dial
	if dial == nil {
		dialer := &net.Dialer{Timeout: timeout}
		dial = dialer.DialContext
	}
	return dial(ctx, "unix", c.SocketPath)
}

func setExchangeDeadline(ctx context.Context, connection net.Conn) {
	if deadline, ok := ctx.Deadline(); ok {
		_ = connection.SetDeadline(deadline)
	}
}

func mismatchedExecutionID(request executorprotocol.Request, response executorprotocol.Response) bool {
	return request.Type == executorprotocol.TypeExecute && response.ExecutionID != "" && response.ExecutionID != request.ExecutionID
}
