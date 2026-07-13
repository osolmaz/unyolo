// Package agentapi serves the provider-neutral Agent Operations V1 HTTP API.
package agentapi

import (
	"context"
	"errors"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/labstack/echo/v4"
	"github.com/osolmaz/brokerkit/agentops"
	"github.com/osolmaz/brokerkit/agentv1"
	"github.com/osolmaz/brokerkit/agentv1wire"
	bkauth "github.com/osolmaz/brokerkit/auth"
	"github.com/osolmaz/brokerkit/httpx"
	"github.com/osolmaz/brokerkit/protocol/agentwire"
)

const maxSubmitBytes = 2 * 1024 * 1024

// Store is the durable operation lifecycle required by the HTTP boundary.
type Store interface {
	Get(clientID, id string) (agentv1.Operation, error)
	Wait(context.Context, string, string, int64) (agentv1.Operation, error)
	Cancel(clientID, id string) (agentv1.Operation, error)
}

// SubmitFunc validates, classifies, and starts one provider operation.
type SubmitFunc func(context.Context, string, agentv1.SubmitRequest) (agentv1.Operation, bool, error)

// CancelFunc performs provider cleanup while canceling requester-owned work.
type CancelFunc func(context.Context, string, string) (agentv1.Operation, error)

// AuthenticateFunc resolves one bearer header to a provider client identity.
type AuthenticateFunc func(string) (string, error)

// AuthFailureFunc records a redacted authentication failure.
type AuthFailureFunc func()

// Options configures the shared Agent V1 server boundary.
type Options struct {
	Store        Store
	Authenticate AuthenticateFunc
	Submit       SubmitFunc
	Cancel       CancelFunc
	AuthFailure  AuthFailureFunc
	Realm        string
}

// Handler implements the generated Agent V1 Echo interface.
type Handler struct {
	store        Store
	authenticate AuthenticateFunc
	submit       SubmitFunc
	cancel       CancelFunc
	authFailure  AuthFailureFunc
	realm        string
}

var _ agentwire.ServerInterface = (*Handler)(nil)

// Error is a provider-safe stable Agent V1 HTTP failure.
type Error struct {
	Status  int
	Code    string
	Message string
}

func (e *Error) Error() string { return e.Message }

// New validates and constructs an Agent V1 HTTP handler.
func New(options Options) (*Handler, error) {
	if options.Store == nil || options.Authenticate == nil || options.Submit == nil {
		return nil, errors.New("agent store, authenticator, and submitter are required")
	}
	if strings.TrimSpace(options.Realm) == "" {
		options.Realm = "brokerkit-agent"
	}
	cancel := options.Cancel
	if cancel == nil {
		cancel = func(_ context.Context, client, id string) (agentv1.Operation, error) {
			return options.Store.Cancel(client, id)
		}
	}
	return &Handler{
		store: options.Store, authenticate: options.Authenticate, submit: options.Submit,
		cancel: cancel, authFailure: options.AuthFailure, realm: options.Realm,
	}, nil
}

// Register installs only the generated Agent V1 routes on router.
func (h *Handler) Register(router *echo.Echo) { agentwire.RegisterHandlers(router, h) }

func (h *Handler) DiscoverAgent(c echo.Context) error {
	return h.withAuthenticated(c, func(string) error {
		return c.JSON(http.StatusOK, agentwire.Descriptor{ApiVersion: agentwire.DescriptorApiVersionBrokerkitIoagentv1})
	})
}

func (h *Handler) SubmitAgentOperation(c echo.Context) error {
	client, ok := h.authenticateRequest(c)
	if !ok {
		return nil
	}
	request, err := readSubmit(c.Request())
	if err != nil {
		return writeError(c, &Error{Status: http.StatusBadRequest, Code: "invalid_request", Message: err.Error()})
	}
	operation, created, err := h.submit(c.Request().Context(), client, request)
	if err != nil {
		return writeSubmitError(c, err)
	}
	return writeOperation(c, operation, created)
}

func (h *Handler) GetAgentOperation(c echo.Context, id agentwire.OperationID) error {
	client, ok := h.authenticateRequest(c)
	if !ok {
		return nil
	}
	operation, err := h.store.Get(client, id)
	if err != nil {
		return writeStoreError(c, err, "read")
	}
	return writeOperation(c, operation, false)
}

func (h *Handler) CancelAgentOperation(c echo.Context, id agentwire.OperationID) error {
	client, ok := h.authenticateRequest(c)
	if !ok {
		return nil
	}
	operation, err := h.cancel(c.Request().Context(), client, id)
	if err != nil {
		if errors.Is(err, agentops.ErrNotCancelable) {
			return writeError(c, &Error{Status: http.StatusConflict, Code: "operation_not_cancelable", Message: "Operation is already executing"})
		}
		return writeStoreError(c, err, "cancel")
	}
	return writeOperation(c, operation, false)
}

func (h *Handler) WaitForAgentOperation(c echo.Context, id agentwire.OperationID, params agentwire.WaitForAgentOperationParams) error {
	client, ok := h.authenticateRequest(c)
	if !ok {
		return nil
	}
	after, wait, err := waitOptions(params)
	if err != nil {
		return writeError(c, err)
	}
	ctx, cancel := context.WithTimeout(c.Request().Context(), wait)
	defer cancel()
	operation, storeErr := h.store.Wait(ctx, client, id, after)
	if storeErr != nil {
		return writeStoreError(c, storeErr, "wait for")
	}
	return writeOperation(c, operation, false)
}

func (h *Handler) authenticateRequest(c echo.Context) (string, bool) {
	header := c.Request().Header.Get("Authorization")
	client, err := h.authenticate(header)
	if err == nil {
		return client, true
	}
	status := http.StatusForbidden
	if header == "" || errors.Is(err, bkauth.ErrMissing) {
		status = http.StatusUnauthorized
		c.Response().Header().Set("WWW-Authenticate", `Bearer realm="`+h.realm+`"`)
	}
	_ = writeError(c, &Error{Status: status, Code: "authentication_failed", Message: "Authentication failed"})
	if h.authFailure != nil {
		h.authFailure()
	}
	return "", false
}

func (h *Handler) withAuthenticated(c echo.Context, action func(string) error) error {
	client, ok := h.authenticateRequest(c)
	if !ok {
		return nil
	}
	return action(client)
}

func readSubmit(request *http.Request) (agentv1.SubmitRequest, error) {
	var wire agentwire.SubmitRequest
	if err := httpx.DecodeJSON(request.Body, maxSubmitBytes, &wire, true); err != nil {
		return agentv1.SubmitRequest{}, errors.New("agent operation request is invalid")
	}
	result, err := agentv1wire.SubmitFromWire(wire)
	if err != nil || strings.TrimSpace(result.IdempotencyKey) == "" || len(result.IdempotencyKey) > 128 ||
		strings.TrimSpace(result.Reason) == "" || len(result.Reason) > 2000 {
		return agentv1.SubmitRequest{}, errors.New("idempotency key and reason are required")
	}
	return result, nil
}

func waitOptions(params agentwire.WaitForAgentOperationParams) (int64, time.Duration, *Error) {
	after, seconds := 0, 30
	if params.AfterRevision != nil {
		after = *params.AfterRevision
	}
	if params.WaitSeconds != nil {
		seconds = *params.WaitSeconds
	}
	if after < 0 || seconds < 0 || seconds > 30 {
		return 0, 0, &Error{Status: http.StatusBadRequest, Code: "invalid_request", Message: "Invalid operation wait query"}
	}
	return int64(after), time.Duration(seconds) * time.Second, nil
}

func writeOperation(c echo.Context, operation agentv1.Operation, created bool) error {
	wire, err := agentv1wire.OperationToWire(operation)
	if err != nil {
		return writeError(c, &Error{Status: http.StatusInternalServerError, Code: "operation_store_unavailable", Message: "Stored operation is invalid"})
	}
	status := http.StatusOK
	if created && !operation.State.Terminal() {
		status = http.StatusAccepted
	}
	if !operation.State.Terminal() {
		c.Response().Header().Set("Location", "/api/agent/v1/operations/"+url.PathEscape(operation.ID))
		c.Response().Header().Set("Retry-After", "2")
	}
	return c.JSON(status, wire)
}

func writeSubmitError(c echo.Context, err error) error {
	var apiErr *Error
	if errors.As(err, &apiErr) {
		return writeError(c, apiErr)
	}
	if errors.Is(err, agentops.ErrIdempotencyConflict) {
		return writeError(c, &Error{Status: http.StatusConflict, Code: "idempotency_conflict", Message: "Idempotency key was reused with a different operation"})
	}
	return writeError(c, &Error{Status: http.StatusInternalServerError, Code: "operation_store_unavailable", Message: "Could not store operation"})
}

func writeStoreError(c echo.Context, err error, action string) error {
	if errors.Is(err, agentops.ErrNotFound) {
		return writeError(c, &Error{Status: http.StatusNotFound, Code: "not_found", Message: "Operation not found"})
	}
	return writeError(c, &Error{Status: http.StatusInternalServerError, Code: "operation_store_unavailable", Message: "Could not " + action + " operation"})
}

func writeError(c echo.Context, err *Error) error {
	return c.JSON(err.Status, agentwire.ErrorEnvelope{Error: agentwire.OperationError{Code: err.Code, Message: err.Message}})
}
