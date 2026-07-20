// Package agentconformance provides reusable black-box Agent Operations V1 tests.
package agentconformance

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/osolmaz/brokerkit/agent/client"
	"github.com/osolmaz/brokerkit/agent/v1"
)

const (
	discoveryPath     = "/.well-known/brokerkit-agent"
	operationsPath    = "/api/agent/v1/operations"
	unknownCredential = "unknown-agent-secret-abcdefghijklmnopqrstuvwxyz"
	maxErrorBodyBytes = 64 * 1024
)

// Endpoint is one running real broker handler backed by the fixture's durable state.
type Endpoint struct {
	BaseURL    string
	HTTPClient *http.Client
	Close      func() error
}

// Fixture supplies provider behavior around the shared black-box lifecycle.
type Fixture struct {
	Start    func() (Endpoint, error)
	Approve  func(context.Context, agentv1.Operation) error
	Verify   func(*testing.T, agentv1.Operation)
	Token    string
	Request  agentv1.SubmitRequest
	WaitTime time.Duration
}

// RunAgentV1 verifies the shared lifecycle against a real broker handler.
func RunAgentV1(t *testing.T, fixture Fixture) {
	t.Helper()
	if err := validateFixture(fixture); err != nil {
		t.Fatal(err)
	}
	endpoint, closeInitial := startManagedEndpoint(t, fixture)
	client := newClient(t, endpoint, fixture.Token)
	assertDiscovery(t, endpoint, fixture.Token)
	assertRejectedCredential(t, endpoint)
	operation := assertSubmission(t, client, fixture.Request)
	assertListRecovery(t, client, operation)
	assertErrorEnvelopes(t, endpoint, fixture.Token, operation)
	terminal := approveAndWait(t, fixture, client, operation)
	fixture.Verify(t, terminal)
	closeEndpoint(t, closeInitial)
	assertRestartRecovery(t, fixture, terminal)
}

func validateFixture(fixture Fixture) error {
	if fixture.Start == nil || fixture.Approve == nil || fixture.Verify == nil {
		return errors.New("start, approve, and verify hooks are required")
	}
	if len(fixture.Token) < 32 {
		return errors.New("agent token is invalid")
	}
	if incompleteRequest(fixture.Request) {
		return errors.New("agent request is incomplete")
	}
	if fixture.WaitTime <= 0 {
		return errors.New("wait time must be positive")
	}
	return nil
}

func incompleteRequest(request agentv1.SubmitRequest) bool {
	return strings.TrimSpace(request.IdempotencyKey) == "" || strings.TrimSpace(request.Operation) == "" ||
		strings.TrimSpace(request.Reason) == "" || len(request.Target) == 0 || len(request.Arguments) == 0
}

func startManagedEndpoint(t *testing.T, fixture Fixture) (Endpoint, func() error) {
	t.Helper()
	endpoint, err := fixture.Start()
	if err != nil {
		t.Fatalf("start endpoint: %v", err)
	}
	if endpoint.BaseURL == "" || endpoint.HTTPClient == nil || endpoint.Close == nil {
		t.Fatal("start endpoint returned an incomplete endpoint")
	}
	closeOnce := sync.OnceValue(endpoint.Close)
	t.Cleanup(func() { closeEndpoint(t, closeOnce) })
	return endpoint, closeOnce
}

func closeEndpoint(t *testing.T, close func() error) {
	t.Helper()
	if err := close(); err != nil {
		t.Fatalf("close endpoint: %v", err)
	}
}

func approveAndWait(t *testing.T, fixture Fixture, client *agentclient.Client, operation agentv1.Operation) agentv1.Operation {
	t.Helper()
	if err := fixture.Approve(t.Context(), operation); err != nil {
		t.Fatalf("approve operation: %v", err)
	}
	waitContext, cancel := context.WithTimeout(t.Context(), fixture.WaitTime)
	terminal, err := client.Wait(waitContext, operation)
	cancel()
	if err != nil || !terminal.State.Terminal() {
		t.Fatalf("wait operation = %+v, %v", terminal, err)
	}
	return terminal
}

func assertRestartRecovery(t *testing.T, fixture Fixture, terminal agentv1.Operation) {
	t.Helper()
	restarted, _ := startManagedEndpoint(t, fixture)
	client := newClient(t, restarted, fixture.Token)
	recovered, err := client.Get(t.Context(), terminal.ID)
	if err != nil || recovered.State != terminal.State || recovered.Revision != terminal.Revision {
		t.Fatalf("recovered operation = %+v, %v; want state %s revision %d", recovered, err, terminal.State, terminal.Revision)
	}
	fixture.Verify(t, recovered)
}

func newClient(t *testing.T, endpoint Endpoint, token string) *agentclient.Client {
	t.Helper()
	client, err := agentclient.New(agentclient.Options{Endpoint: endpointURI(endpoint.BaseURL), Credential: token, HTTPClient: endpoint.HTTPClient})
	if err != nil {
		t.Fatal(err)
	}
	return client
}

func endpointURI(baseURL string) string {
	return strings.Replace(baseURL, "http://", "tcp://", 1)
}

func assertDiscovery(t *testing.T, endpoint Endpoint, token string) {
	t.Helper()
	status, body := doRequest(t, endpoint, http.MethodGet, discoveryPath, token, nil)
	var descriptor agentv1.Descriptor
	if status != http.StatusOK || json.Unmarshal(body, &descriptor) != nil || descriptor.APIVersion != agentv1.APIVersion {
		t.Fatalf("agent discovery = %d %s", status, body)
	}
}

func assertRejectedCredential(t *testing.T, endpoint Endpoint) {
	t.Helper()
	status, body := doRequest(t, endpoint, http.MethodGet, discoveryPath, unknownCredential, nil)
	assertAPIError(t, status, body, http.StatusForbidden, "authentication_failed")
}

func assertSubmission(t *testing.T, client *agentclient.Client, request agentv1.SubmitRequest) agentv1.Operation {
	t.Helper()
	operation, err := client.Submit(t.Context(), request)
	if err != nil || operation.ID == "" || operation.State.Terminal() {
		t.Fatalf("submit operation = %+v, %v", operation, err)
	}
	assertReplayAndGet(t, client, request, operation)
	conflict := request
	conflict.Reason += " changed"
	if _, err := client.Submit(t.Context(), conflict); !clientError(err, http.StatusConflict, "idempotency_conflict") {
		t.Fatalf("idempotency conflict = %v", err)
	}
	return operation
}

func assertReplayAndGet(t *testing.T, client *agentclient.Client, request agentv1.SubmitRequest, operation agentv1.Operation) {
	t.Helper()
	replay, err := client.Submit(t.Context(), request)
	if err != nil || replay.ID != operation.ID || replay.Revision != operation.Revision {
		t.Fatalf("replay operation = %+v, %v; want %s revision %d", replay, err, operation.ID, operation.Revision)
	}
	assertGet(t, client, operation)
}

func assertGet(t *testing.T, client *agentclient.Client, operation agentv1.Operation) {
	t.Helper()
	current, err := client.Get(t.Context(), operation.ID)
	if err != nil || current.ID != operation.ID || current.Revision != operation.Revision {
		t.Fatalf("get operation = %+v, %v", current, err)
	}
}

func assertListRecovery(t *testing.T, client *agentclient.Client, operation agentv1.Operation) {
	t.Helper()
	page, err := client.List(t.Context(), agentv1.ListOptions{IdempotencyKey: operation.IdempotencyKey, Limit: 1})
	if err != nil || len(page.Operations) != 1 || page.Operations[0].ID != operation.ID || page.Operations[0].ClientID != operation.ClientID {
		t.Fatalf("list operation = %+v, %v", page, err)
	}
}

func assertErrorEnvelopes(t *testing.T, endpoint Endpoint, token string, operation agentv1.Operation) {
	t.Helper()
	status, body := doRequest(t, endpoint, http.MethodGet, operationsPath+"/missing", token, nil)
	assertAPIError(t, status, body, http.StatusNotFound, "not_found")
	status, body = doRequest(t, endpoint, http.MethodGet, operationsPath+"/"+operation.ID+"/events?wait_seconds=31", token, nil)
	assertAPIError(t, status, body, http.StatusBadRequest, "invalid_request")
	status, body = doRequest(t, endpoint, http.MethodPost, operationsPath, token, strings.NewReader(`{"invalid":true}`))
	assertAPIError(t, status, body, http.StatusBadRequest, "invalid_request")
}

func doRequest(t *testing.T, endpoint Endpoint, method, path, token string, body io.Reader) (int, []byte) {
	t.Helper()
	request, err := http.NewRequestWithContext(t.Context(), method, endpoint.BaseURL+path, body)
	if err != nil {
		t.Fatal(err)
	}
	request.Header.Set("Authorization", "Bearer "+token)
	if body != nil {
		request.Header.Set("Content-Type", "application/json")
	}
	response, err := endpoint.HTTPClient.Do(request)
	if err != nil {
		t.Fatal(err)
	}
	data, readErr := io.ReadAll(io.LimitReader(response.Body, maxErrorBodyBytes+1))
	closeErr := response.Body.Close()
	if err := errors.Join(readErr, closeErr); err != nil {
		t.Fatal(err)
	}
	if len(data) > maxErrorBodyBytes {
		t.Fatal("agent response exceeded conformance bound")
	}
	return response.StatusCode, data
}

func assertAPIError(t *testing.T, status int, body []byte, wantStatus int, wantCode string) {
	t.Helper()
	var envelope agentv1.ErrorEnvelope
	if status != wantStatus || json.Unmarshal(body, &envelope) != nil || envelope.Error.Code != wantCode || envelope.Error.Message == "" {
		t.Fatalf("agent error = %d %s; want %d %s", status, body, wantStatus, wantCode)
	}
}

func clientError(err error, status int, code string) bool {
	var apiErr *agentclient.Error
	return errors.As(err, &apiErr) && apiErr.Status == status && apiErr.Code == code
}
