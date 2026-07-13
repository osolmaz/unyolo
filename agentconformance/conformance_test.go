package agentconformance

import (
	"context"
	"encoding/json"
	"errors"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/labstack/echo/v4"
	"github.com/osolmaz/brokerkit/agentapi"
	"github.com/osolmaz/brokerkit/agentclient"
	"github.com/osolmaz/brokerkit/agentops"
	"github.com/osolmaz/brokerkit/agentv1"
)

type conformanceStore struct {
	operation agentv1.Operation
	request   agentv1.SubmitRequest
}

func (s *conformanceStore) Get(clientID, id string) (agentv1.Operation, error) {
	if clientID != "agent" || id == "missing" || id != s.operation.ID {
		return agentv1.Operation{}, agentops.ErrNotFound
	}
	return s.operation, nil
}

func (s *conformanceStore) Wait(_ context.Context, clientID, id string, _ int64) (agentv1.Operation, error) {
	return s.Get(clientID, id)
}

func TestRunAgentV1(t *testing.T) {
	store := &conformanceStore{}
	start := func() (Endpoint, error) {
		handler, err := agentapi.New(agentapi.Options{
			Store: store, Realm: "conformance",
			Authenticate: func(header string) (string, error) {
				if header != "Bearer agent-secret-abcdefghijklmnopqrstuvwxyz" {
					return "", errors.New("authentication failed")
				}
				return "agent", nil
			},
			Submit: func(_ context.Context, client string, request agentv1.SubmitRequest) (agentv1.Operation, bool, error) {
				if store.operation.ID != "" {
					if request.Reason != store.request.Reason {
						return agentv1.Operation{}, false, agentops.ErrIdempotencyConflict
					}
					return store.operation, false, nil
				}
				now := time.Date(2026, time.January, 1, 0, 0, 0, 0, time.UTC)
				store.request = request
				store.operation = agentv1.Operation{
					APIVersion: agentv1.APIVersion, ID: "operation", Broker: "test-broker", ClientID: client,
					IdempotencyKey: request.IdempotencyKey, Operation: request.Operation, Target: request.Target,
					Arguments: request.Arguments, Reason: request.Reason, State: agentv1.StatePending, Revision: 1,
					CreatedAt: now, UpdatedAt: now, Presentation: agentv1.Presentation{Title: "Conformance operation"},
				}
				return store.operation, true, nil
			},
		})
		if err != nil {
			return Endpoint{}, err
		}
		router := echo.New()
		handler.Register(router)
		server := httptest.NewServer(router)
		return Endpoint{BaseURL: server.URL, HTTPClient: server.Client(), Close: func() error {
			server.Close()
			return nil
		}}, nil
	}

	RunAgentV1(t, Fixture{
		Start: start, Token: "agent-secret-abcdefghijklmnopqrstuvwxyz", WaitTime: time.Second,
		Request: agentv1.SubmitRequest{
			IdempotencyKey: "conformance", Operation: "repo.create", Target: json.RawMessage(`{}`),
			Arguments: json.RawMessage(`{}`), Reason: "test conformance",
		},
		Approve: func(context.Context, agentv1.Operation) error {
			now := store.operation.UpdatedAt.Add(time.Second)
			store.operation.State = agentv1.StateSucceeded
			store.operation.Revision++
			store.operation.UpdatedAt = now
			store.operation.TerminalAt = &now
			store.operation.Result = json.RawMessage(`{"ok":true}`)
			return nil
		},
		Verify: func(t *testing.T, operation agentv1.Operation) {
			t.Helper()
			if operation.State != agentv1.StateSucceeded || string(operation.Result) != `{"ok":true}` {
				t.Fatalf("operation = %#v", operation)
			}
		},
	})
}

func TestValidateFixture(t *testing.T) {
	valid := Fixture{
		Start:    func() (Endpoint, error) { return Endpoint{}, nil },
		Approve:  func(context.Context, agentv1.Operation) error { return nil },
		Verify:   func(*testing.T, agentv1.Operation) {},
		Token:    "agent-secret-abcdefghijklmnopqrstuvwxyz",
		Request:  agentv1.SubmitRequest{IdempotencyKey: "one", Operation: "repo.create", Target: json.RawMessage(`{}`), Arguments: json.RawMessage(`{}`), Reason: "test"},
		WaitTime: time.Second,
	}
	if err := validateFixture(valid); err != nil {
		t.Fatal(err)
	}
	for _, mutate := range []func(*Fixture){
		func(f *Fixture) { f.Start = nil },
		func(f *Fixture) { f.Approve = nil },
		func(f *Fixture) { f.Verify = nil },
		func(f *Fixture) { f.Token = "short" },
		func(f *Fixture) { f.Request.Reason = "" },
		func(f *Fixture) { f.WaitTime = 0 },
	} {
		fixture := valid
		mutate(&fixture)
		if err := validateFixture(fixture); err == nil {
			t.Fatal("validateFixture accepted invalid fixture")
		}
	}
}

func TestClientError(t *testing.T) {
	err := &agentclient.Error{Status: 409, Code: "idempotency_conflict", Message: "conflict"}
	if !clientError(err, 409, "idempotency_conflict") || clientError(err, 400, "idempotency_conflict") {
		t.Fatal("clientError did not match exact status and code")
	}
}
