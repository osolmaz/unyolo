// Package conformance provides reusable black-box broker contract tests.
package conformance

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/osolmaz/brokerkit/controlplane"
	"github.com/osolmaz/brokerkit/grants"
	"github.com/osolmaz/brokerkit/notify"
	"github.com/osolmaz/brokerkit/operatorclient"
	"github.com/osolmaz/brokerkit/operatorv1"
)

// Fixture describes one broker's real shared control-plane assembly.
type Fixture struct {
	Runtime       *controlplane.Runtime
	Request       grants.Request
	Prepare       func(*grants.Request) error
	ClientToken   string
	OperatorToken string
}

// RunOperatorV1 verifies the common broker contract against a real HTTP server.
func RunOperatorV1(t *testing.T, fixture Fixture) {
	t.Helper()
	if err := validateFixture(fixture); err != nil {
		t.Fatal(err)
	}
	created := requestGrant(t, fixture)
	server := httptest.NewServer(fixture.Runtime.OperatorHandler)
	t.Cleanup(server.Close)
	assertRejectedCredential(t, server, fixture.ClientToken)
	assertRejectedCredential(t, server, "unknown-operator-secret-abcdefghijklmnopqrstuvwxyz")
	assertOperatorLifecycle(t, fixture, server, created)
	assertTokenLifecycle(t, fixture)
	assertTerminalTransitions(t, fixture, server)
}

func validateFixture(fixture Fixture) error {
	if fixture.Runtime == nil || fixture.Runtime.Clients == nil {
		return errors.New("conformance runtime is required")
	}
	client, err := fixture.Runtime.Clients.AuthenticateHeader("Bearer " + fixture.ClientToken)
	if err != nil {
		return fmt.Errorf("fixture client authentication: %w", err)
	}
	if client != fixture.Request.Client {
		return fmt.Errorf("fixture client authentication = %q; want %q", client, fixture.Request.Client)
	}
	return nil
}

func requestGrant(t *testing.T, fixture Fixture) grants.RequestResult {
	t.Helper()
	created, _, err := fixture.Runtime.Store.Request(fixture.Request)
	if err != nil {
		t.Fatalf("request grant: %v", err)
	}
	return created
}

func assertOperatorLifecycle(t *testing.T, fixture Fixture, server *httptest.Server, created grants.RequestResult) {
	t.Helper()
	client := &operatorclient.Client{BaseURL: server.URL, Token: fixture.OperatorToken, HTTPClient: server.Client()}
	if descriptor, err := client.Discover(t.Context()); err != nil || descriptor.APIVersion != operatorv1.APIVersion {
		t.Fatalf("operator discovery = %+v, %v", descriptor, err)
	}
	if err := client.Health(t.Context()); err != nil {
		t.Fatalf("operator health: %v", err)
	}
	page, err := client.List(t.Context(), operatorv1.Query{Status: grants.StatusGroupPending})
	if err != nil || len(page.Requests) != 1 || page.Requests[0].ID != created.Grant.ID || page.EventCursor == "" {
		t.Fatalf("operator list = %+v, %v", page, err)
	}
	stream, err := client.Watch(t.Context(), "")
	if err != nil {
		t.Fatalf("operator watch: %v", err)
	}
	streamContext, cancel := context.WithTimeout(t.Context(), time.Second)
	event, receiveErr := stream.Receive(streamContext)
	cancel()
	_ = stream.Close()
	if receiveErr != nil || event.RequestID != created.Grant.ID {
		t.Fatalf("operator initial event = %+v, %v", event, receiveErr)
	}
	approved, err := client.Decide(t.Context(), created.Grant.ID, operatorv1.ActionApprove, operatorv1.Decision{
		ExpectedRevision: created.Grant.Revision, IdempotencyKey: "conformance-approve",
	})
	if err != nil || approved.Status != grants.StatusActive {
		t.Fatalf("operator approve = %+v, %v", approved, err)
	}
	replay, err := client.Decide(t.Context(), created.Grant.ID, operatorv1.ActionApprove, operatorv1.Decision{
		ExpectedRevision: created.Grant.Revision, IdempotencyKey: "conformance-approve",
	})
	if err != nil || replay.Revision != approved.Revision {
		t.Fatalf("operator replay = %+v, %v", replay, err)
	}
	if _, err := client.Decide(t.Context(), created.Grant.ID, operatorv1.ActionApprove, operatorv1.Decision{
		ExpectedRevision: created.Grant.Revision, IdempotencyKey: "conformance-approve", OnBehalfOf: "changed",
	}); !apiErrorCode(err, "idempotency_conflict") {
		t.Fatalf("operator replay mismatch error = %v", err)
	}
	detail, err := client.Get(t.Context(), created.Grant.ID)
	if err != nil || detail.Status != grants.StatusActive || detail.Revision <= created.Grant.Revision {
		t.Fatalf("operator detail = %+v, %v", detail, err)
	}
	if _, err := client.Decide(t.Context(), created.Grant.ID, operatorv1.ActionRevoke, operatorv1.Decision{
		ExpectedRevision: created.Grant.Revision, IdempotencyKey: "conformance-stale-revoke",
	}); !apiErrorCode(err, "revision_conflict") {
		t.Fatalf("stale revoke error = %v", err)
	}
	revoked, err := client.Decide(t.Context(), created.Grant.ID, operatorv1.ActionRevoke, operatorv1.Decision{
		ExpectedRevision: detail.Revision, IdempotencyKey: "conformance-revoke",
	})
	if err != nil || revoked.Status != grants.StatusRevoked {
		t.Fatalf("operator revoke = %+v, %v", revoked, err)
	}
}

func assertTokenLifecycle(t *testing.T, fixture Fixture) {
	t.Helper()
	created := requestGrantWithSuffix(t, fixture, "token")
	result := fixture.Runtime.HandleDecision(t.Context(), notify.Decision{
		Action: notify.ActionApprove, GrantID: created.Grant.ID, DecisionToken: created.DecisionToken,
		ChatID: 1, MessageID: 2, OperatorID: 42,
	})
	if result.Retry || result.Answer != "Grant approved" {
		t.Fatalf("token approval = %+v", result)
	}
	current, err := fixture.Runtime.Store.Get(created.Grant.ID)
	if err != nil || current.Status != grants.StatusActive || current.DecidedBy != "telegram:42" {
		t.Fatalf("token grant = %+v, %v", current, err)
	}
}

func assertTerminalTransitions(t *testing.T, fixture Fixture, server *httptest.Server) {
	t.Helper()
	client := &operatorclient.Client{BaseURL: server.URL, Token: fixture.OperatorToken, HTTPClient: server.Client()}
	denied := requestGrantWithSuffix(t, fixture, "deny")
	result, err := client.Decide(t.Context(), denied.Grant.ID, operatorv1.ActionDeny, operatorv1.Decision{
		ExpectedRevision: denied.Grant.Revision, IdempotencyKey: "conformance-deny",
	})
	if err != nil || result.Status != grants.StatusDenied {
		t.Fatalf("operator deny = %+v, %v", result, err)
	}

	canceled := requestGrantWithSuffix(t, fixture, "cancel")
	resultGrant, err := fixture.Runtime.Store.CancelForClient(canceled.Grant.ID, canceled.Grant.Client)
	if err != nil || resultGrant.Status != grants.StatusCanceled {
		t.Fatalf("requester cancel = %+v, %v", resultGrant, err)
	}
}

func requestGrantWithSuffix(t *testing.T, fixture Fixture, suffix string) grants.RequestResult {
	t.Helper()
	request := fixture.Request
	request.ClientRequestID += "-" + suffix
	if fixture.Prepare != nil {
		if err := fixture.Prepare(&request); err != nil {
			t.Fatalf("prepare %s grant: %v", suffix, err)
		}
	}
	created, _, err := fixture.Runtime.Store.Request(request)
	if err != nil {
		t.Fatalf("request %s grant: %v", suffix, err)
	}
	return created
}

func apiErrorCode(err error, code string) bool {
	var apiErr *operatorclient.Error
	return errors.As(err, &apiErr) && apiErr.Code == code
}

func assertRejectedCredential(t *testing.T, server *httptest.Server, token string) {
	t.Helper()
	request, err := http.NewRequestWithContext(t.Context(), http.MethodGet, server.URL+"/api/operator/v1/requests", nil)
	if err != nil {
		t.Fatal(err)
	}
	request.Header.Set("Authorization", "Bearer "+token)
	response, err := server.Client().Do(request)
	if err != nil {
		t.Fatal(err)
	}
	if response.StatusCode != http.StatusUnauthorized {
		t.Fatalf("rejected credential status = %d, want 401", response.StatusCode)
	}
	if err := response.Body.Close(); err != nil {
		t.Fatal(err)
	}
}
