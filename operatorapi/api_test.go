package operatorapi_test

import (
	"context"
	"errors"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/osolmaz/brokerkit/decision"
	"github.com/osolmaz/brokerkit/grants"
	"github.com/osolmaz/brokerkit/operatorclient"
	"github.com/osolmaz/brokerkit/operatorfake"
	"github.com/osolmaz/brokerkit/operatorinbox"
	"github.com/osolmaz/brokerkit/operatorv1"
	"github.com/osolmaz/brokerkit/policy"
)

const testOperatorSecret = "operator-secret-with-enough-entropy"

func TestOperatorV1DiscoveryAuthAndLegacyCutover(t *testing.T) {
	_, server, client := newOperatorServer(t, nil)
	if descriptor, err := client.Discover(t.Context()); err != nil || descriptor.APIVersion != operatorv1.APIVersion {
		t.Fatalf("Discover() = %+v, %v", descriptor, err)
	}
	if err := (&operatorclient.Client{BaseURL: server.URL(), HTTPClient: client.HTTPClient}).Health(t.Context()); err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{"/.well-known/brokerkit-operator", "/api/operator/v1/requests"} {
		response := rawRequest(t, client.HTTPClient, http.MethodGet, server.URL()+path, "", "")
		if response.status != http.StatusUnauthorized || response.cacheControl != "no-store" {
			t.Fatalf("%s = %+v", path, response)
		}
	}
	legacy := rawRequest(t, client.HTTPClient, http.MethodGet, server.URL()+"/api/grants", testOperatorSecret, "")
	if legacy.status != http.StatusNotFound {
		t.Fatalf("legacy route = %+v", legacy)
	}
}

func TestOperatorV1ListDecisionAndReplay(t *testing.T) {
	store, _, client := newOperatorServer(t, nil)
	grant := requestGrant(t, store, "decision")
	page, err := client.List(t.Context(), operatorv1.Query{Status: grants.StatusGroupPending, Requester: "bob"})
	if err != nil || len(page.Requests) != 1 || page.EventCursor == "" {
		t.Fatalf("List() = %+v, %v", page, err)
	}
	request := page.Requests[0]
	if request.ApprovalBounds == nil || request.ApprovalBounds.MaxUses != 2 || len(request.AllowedActions) != 3 {
		t.Fatalf("request = %+v", request)
	}
	command := operatorv1.Decision{ExpectedRevision: grant.Revision, IdempotencyKey: "decision-1", OnBehalfOf: "Onur",
		Constraints: &operatorv1.Constraints{DurationSeconds: 60, MaxUses: 1}}
	approved, err := client.Decide(t.Context(), grant.ID, operatorv1.ActionApprove, command)
	if err != nil || approved.Status != grants.StatusActive || approved.GrantedMaxUses == nil || *approved.GrantedMaxUses != 1 || approved.RequestedMaxUses != 2 {
		t.Fatalf("Approve() = %+v, %v", approved, err)
	}
	replay, err := client.Decide(t.Context(), grant.ID, operatorv1.ActionApprove, command)
	if err != nil || replay.Revision != approved.Revision {
		t.Fatalf("replay = %+v, %v", replay, err)
	}
	command.DecisionReason = "changed"
	if _, err := client.Decide(t.Context(), grant.ID, operatorv1.ActionApprove, command); !hasCode(err, "idempotency_conflict") {
		t.Fatalf("changed replay = %v", err)
	}
}

func TestOperatorV1StrictInputAndActivationValidation(t *testing.T) {
	rejected := errors.New("provider plan invalid")
	store, server, client := newOperatorServer(t, decision.ActivationValidatorFunc(func(context.Context, grants.Grant, grants.ApprovalConstraints) error { return rejected }))
	grant := requestGrant(t, store, "strict")
	unknown := rawRequest(t, client.HTTPClient, http.MethodPost, server.URL()+"/api/operator/v1/requests/"+grant.ID+"/approve", testOperatorSecret,
		`{"expected_revision":1,"idempotency_key":"one","operation":"replacement"}`)
	if unknown.status != http.StatusBadRequest || !strings.Contains(unknown.body, "invalid_request") {
		t.Fatalf("unknown input = %+v", unknown)
	}
	_, err := client.Decide(t.Context(), grant.ID, operatorv1.ActionApprove, operatorv1.Decision{ExpectedRevision: grant.Revision, IdempotencyKey: "decision-1"})
	if !hasCode(err, "internal_error") {
		t.Fatalf("validator error = %v", err)
	}
	current, _ := store.Get(grant.ID)
	if current.Status != grants.StatusPending {
		t.Fatalf("validator committed state: %+v", current)
	}
}

func TestOperatorV1EventStream(t *testing.T) {
	store, _, client := newOperatorServer(t, nil)
	requestGrant(t, store, "stream")
	stream, err := client.Watch(t.Context(), "")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = stream.Close() }()
	ctx, cancel := context.WithTimeout(t.Context(), time.Second)
	defer cancel()
	event, err := stream.Receive(ctx)
	if err != nil || event.Kind != "request.created" || event.RequestID == "" {
		t.Fatalf("Receive() = %+v, %v", event, err)
	}
}

func newOperatorServer(t *testing.T, validator decision.ActivationValidator) (*grants.Store, *operatorfake.Server, *operatorclient.Client) {
	t.Helper()
	store := grants.New(t.TempDir()+"/grants.json", grants.Options{})
	server, err := operatorfake.New(operatorfake.Options{Store: store, OperatorSecrets: map[string]string{"onur": testOperatorSecret},
		ClientSecrets: map[string]string{"bob": "client-secret-with-enough-entropy"}, ActivationValidator: validator,
		Presenter: operatorinbox.PresenterFunc(func(_ context.Context, grant grants.Grant) (operatorinbox.Presentation, error) {
			return operatorinbox.Presentation{Risk: operatorinbox.RiskHigh, Title: "Protected write", Target: grant.Target.Kind,
				Fields: []operatorinbox.DisplayField{{Label: "Repository", Value: "demo"}}, PlanHash: "private-plan-hash"}, nil
		})})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(server.Close)
	return store, server, server.Client(testOperatorSecret)
}

func requestGrant(t *testing.T, store *grants.Store, id string) grants.Grant {
	t.Helper()
	result, _, err := store.Request(grants.Request{Client: "bob", ClientRequestID: id, Operation: "provider.write",
		Target: policy.Target{Kind: "repository", Fields: map[string][]string{"name": {"demo"}}}, Reason: "test request", Duration: 5 * time.Minute, MaxUses: 2})
	if err != nil {
		t.Fatal(err)
	}
	return result.Grant
}

type rawResponse struct {
	status       int
	body         string
	cacheControl string
}

func rawRequest(t *testing.T, client *http.Client, method, url, token, body string) rawResponse {
	t.Helper()
	request, err := http.NewRequestWithContext(t.Context(), method, url, strings.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	if token != "" {
		request.Header.Set("Authorization", "Bearer "+token)
	}
	if body != "" {
		request.Header.Set("Content-Type", "application/json")
	}
	response, err := client.Do(request)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = response.Body.Close() }()
	data, _ := io.ReadAll(response.Body)
	return rawResponse{response.StatusCode, string(data), response.Header.Get("Cache-Control")}
}

func hasCode(err error, code string) bool {
	var apiErr *operatorclient.Error
	return errors.As(err, &apiErr) && apiErr.Code == code
}
