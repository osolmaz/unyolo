package operatorapi_test

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/osolmaz/brokerkit/audit"
	"github.com/osolmaz/brokerkit/grants"
	"github.com/osolmaz/brokerkit/operatorclient"
	"github.com/osolmaz/brokerkit/operatorfake"
	"github.com/osolmaz/brokerkit/operatorinbox"
	"github.com/osolmaz/brokerkit/policy"
)

const testOperatorSecret = "operator-secret-with-enough-entropy"

func TestOperatorAPIClientCoversQueriesAndDecisions(t *testing.T) { //nolint:cyclop,gocognit // End-to-end contract scenario covers every decision route.
	store, server, client := newOperatorServer(t)
	first := requestGrant(t, store, "approve")
	second := requestGrant(t, store, "deny")
	third := requestGrant(t, store, "cancel")

	page, err := client.List(context.Background(), grants.Query{StatusGroup: grants.StatusGroupPending, Client: "bob", Limit: 10})
	if err != nil || len(page.Items) != 3 {
		t.Fatalf("List() = %+v, %v", page, err)
	}
	approved, err := client.Approve(context.Background(), first.ID, operatorclient.Decision{
		ExpectedRevision: first.Revision, ExpectedStatus: grants.StatusPending, Duration: time.Minute, MaxUses: 1,
	})
	if err != nil || approved.Status != grants.StatusActive || approved.Revision != first.Revision+1 {
		t.Fatalf("Approve() = %+v, %v", approved, err)
	}
	_, err = client.Revoke(context.Background(), first.ID, operatorclient.Decision{ExpectedRevision: first.Revision})
	var conflict *operatorclient.Error
	if !errors.As(err, &conflict) || conflict.Code != "revision_conflict" || conflict.Current == nil || conflict.Current.Revision != approved.Revision {
		t.Fatalf("stale Revoke() error = %#v", err)
	}
	revoked, err := client.Revoke(context.Background(), first.ID, operatorclient.Decision{ExpectedRevision: approved.Revision})
	if err != nil || revoked.Status != grants.StatusRevoked {
		t.Fatalf("Revoke() = %+v, %v", revoked, err)
	}
	denied, err := client.Deny(context.Background(), second.ID, operatorclient.Decision{ExpectedRevision: second.Revision, Reason: "not approved"})
	if err != nil || denied.Status != grants.StatusDenied {
		t.Fatalf("Deny() = %+v, %v", denied, err)
	}
	canceled, err := client.Cancel(context.Background(), third.ID, operatorclient.Decision{ExpectedRevision: third.Revision})
	if err != nil || canceled.Status != grants.StatusCanceled {
		t.Fatalf("Cancel() = %+v, %v", canceled, err)
	}

	request, err := http.NewRequestWithContext(context.Background(), http.MethodGet, server.URL()+"/api/grants", nil)
	if err != nil {
		t.Fatal(err)
	}
	response, err := server.Client("").HTTPClient.Do(request)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = response.Body.Close() }()
	if response.StatusCode != http.StatusUnauthorized || response.Header.Get("Cache-Control") != "no-store" {
		t.Fatalf("unauthorized status = %d headers=%v", response.StatusCode, response.Header)
	}
}

func TestOperatorAPIStrictBodiesAndSafeResponses(t *testing.T) {
	store, server, _ := newOperatorServer(t)
	grant := requestGrant(t, store, "strict")
	request, err := http.NewRequestWithContext(context.Background(), http.MethodPost, server.URL()+"/api/grants/"+grant.ID+"/approve", strings.NewReader(`{"expected_revision":1,"operation":"replacement"}`))
	if err != nil {
		t.Fatal(err)
	}
	request.Header.Set("Authorization", "Bearer "+testOperatorSecret)
	request.Header.Set("Content-Type", "application/json")
	response, err := server.Client(testOperatorSecret).HTTPClient.Do(request)
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(response.Body)
	_ = response.Body.Close()
	if response.StatusCode != http.StatusBadRequest || !strings.Contains(string(body), "invalid_body") {
		t.Fatalf("strict response = %d %s", response.StatusCode, body)
	}
	for _, protected := range []string{"decision_token", "verifier", "replacement"} {
		if strings.Contains(string(body), protected) {
			t.Fatalf("error response leaked %q: %s", protected, body)
		}
	}
}

func TestOperatorClientStreamsDurableEvents(t *testing.T) {
	store, _, client := newOperatorServer(t)
	requestGrant(t, store, "stream")
	wantStop := errors.New("stop stream")
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	err := client.StreamEvents(ctx, "", func(event grants.Event) error {
		if event.Kind != grants.EventRequestCreated || event.Cursor == "" {
			t.Fatalf("event = %+v", event)
		}
		return wantStop
	})
	if !errors.Is(err, wantStop) {
		t.Fatalf("StreamEvents() error = %v", err)
	}
}

func TestOperatorDecisionWritesSharedAuditFields(t *testing.T) {
	store := grants.New(t.TempDir()+"/grants.json", grants.Options{})
	var output bytes.Buffer
	server, err := operatorfake.New(operatorfake.Options{
		Store: store, OperatorSecrets: map[string]string{"onur": testOperatorSecret},
		Broker: "audit-broker", Audit: audit.New(&output),
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(server.Close)
	grant := requestGrant(t, store, "audit")
	if _, err := server.Client(testOperatorSecret).Deny(t.Context(), grant.ID, operatorclient.Decision{
		ExpectedRevision: grant.Revision, Reason: "reviewed",
	}); err != nil {
		t.Fatal(err)
	}
	line := output.String()
	for _, expected := range []string{`"broker":"audit-broker"`, `"approver":"onur"`, `"decision":"deny"`, `"previous_status":"pending"`, `"next_status":"denied"`, `"event_cursor"`} {
		if !strings.Contains(line, expected) {
			t.Fatalf("audit record missing %s: %s", expected, line)
		}
	}
}

func TestOperatorAPIRouteAndErrorContract(t *testing.T) { //nolint:cyclop // Route table intentionally covers all HTTP mappings.
	store, server, _ := newOperatorServer(t)
	grant := requestGrant(t, store, "errors")
	tests := []struct {
		method      string
		path        string
		contentType string
		body        string
		status      int
		code        string
	}{
		{http.MethodGet, "/api/grants?status=invalid", "", "", 400, "invalid_query"},
		{http.MethodGet, "/api/grants?limit=no", "", "", 400, "invalid_query"},
		{http.MethodGet, "/api/grants?target.name=demo", "", "", 400, "invalid_query"},
		{http.MethodGet, "/api/grants/missing", "", "", 404, "not_found"},
		{http.MethodGet, "/api/grants/events?cursor=bad", "", "", 400, "invalid_cursor"},
		{http.MethodPost, "/api/grants/" + grant.ID + "/deny", "", `{}`, 415, "unsupported_media_type"},
		{http.MethodPost, "/api/grants/" + grant.ID + "/deny", "application/json", `{"expected_revision":0}`, 400, "invalid_command"},
		{http.MethodPost, "/api/grants/" + grant.ID + "/unknown", "application/json", `{"expected_revision":1}`, 404, "not_found"},
		{http.MethodGet, "/api/grants/" + grant.ID + "/deny", "", "", 405, "method_not_allowed"},
		{http.MethodPost, "/api/grants", "application/json", `{}`, 405, "method_not_allowed"},
		{http.MethodGet, "/unknown", "", "", 404, "not_found"},
		{http.MethodGet, "/api/grants/", "", "", 200, "items"},
		{http.MethodGet, "/api/grants/a/b/c", "", "", 404, "not_found"},
	}
	for _, test := range tests {
		request, err := http.NewRequestWithContext(t.Context(), test.method, server.URL()+test.path, strings.NewReader(test.body))
		if err != nil {
			t.Fatal(err)
		}
		request.Header.Set("Authorization", "Bearer "+testOperatorSecret)
		if test.contentType != "" {
			request.Header.Set("Content-Type", test.contentType)
		}
		response, err := server.Client(testOperatorSecret).HTTPClient.Do(request)
		if err != nil {
			t.Fatal(err)
		}
		body, _ := io.ReadAll(response.Body)
		_ = response.Body.Close()
		if response.StatusCode != test.status || !strings.Contains(string(body), test.code) {
			t.Fatalf("%s %s = %d %s, want %d %s", test.method, test.path, response.StatusCode, body, test.status, test.code)
		}
	}
	denied, err := server.Client(testOperatorSecret).Deny(t.Context(), grant.ID, operatorclient.Decision{ExpectedRevision: grant.Revision})
	if err != nil {
		t.Fatal(err)
	}
	_, err = server.Client(testOperatorSecret).Deny(t.Context(), grant.ID, operatorclient.Decision{ExpectedRevision: denied.Revision})
	var apiErr *operatorclient.Error
	if !errors.As(err, &apiErr) || apiErr.Code != "invalid_state" {
		t.Fatalf("second deny error = %#v", err)
	}
	page, err := server.Client(testOperatorSecret).List(t.Context(), grants.Query{
		Target: &policy.Target{Kind: "repository", Fields: map[string][]string{"name": {"demo"}}},
	})
	if err != nil || len(page.Items) == 0 {
		t.Fatalf("target List() = %+v, %v", page, err)
	}
}

func TestOperatorAPIReportsExpiredEventCursor(t *testing.T) {
	store := grants.New(t.TempDir()+"/grants.json", grants.Options{MaxEvents: 2})
	server, err := operatorfake.New(operatorfake.Options{
		Store: store, OperatorSecrets: map[string]string{"onur": testOperatorSecret},
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(server.Close)
	requestGrant(t, store, "cursor-first")
	initial, err := store.EventsAfter("", 1)
	if err != nil {
		t.Fatal(err)
	}
	requestGrant(t, store, "cursor-second")
	requestGrant(t, store, "cursor-third")
	requestGrant(t, store, "cursor-fourth")
	request, err := http.NewRequestWithContext(t.Context(), http.MethodGet, server.URL()+"/api/grants/events?cursor="+initial.NextCursor, nil)
	if err != nil {
		t.Fatal(err)
	}
	request.Header.Set("Authorization", "Bearer "+testOperatorSecret)
	response, err := server.Client(testOperatorSecret).HTTPClient.Do(request)
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(response.Body)
	_ = response.Body.Close()
	if response.StatusCode != http.StatusGone || !strings.Contains(string(body), "cursor_expired") {
		t.Fatalf("expired cursor = %d %s", response.StatusCode, body)
	}
}

func newOperatorServer(t *testing.T) (*grants.Store, *operatorfake.Server, *operatorclient.Client) {
	t.Helper()
	store := grants.New(t.TempDir()+"/grants.json", grants.Options{})
	server, err := operatorfake.New(operatorfake.Options{
		Store: store, OperatorSecrets: map[string]string{"onur": testOperatorSecret},
		ClientSecrets: map[string]string{"bob": "client-secret-with-enough-entropy"},
		Presenter: operatorinbox.PresenterFunc(func(_ context.Context, grant grants.Grant) (operatorinbox.Presentation, error) {
			return operatorinbox.Presentation{Risk: operatorinbox.RiskHigh, Title: "Protected write", Target: grant.Target.Kind}, nil
		}),
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(server.Close)
	return store, server, server.Client(testOperatorSecret)
}

func requestGrant(t *testing.T, store *grants.Store, id string) operatorinbox.Item {
	t.Helper()
	result, _, err := store.Request(grants.Request{
		Client: "bob", ClientRequestID: id, Operation: "provider.write",
		Target: policy.Target{Kind: "repository", Fields: map[string][]string{"name": {"demo"}}},
		Reason: "test request", Duration: 5 * time.Minute, MaxUses: 2,
	})
	if err != nil {
		t.Fatal(err)
	}
	return operatorinbox.Item{ID: result.Grant.ID, Revision: result.Grant.Revision}
}
