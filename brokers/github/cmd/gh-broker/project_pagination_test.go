package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	agentclient "github.com/osolmaz/unyolo/agent/client"
	agentv1 "github.com/osolmaz/unyolo/agent/v1"
	"github.com/osolmaz/unyolo/brokers/github/internal/apicompat"
	"github.com/osolmaz/unyolo/brokers/github/internal/config"
	"github.com/osolmaz/unyolo/brokers/github/internal/httpapi"
	"github.com/osolmaz/unyolo/brokers/github/internal/policy"
)

func TestProjectInventoryCompatRouteUnavailable(t *testing.T) {
	match, err := apicompat.MatchREST(http.MethodGet, "/orgs/github/projectsV2/1/items")
	if err != nil {
		t.Fatal(err)
	}
	_, err = match.Request(url.Values{"per_page": {"1"}}, nil)
	if err == nil || !strings.Contains(err.Error(), "not scoped to one repository") {
		t.Fatalf("unexpected compatibility route qualification: %v", err)
	}
}

// No Git fixture or external provider: real loopback HTTP, auth executor,
// durable operation runtime/database, generated Agent client, and CLI writer.
func TestProjectPaginationDurableCLI(t *testing.T) {
	t.Setenv("HOME", t.TempDir()) // CLI config resolution must not read the operator's home.
	// Keep this regression independent of changes to the item-content projection.
	const item = `{"created_at":"2025-08-01T18:44:51Z","id":13,"node_id":"PVTI_lAAFAQ0","updated_at":"2025-08-06T19:25:18Z"}`
	var calls atomic.Int32
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		if r.Method != "GET" || r.URL.Path != "/orgs/github/projectsV2/1/items" || r.Header.Get("Authorization") != "Bearer offline-pagination-canary" {
			t.Error("unexpected upstream request shape/authentication")
			w.WriteHeader(500)
			return
		}
		if r.URL.Query().Get("fields") != "3" || r.URL.Query().Get("per_page") != "1" {
			t.Error("request selectors lost")
		}
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Query().Get("after") {
		case "":
			w.Header().Set("Link", `<http://`+r.Host+r.URL.Path+`?after=cursor2&fields=3&per_page=1>; rel="next"`)
		case "cursor2":
			w.Header().Add("Link", `<http://`+r.Host+r.URL.Path+`?after=cursor3&fields=3&per_page=1>; rel="next"`)
			w.Header().Add("Link", `<http://`+r.Host+r.URL.Path+`?before=cursor1&fields=3&per_page=1>; rel="prev"`)
		case "cursor3": // Explicit no-Link terminal page, still nonempty.
		case "empty":
			_, _ = io.WriteString(w, "[]")
			return
		case "empty-malformed":
			w.Header().Set("Link", "not-a-link")
			_, _ = io.WriteString(w, "[]")
			return
		case "blank":
			return
		case "wrong-target":
			w.Header().Set("Link", `<http://`+r.Host+`/orgs/other/projectsV2/1/items?after=cursor2&fields=3&per_page=1>; rel="next"`)
		case "malformed":
			w.Header().Set("Link", `not-a-link-secret-canary`)
		case "signed":
			w.Header().Set("Link", `<http://`+r.Host+r.URL.Path+`?after=cursor2&fields=3&per_page=1&token=secret-canary>; rel="next"`)
		case "transport":
			w.Header().Set("Content-Length", "99999")
		case "invalid-json":
			_, _ = io.WriteString(w, "[")
			return
		default:
			t.Error("unexpected cursor")
		}
		_, _ = io.WriteString(w, "["+item+"]")
	}))
	defer upstream.Close()
	p, err := policy.New(policy.Scope{Rules: []policy.Rule{{ID: "offline-list", Effect: policy.EffectAllow, Clients: []string{"agent"}, Operations: []policy.Operation{"project.projects_list_items_for_org"}, Targets: []policy.Target{{Kind: "organization", Name: "github"}}, Attrs: map[string][]string{"selector_project_number": {"1"}}}}})
	if err != nil {
		t.Fatal(err)
	}
	cfg := config.Config{ClientID: "agent", SharedSecret: operationTestSecret, GitHubToken: "offline-pagination-canary", GitHubTokenFile: "/offline/unused", GitHubAPIBaseURL: upstream.URL, GitHubWebBaseURL: upstream.URL, StateDir: t.TempDir()}
	start := func() (*agentclient.Client, func()) {
		t.Helper()
		broker, err := httpapi.New(cfg, p)
		if err != nil {
			t.Fatal(err)
		}
		ctx, cancel := context.WithCancel(t.Context())
		broker.Start(ctx)
		endpoint := httptest.NewServer(broker.Handler())
		t.Setenv("GH_BROKER_AGENT_ENDPOINT", ghTestEndpoint(endpoint.URL))
		t.Setenv("GH_BROKER_SHARED_SECRET", operationTestSecret)
		client, err := agentclient.New(agentclient.Options{Endpoint: ghTestEndpoint(endpoint.URL), Credential: operationTestSecret, HTTPClient: endpoint.Client()})
		if err != nil {
			t.Fatal(err)
		}
		return client, func() {
			endpoint.Close()
			cancel()
			if err := broker.Close(); err != nil {
				t.Error(err)
			}
		}
	}
	client, stop := start()
	stopped := false
	defer func() {
		if !stopped {
			stop()
		}
	}()
	var completed []agentv1.Operation
	for index, cursor := range []string{"", "cursor2", "cursor3"} {
		args := map[string]any{"project_number": 1, "fields": "3", "per_page": 1}
		if cursor != "" {
			args["after"] = cursor
		}
		raw, _ := json.Marshal(args)
		ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
		op, err := client.Submit(ctx, agentv1.SubmitRequest{IdempotencyKey: fmt.Sprintf("pagination-%d", index), Operation: "project.projects_list_items_for_org", Target: json.RawMessage(`{"kind":"organization","name":"github"}`), Arguments: raw, Reason: "offline pagination qualification"})
		if err == nil {
			op, err = client.Wait(ctx, op)
		}
		cancel()
		if err != nil || op.State != agentv1.StateSucceeded {
			t.Fatalf("execution state=%s err=%v detail=%+v", op.State, err, op.Error)
		}
		assertProjectPage(t, op, item, index)
		completed = append(completed, op)
	}
	for _, test := range []struct {
		cursor string
		failed bool
	}{
		{"empty", false}, {"empty-malformed", false}, {"blank", false}, {"wrong-target", false}, {"malformed", false}, {"signed", false}, {"transport", true}, {"invalid-json", true},
	} {
		raw, _ := json.Marshal(map[string]any{"project_number": 1, "fields": "3", "per_page": 1, "after": test.cursor})
		ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
		op, err := client.Submit(ctx, agentv1.SubmitRequest{IdempotencyKey: "pagination-" + test.cursor, Operation: "project.projects_list_items_for_org", Target: json.RawMessage(`{"kind":"organization","name":"github"}`), Arguments: raw, Reason: "offline negative qualification"})
		if err == nil {
			op, err = client.Wait(ctx, op)
		}
		cancel()
		if err != nil {
			t.Fatal(err)
		}
		if test.failed {
			if op.State != agentv1.StateFailed || len(op.Result) != 0 {
				t.Fatalf("%s falsely succeeded or returned a result", test.cursor)
			}
		} else {
			if op.State != agentv1.StateSucceeded {
				t.Fatalf("%s state=%s error=%+v", test.cursor, op.State, op.Error)
			}
			want := `{"items":[` + item + `]}`
			if test.cursor == "empty" {
				want = `{"items":[],"pagination":{"has_next":false}}`
			}
			if test.cursor == "empty-malformed" || test.cursor == "blank" {
				want = `{"items":[]}`
			}
			if string(op.Result) != want {
				t.Fatalf("%s result changed, leaked unsafe metadata or falsely complete", test.cursor)
			}
		}
		completed = append(completed, op)
	}
	wantCalls := int32(len(completed))
	if calls.Load() != wantCalls {
		t.Fatalf("calls=%d, want %d explicit pages (no autofollow)", calls.Load(), wantCalls)
	}
	stop()
	stopped = true
	// Fresh process dependencies/database handle, read only old operations.
	client, stop = start()
	stopped = false
	for index, old := range completed {
		op, err := client.Get(t.Context(), old.ID)
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(op.Result, old.Result) {
			t.Fatal("persisted result bytes changed on reopen")
		}
		if op.State != old.State {
			t.Fatal("persisted operation state changed on reopen")
		}
		if index < 3 {
			assertProjectPage(t, op, item, index)
		}
		var stdout, stderr bytes.Buffer
		if err := runOperation(t.Context(), &stdout, &stderr, []string{"get", op.ID}); err != nil {
			t.Fatalf("CLI get failed: %v", err)
		}
		var serialized agentv1.Operation
		if json.Unmarshal(stdout.Bytes(), &serialized) != nil {
			t.Fatal("invalid CLI JSON")
		}
		if serialized.State != op.State {
			t.Fatal("CLI changed operation state")
		}
		for _, excluded := range []string{"secret-canary", "offline-pagination-canary", `"Link"`, `"headers"`, "totalCount", "total_count"} {
			if strings.Contains(stdout.String()+stderr.String(), excluded) {
				t.Fatal("CLI leaked or invented metadata")
			}
		}
		// CLI pretty-printing is immaterial; exact compact result bytes must survive.
		if len(op.Result) > 0 {
			compact := new(bytes.Buffer)
			if err := json.Compact(compact, serialized.Result); err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(compact.Bytes(), op.Result) {
				t.Fatal("CLI changed result content")
			}
		} else if len(serialized.Result) != 0 {
			t.Fatal("CLI invented a result on failure")
		}
	}
	if calls.Load() != wantCalls {
		t.Fatal("readback reissued provider calls")
	}
}

func assertProjectPage(t *testing.T, op agentv1.Operation, item string, index int) {
	t.Helper()
	var page struct {
		Items      json.RawMessage `json:"items"`
		Pagination *struct {
			HasNext   bool   `json:"has_next"`
			NextAfter string `json:"next_after,omitempty"`
		} `json:"pagination"`
	}
	if err := json.Unmarshal(op.Result, &page); err != nil {
		t.Fatal(err)
	}
	if string(page.Items) != "["+item+"]" {
		t.Fatalf("original projected item tuple/array bytes changed: got %d want %d", len(page.Items), len(item)+2)
	}
	if page.Pagination == nil {
		t.Fatal("pagination metadata missing from persisted/client result")
	}
	wantNext := ""
	if index < 2 {
		wantNext = fmt.Sprintf("cursor%d", index+2)
	}
	if page.Pagination.HasNext != (index < 2) || page.Pagination.NextAfter != wantNext {
		t.Fatalf("wrong pagination facts: %+v", page.Pagination)
	}
	for _, excluded := range []string{"offline-pagination-canary", "total_count", "totalCount", `"Link"`, `"headers"`} {
		if strings.Contains(string(op.Result), excluded) {
			t.Fatal("unsafe/invented metadata")
		}
	}
	t.Logf("page %d: retained %d original array bytes; has_next=%v next_after=%q", index+1, len(page.Items), page.Pagination.HasNext, page.Pagination.NextAfter)
}
