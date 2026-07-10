package httpapi

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"
	"time"

	bkaudit "github.com/osolmaz/brokerkit/audit"
	bkgrants "github.com/osolmaz/brokerkit/grants"
	"github.com/osolmaz/brokerkit/operatorclient"
	bkpolicy "github.com/osolmaz/brokerkit/policy"
	"github.com/osolmaz/hf-broker/internal/config"
	"github.com/osolmaz/hf-broker/internal/policy"
)

func TestOperatorHandlerSharesCanonicalHFGrantState(t *testing.T) {
	clientSecret := "client-secret-abcdefghijklmnopqrstuvwxyz"
	operatorSecret := "operator-secret-abcdefghijklmnopqrstuvwxyz"
	scope, err := policy.Parse([]byte(`{"rules":[]}`))
	if err != nil {
		t.Fatal(err)
	}
	cfg := config.Config{
		HFToken: "hf_test", Clients: []config.Client{{Name: "bob", Secret: clientSecret}},
		Operators: []config.Client{{Name: "onur", Secret: operatorSecret}},
		StateDir:  filepath.Join(t.TempDir(), "state"), MaxPackBytes: 1024, HFTimeout: time.Second,
	}
	server, err := New(Options{Config: cfg, Scope: scope, UpstreamBaseURL: "http://127.0.0.1:1"})
	if err != nil {
		t.Fatal(err)
	}
	result, _, err := server.grants.Core().Request(bkgrants.Request{
		Client: "bob", ClientRequestID: "operator-test", Operation: "git.push.force",
		Target:   bkpolicy.Target{Kind: "hf", Fields: map[string][]string{"name": {"dataset/acme/demo"}, "ref": {"refs/heads/main"}}},
		Metadata: map[string]string{"hf_grant_mode": "window"}, Reason: "repair branch", Duration: 5 * time.Minute,
	})
	if err != nil {
		t.Fatal(err)
	}
	handler, err := server.OperatorHandler(cfg, bkaudit.New(io.Discard))
	if err != nil {
		t.Fatal(err)
	}
	operatorServer := httptest.NewServer(handler)
	t.Cleanup(operatorServer.Close)
	client := &operatorclient.Client{BaseURL: operatorServer.URL, Token: operatorSecret, HTTPClient: operatorServer.Client()}
	page, err := client.List(t.Context(), bkgrants.Query{StatusGroup: bkgrants.StatusGroupPending})
	if err != nil || len(page.Items) != 1 || page.Items[0].Presentation.Target != "dataset/acme/demo" {
		t.Fatalf("List() = %+v, %v", page, err)
	}
	approved, err := client.Approve(t.Context(), result.Grant.ID, operatorclient.Decision{ExpectedRevision: page.Items[0].Revision, MaxUses: 1})
	if err != nil || approved.Status != bkgrants.StatusActive {
		t.Fatalf("Approve() = %+v, %v", approved, err)
	}
	if _, err := server.grants.Core().Deny(result.Grant.ID, result.DecisionToken, "telegram:onur"); !errors.Is(err, bkgrants.ErrNotPending) {
		t.Fatalf("Telegram replay error = %v", err)
	}

	request, err := http.NewRequestWithContext(context.Background(), http.MethodGet, operatorServer.URL+"/api/grants", nil)
	if err != nil {
		t.Fatal(err)
	}
	request.Header.Set("Authorization", "Bearer "+clientSecret)
	response, err := operatorServer.Client().Do(request)
	if err != nil {
		t.Fatal(err)
	}
	_ = response.Body.Close()
	if response.StatusCode != http.StatusUnauthorized {
		t.Fatalf("client credential status = %d", response.StatusCode)
	}
}
