package httpapi

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"
	"time"

	"github.com/osolmaz/brokerkit/brokers/huggingface/internal/config"
	"github.com/osolmaz/brokerkit/brokers/huggingface/internal/policy"
	"github.com/osolmaz/brokerkit/conformance"
	bkgrants "github.com/osolmaz/brokerkit/grants"
	"github.com/osolmaz/brokerkit/operatorclient"
	"github.com/osolmaz/brokerkit/operatorv1"
	bkpolicy "github.com/osolmaz/brokerkit/policy"
)

func TestBrokerkitControlPlaneConformance(t *testing.T) {
	clientSecret := "client-secret-abcdefghijklmnopqrstuvwxyz"
	operatorSecret := "operator-secret-abcdefghijklmnopqrstuvwxyz"
	scope, err := policy.Parse([]byte(`{"rules":[]}`))
	if err != nil {
		t.Fatal(err)
	}
	server, err := New(Options{
		Config: config.Config{
			HFToken: "hf_test", Clients: []config.Client{{Name: "bob", Secret: clientSecret}},
			Operators: []config.Client{{Name: "onur", Secret: operatorSecret}},
			StateDir:  filepath.Join(t.TempDir(), "state"), MaxPackBytes: 1024, HFTimeout: time.Second,
		},
		Scope: scope, UpstreamBaseURL: "http://127.0.0.1:1",
	})
	if err != nil {
		t.Fatal(err)
	}
	conformance.RunOperatorV1(t, conformance.Fixture{
		Runtime: server.control, ClientToken: clientSecret, OperatorToken: operatorSecret,
		Request: bkgrants.Request{
			Client: "bob", ClientRequestID: "conformance", Operation: "git.push.force",
			Target: bkpolicy.Target{Kind: "hf", Fields: map[string][]string{
				"name": {"dataset/acme/conformance"}, "ref": {"refs/heads/main"},
			}},
			Metadata: map[string]string{"hf_grant_mode": "window"}, Reason: "verify shared control plane", Duration: 5 * time.Minute,
		},
	})
}

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
	result, _, err := server.grants.Request(bkgrants.Request{
		Client: "bob", ClientRequestID: "operator-test", Operation: "git.push.force",
		Target:   bkpolicy.Target{Kind: "hf", Fields: map[string][]string{"name": {"dataset/acme/demo"}, "ref": {"refs/heads/main"}}},
		Metadata: map[string]string{"hf_grant_mode": "window"}, Reason: "repair branch", Duration: 5 * time.Minute,
	})
	if err != nil {
		t.Fatal(err)
	}
	operatorServer := httptest.NewServer(server.OperatorHandler())
	t.Cleanup(operatorServer.Close)
	client := &operatorclient.Client{BaseURL: operatorServer.URL, Token: operatorSecret, HTTPClient: operatorServer.Client()}
	page, err := client.List(t.Context(), operatorv1.Query{Status: bkgrants.StatusGroupPending})
	if err != nil || len(page.Requests) != 1 || len(page.Requests[0].Presentation.Facts) == 0 {
		t.Fatalf("List() = %+v, %v", page, err)
	}
	approved, err := client.Decide(t.Context(), result.Grant.ID, operatorv1.ActionApprove, operatorv1.Decision{
		ExpectedRevision: page.Requests[0].Revision, IdempotencyKey: "operator-test-approve",
		Constraints: &operatorv1.Constraints{MaxUses: 1},
	})
	if err != nil || approved.Status != bkgrants.StatusActive {
		t.Fatalf("Approve() = %+v, %v", approved, err)
	}
	if _, err := server.grants.Deny(result.Grant.ID, result.DecisionToken, "telegram:onur"); !errors.Is(err, bkgrants.ErrNotPending) {
		t.Fatalf("Telegram replay error = %v", err)
	}

	request, err := http.NewRequestWithContext(context.Background(), http.MethodGet, operatorServer.URL+"/api/operator/v1/requests", nil)
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
