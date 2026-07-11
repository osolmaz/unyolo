package httpapi

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"
	"time"

	"github.com/osolmaz/brokerkit/brokers/github/internal/config"
	"github.com/osolmaz/brokerkit/brokers/github/internal/policy"
	"github.com/osolmaz/brokerkit/conformance"
	"github.com/osolmaz/brokerkit/grants"
	"github.com/osolmaz/brokerkit/operatorclient"
	"github.com/osolmaz/brokerkit/operatorv1"
	corepolicy "github.com/osolmaz/brokerkit/policy"
)

func TestBrokerkitControlPlaneConformance(t *testing.T) {
	clientSecret := "client-secret-abcdefghijklmnopqrstuvwxyz"
	operatorSecret := "operator-secret-abcdefghijklmnopqrstuvwxyz"
	server, _ := newOperatorTestServer(t, clientSecret, operatorSecret)
	conformance.RunOperatorV1(t, conformance.Fixture{
		Runtime: server.control, ClientToken: clientSecret, OperatorToken: operatorSecret,
		Request: grants.Request{
			Client: "bob", ClientRequestID: "conformance", Operation: "git.push.force",
			Target: corepolicy.Target{Kind: "repo", Fields: map[string][]string{
				"owner": {"osolmaz"}, "name": {"gh-broker"},
			}},
			Attrs: map[string][]string{"ref": {"refs/heads/main"}}, Reason: "verify shared control plane", Duration: 5 * time.Minute,
		},
	})
}

func TestOperatorHandlerSharesCanonicalGitHubGrantState(t *testing.T) {
	clientSecret := "client-secret-abcdefghijklmnopqrstuvwxyz"
	operatorSecret := "operator-secret-abcdefghijklmnopqrstuvwxyz"
	server, cfg := newOperatorTestServer(t, clientSecret, operatorSecret)
	result := requestOperatorTestGrant(t, server)
	operatorServer := newOperatorHTTPServer(t, server, cfg)
	client := &operatorclient.Client{BaseURL: operatorServer.URL, Token: operatorSecret, HTTPClient: operatorServer.Client()}
	page, err := client.List(t.Context(), operatorv1.Query{Status: grants.StatusGroupPending})
	if err != nil || len(page.Requests) != 1 || len(page.Requests[0].Presentation.Facts) == 0 {
		t.Fatalf("List() = %+v, %v", page, err)
	}
	approved, err := client.Decide(t.Context(), result.Grant.ID, operatorv1.ActionApprove, operatorv1.Decision{
		ExpectedRevision: page.Requests[0].Revision, IdempotencyKey: "operator-test-approve",
		Constraints: &operatorv1.Constraints{MaxUses: 1},
	})
	if err != nil || approved.Status != grants.StatusActive {
		t.Fatalf("Approve() = %+v, %v", approved, err)
	}
	if _, err := server.grants.Deny(result.Grant.ID, result.DecisionToken, "telegram:onur"); !errors.Is(err, grants.ErrNotPending) {
		t.Fatalf("Telegram replay error = %v", err)
	}
	assertOperatorRejectsClientSecret(t, operatorServer, clientSecret)
}

func newOperatorTestServer(t *testing.T, clientSecret string, operatorSecret string) (*Server, config.Config) {
	t.Helper()
	brokerPolicy, err := policy.New(policy.Scope{})
	if err != nil {
		t.Fatal(err)
	}
	cfg := config.Config{
		ClientID: "bob", SharedSecret: clientSecret, OperatorID: "onur", OperatorSecret: operatorSecret,
		StateDir: filepath.Join(t.TempDir(), "state"), GitHubToken: "github-token", GitHubHTTPTimeout: time.Second,
	}
	server, err := New(cfg, brokerPolicy)
	if err != nil {
		t.Fatal(err)
	}
	return server, cfg
}

func requestOperatorTestGrant(t *testing.T, server *Server) grants.RequestResult {
	t.Helper()
	result, _, err := server.grants.Request(grants.Request{
		Client: "bob", ClientRequestID: "operator-test", Operation: "git.push.force",
		Target: corepolicy.Target{Kind: "repo", Fields: map[string][]string{"owner": {"osolmaz"}, "name": {"gh-broker"}}},
		Attrs:  map[string][]string{"ref": {"refs/heads/main"}}, Reason: "repair branch", Duration: 5 * time.Minute, MaxUses: 1,
	})
	if err != nil {
		t.Fatal(err)
	}
	return result
}

func newOperatorHTTPServer(t *testing.T, server *Server, cfg config.Config) *httptest.Server {
	t.Helper()
	operatorServer := httptest.NewServer(server.OperatorHandler())
	t.Cleanup(operatorServer.Close)
	return operatorServer
}

func assertOperatorRejectsClientSecret(t *testing.T, operatorServer *httptest.Server, clientSecret string) {
	t.Helper()
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
