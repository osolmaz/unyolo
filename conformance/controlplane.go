// Package conformance provides reusable black-box broker contract tests.
package conformance

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/osolmaz/brokerkit/controlplane"
	"github.com/osolmaz/brokerkit/grants"
	"github.com/osolmaz/brokerkit/operatorclient"
)

// Fixture describes one broker's real shared control-plane assembly.
type Fixture struct {
	Runtime       *controlplane.Runtime
	Request       grants.Request
	ClientToken   string
	OperatorToken string
}

// RunControlPlane verifies the common broker contract against a real HTTP server.
func RunControlPlane(t *testing.T, fixture Fixture) {
	t.Helper()
	if fixture.Runtime == nil {
		t.Fatal("conformance runtime is required")
	}
	created := requestGrant(t, fixture)
	server := httptest.NewServer(fixture.Runtime.OperatorHandler)
	t.Cleanup(server.Close)
	assertRejectedCredential(t, server, fixture.ClientToken)
	assertRejectedCredential(t, server, "unknown-operator-secret-abcdefghijklmnopqrstuvwxyz")
	assertOperatorLifecycle(t, fixture, server, created)
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
	page, err := client.List(t.Context(), grants.Query{StatusGroup: grants.StatusGroupPending})
	if err != nil || len(page.Items) != 1 || page.Items[0].ID != created.Grant.ID {
		t.Fatalf("operator list = %+v, %v", page, err)
	}
	approved, err := client.Approve(t.Context(), created.Grant.ID, operatorclient.Decision{
		ExpectedRevision: created.Grant.Revision, ExpectedStatus: grants.StatusPending,
	})
	if err != nil || approved.Status != grants.StatusActive {
		t.Fatalf("operator approve = %+v, %v", approved, err)
	}
	detail, err := client.Get(t.Context(), created.Grant.ID)
	if err != nil || detail.Status != grants.StatusActive || detail.Revision <= created.Grant.Revision {
		t.Fatalf("operator detail = %+v, %v", detail, err)
	}
}

func assertRejectedCredential(t *testing.T, server *httptest.Server, token string) {
	t.Helper()
	request, err := http.NewRequestWithContext(t.Context(), http.MethodGet, server.URL+"/api/grants", nil)
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
