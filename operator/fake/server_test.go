package operatorfake

import (
	"context"
	"io"
	"testing"

	"github.com/osolmaz/unyolo/approval/view"
	"github.com/osolmaz/unyolo/authorization/grants"
	"github.com/osolmaz/unyolo/authorization/policy"
	"github.com/osolmaz/unyolo/operator/v1"
	"github.com/osolmaz/unyolo/telemetry/audit"
)

func TestServerRunsProductionOperatorContract(t *testing.T) {
	if _, err := New(Options{}); err == nil {
		t.Fatal("New() accepted no store")
	}
	store := grants.New(t.TempDir()+"/grants.json", grants.Options{})
	if _, err := New(Options{Store: store}); err == nil {
		t.Fatal("New() accepted no operator credentials")
	}
	server, err := New(Options{
		Store: store, OperatorSecrets: map[string]string{"onur": "operator-secret-with-enough-entropy"},
		Audit: audit.New(io.Discard),
		Presenter: approvalview.PresenterFunc(func(context.Context, grants.Grant) (approvalview.Presentation, error) {
			return approvalview.Presentation{Title: "Request", Target: "target"}, nil
		}),
	})
	if err != nil {
		t.Fatal(err)
	}
	defer server.Close()
	if server.URL() == "" {
		t.Fatal("URL() is empty")
	}
	if _, _, err := store.Request(grants.Request{Client: "bob", Operation: "write", Target: policy.Target{Kind: "repo"}, Reason: "test"}); err != nil {
		t.Fatal(err)
	}
	page, err := server.Client("operator-secret-with-enough-entropy").List(t.Context(), operatorv1.Query{})
	if err != nil || len(page.Requests) != 1 {
		t.Fatalf("List() = %+v, %v", page, err)
	}
}
