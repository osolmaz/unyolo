package operatorfake

import (
	"context"
	"testing"

	"github.com/osolmaz/brokerkit/grants"
	"github.com/osolmaz/brokerkit/operatorinbox"
	"github.com/osolmaz/brokerkit/policy"
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
		Presenter: operatorinbox.PresenterFunc(func(context.Context, grants.Grant) (operatorinbox.Presentation, error) {
			return operatorinbox.Presentation{Title: "Request", Target: "target"}, nil
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
	page, err := server.Client("operator-secret-with-enough-entropy").List(t.Context(), grants.Query{})
	if err != nil || len(page.Items) != 1 {
		t.Fatalf("List() = %+v, %v", page, err)
	}
}
