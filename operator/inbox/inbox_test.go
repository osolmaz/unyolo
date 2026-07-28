package operatorinbox

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"github.com/osolmaz/unyolo/approval/view"
	"github.com/osolmaz/unyolo/authorization/grants"
	"github.com/osolmaz/unyolo/authorization/policy"
)

func TestProjectionNeverExposesGrantInternals(t *testing.T) {
	store := grants.New(t.TempDir()+"/grants.json", grants.Options{})
	result, _, err := store.Request(grants.Request{
		Client: "bob", ClientRequestID: "safe", Operation: "provider.write",
		Target: policy.Target{Kind: "repo", Fields: map[string][]string{"name": {"demo"}}},
		Reason: "ship change", Metadata: map[string]string{"upstream_token": "protected-token-value"},
	})
	if err != nil {
		t.Fatal(err)
	}
	service, err := New(store, approvalview.PresenterFunc(func(context.Context, grants.Grant) (approvalview.Presentation, error) {
		return approvalview.Presentation{Risk: approvalview.RiskHigh, Title: "Write repository", Target: "demo"}, nil
	}))
	if err != nil {
		t.Fatal(err)
	}
	item, err := service.Get(context.Background(), result.Grant.ID)
	if err != nil {
		t.Fatal(err)
	}
	encoded, err := json.Marshal(item)
	if err != nil {
		t.Fatal(err)
	}
	for _, protected := range []string{"protected-token-value", "decision_token_verifier", result.DecisionToken} {
		if strings.Contains(string(encoded), protected) {
			t.Fatalf("projection leaked %q: %s", protected, encoded)
		}
	}
}

func TestPresentationFailureFallsBackWithoutDroppingItem(t *testing.T) {
	store := grants.New(t.TempDir()+"/grants.json", grants.Options{})
	result, _, err := store.Request(grants.Request{
		Client: "bob", Operation: "provider.write", Target: policy.Target{Kind: "repo"}, Reason: "ship",
	})
	if err != nil {
		t.Fatal(err)
	}
	service, _ := New(store, approvalview.PresenterFunc(func(context.Context, grants.Grant) (approvalview.Presentation, error) {
		return approvalview.Presentation{}, errors.New("provider presentation failed")
	}))
	item, err := service.Get(context.Background(), result.Grant.ID)
	if err != nil || !item.PresentationUnavailable || item.Presentation.Title == "" {
		t.Fatalf("Get() = %+v, %v", item, err)
	}
}

func TestListAndGenericPresenter(t *testing.T) {
	store := grants.New(t.TempDir()+"/grants.json", grants.Options{})
	if _, _, err := store.Request(grants.Request{Client: "bob", Operation: "write", Target: policy.Target{Kind: "repo"}, Reason: "test"}); err != nil {
		t.Fatal(err)
	}
	service, err := New(store, nil)
	if err != nil {
		t.Fatal(err)
	}
	page, err := service.List(context.Background(), grants.Query{})
	if err != nil || len(page.Items) != 1 || page.Items[0].Presentation.Title == "" {
		t.Fatalf("List() = %+v, %v", page, err)
	}
	if _, err := New(nil, nil); err == nil {
		t.Fatal("New() accepted nil store")
	}
}
