package githubauth

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

const pullRequestTestHead = "1111111111111111111111111111111111111111"

func TestPullRequestReturnsBoundedSnapshot(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		if request.Method != http.MethodGet || request.URL.Path != "/repos/osolmaz/brokerkit/pulls/77" {
			t.Fatalf("request = %s %s", request.Method, request.URL.Path)
		}
		if request.Header.Get("Authorization") != "Bearer dev-canary" {
			t.Fatal("development credential was not applied")
		}
		_, _ = writer.Write([]byte(`{"id":4101208524,"number":77,"node_id":"PR_node","state":"open","draft":false,"merged":false,"mergeable":true,"mergeable_state":"blocked","head":{"sha":"` + pullRequestTestHead + `"}}`))
	}))
	t.Cleanup(server.Close)

	manager := newDevelopmentManager(t, server.URL)
	snapshot, err := manager.PullRequest(t.Context(), manager.development.Metadata(), "osolmaz", "brokerkit", 77)
	if err != nil {
		t.Fatal(err)
	}
	if snapshot.ID != 4101208524 || snapshot.Number != 77 || snapshot.NodeID != "PR_node" || snapshot.HeadSHA != pullRequestTestHead ||
		snapshot.State != "open" || snapshot.Draft || snapshot.Merged || snapshot.Mergeable == nil || !*snapshot.Mergeable || snapshot.MergeableState != "blocked" {
		t.Fatalf("snapshot = %+v", snapshot)
	}
}

func TestPullRequestRejectsInvalidSelectorsAndResponses(t *testing.T) {
	if _, err := (*Manager)(nil).pullRequestRequest(t.Context(), "osolmaz", "brokerkit", 1); err == nil {
		t.Fatal("nil manager accepted a pull request selector")
	}
	manager := newDevelopmentManager(t, "https://api.github.com")
	for name, selector := range map[string]struct {
		owner  string
		repo   string
		number int64
	}{
		"owner":  {repo: "brokerkit", number: 1},
		"repo":   {owner: "osolmaz", number: 1},
		"number": {owner: "osolmaz", repo: "brokerkit"},
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := manager.pullRequestRequest(t.Context(), selector.owner, selector.repo, selector.number); err == nil {
				t.Fatal("invalid pull request selector was accepted")
			}
		})
	}

	valid := `{"id":1,"number":7,"node_id":"PR_node","state":"open","draft":false,"merged":false,"mergeable":null,"mergeable_state":"unknown","head":{"sha":"` + pullRequestTestHead + `"}}`
	if snapshot, err := decodePullRequestSnapshot([]byte(valid), 7); err != nil || snapshot.Mergeable != nil {
		t.Fatalf("decodePullRequestSnapshot() = %+v, %v", snapshot, err)
	}
	for name, body := range map[string]string{
		"malformed":    `{`,
		"wrong number": strings.Replace(valid, `"number":7`, `"number":8`, 1),
		"missing id":   strings.Replace(valid, `"id":1`, `"id":0`, 1),
		"missing node": strings.Replace(valid, `"PR_node"`, `""`, 1),
		"missing head": strings.Replace(valid, pullRequestTestHead, "", 1),
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := decodePullRequestSnapshot([]byte(body), 7); err == nil {
				t.Fatal("invalid pull request response was accepted")
			}
		})
	}
}
