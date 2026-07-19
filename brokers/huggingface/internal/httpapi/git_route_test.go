package httpapi

import (
	"net/http"
	"testing"
)

func TestHuggingFaceGitRoute(t *testing.T) {
	tests := []struct {
		method string
		path   string
		want   bool
	}{
		{http.MethodGet, "/owner/repo/info/refs", true},
		{http.MethodPost, "/owner/repo/git-upload-pack", true},
		{http.MethodPost, "/datasets/owner/repo/git-receive-pack", true},
		{http.MethodPut, "/spaces/owner/repo/info/lfs/objects/1", true},
		{http.MethodDelete, "/owner/repo/info/lfs/objects/1", false},
		{http.MethodGet, "/owner/repo/git-receive-pack", false},
		{http.MethodGet, "/invalid", false},
		{http.MethodGet, "/owner/repo/unknown", false},
	}
	for _, test := range tests {
		if got := huggingFaceGitRoute(test.method, test.path); got != test.want {
			t.Errorf("huggingFaceGitRoute(%q, %q) = %t, want %t", test.method, test.path, got, test.want)
		}
	}
}
