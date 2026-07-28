package httpapi

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"testing"

	gitx "github.com/osolmaz/unyolo/git/protocol"
)

func TestGitHubPackBaseReaderFetchesAndVerifiesObjects(t *testing.T) {
	t.Parallel()
	blob := []byte("hello\n")
	blobHash, err := gitx.ComputeObjectHash("blob", blob)
	if err != nil {
		t.Fatal(err)
	}
	treeData, treeHash, treeJSON := testGitHubTreePayload(t, blobHash)
	missingHash := strings.Repeat("f", 40)
	mismatchHash := strings.Repeat("a", 40)
	failedHash := strings.Repeat("e", 40)
	server := newTestServerWithHandler(t, func(w http.ResponseWriter, r *http.Request) {
		if !strings.Contains(r.Header.Get("Authorization"), testGitHubToken) {
			t.Fatal("pack-base request omitted GitHub authorization")
		}
		switch r.URL.Path {
		case "/repos/acme/repo/git/blobs/" + blobHash:
			_, _ = w.Write(blob)
		case "/repos/acme/repo/git/blobs/" + treeHash:
			http.NotFound(w, r)
		case "/repos/acme/repo/git/trees/" + treeHash:
			_, _ = w.Write(treeJSON)
		case "/repos/acme/repo/git/blobs/" + mismatchHash:
			_, _ = io.WriteString(w, "mismatch")
		case "/repos/acme/repo/git/blobs/" + failedHash:
			http.Error(w, "canary", http.StatusForbidden)
		default:
			http.NotFound(w, r)
		}
	})
	reader := server.githubPackBaseReader("acme", "repo")
	for _, test := range []struct {
		name string
		oid  string
		typ  string
		data []byte
	}{
		{name: "blob", oid: blobHash, typ: "blob", data: blob},
		{name: "tree", oid: treeHash, typ: "tree", data: treeData},
	} {
		t.Run(test.name, func(t *testing.T) {
			object, found, err := reader(t.Context(), test.oid)
			if err != nil || !found || object.Type != test.typ || !bytes.Equal(object.Data, test.data) {
				t.Fatalf("pack base = %+v, found=%t, err=%v", object, found, err)
			}
		})
	}
	if _, found, err := reader(t.Context(), missingHash); err != nil || found {
		t.Fatalf("missing base: found=%t err=%v", found, err)
	}
	if _, _, err := reader(t.Context(), mismatchHash); err == nil {
		t.Fatal("mismatched base hash was accepted")
	}
	if _, _, err := reader(t.Context(), failedHash); err == nil || strings.Contains(err.Error(), "canary") {
		t.Fatalf("upstream error was not redacted: %v", err)
	}
}

func TestGitHubTreeObjectReconstructsCanonicalObject(t *testing.T) {
	t.Parallel()
	blobHash, err := gitx.ComputeObjectHash("blob", []byte("hello\n"))
	if err != nil {
		t.Fatal(err)
	}
	want, treeHash, payload := testGitHubTreePayload(t, blobHash)
	got, err := githubTreeObject(payload, treeHash)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, want) {
		t.Fatalf("tree object = %x, want %x", got, want)
	}
	if _, _, err := verifiedGitHubPackBase("tree", treeHash, got); err != nil {
		t.Fatal(err)
	}
}

func TestGitHubTreeObjectRejectsInvalidResponses(t *testing.T) {
	t.Parallel()
	oid := strings.Repeat("a", 40)
	for _, data := range [][]byte{
		[]byte(`not-json`),
		[]byte(`{"sha":"` + oid + `","truncated":true,"tree":[]}`),
		[]byte(`{"sha":"` + strings.Repeat("b", 40) + `","tree":[]}`),
		[]byte(`{"sha":"` + oid + `","tree":[{"path":"bad/name","mode":"100644","sha":"` + oid + `"}]}`),
		[]byte(`{"sha":"` + oid + `","tree":[{"path":"file","mode":"999999","sha":"` + oid + `"}]}`),
		[]byte(`{"sha":"` + oid + `","tree":[{"path":"file","mode":"100644","sha":"bad"}]}`),
	} {
		if _, err := githubTreeObject(data, oid); err == nil {
			t.Fatalf("invalid tree response accepted: %s", data)
		}
	}
}

func testGitHubTreePayload(t *testing.T, blobHash string) ([]byte, string, []byte) {
	t.Helper()
	decoded, err := hex.DecodeString(blobHash)
	if err != nil {
		t.Fatal(err)
	}
	want := append([]byte("100644 file.txt\x00"), decoded...)
	treeHash, err := gitx.ComputeObjectHash("tree", want)
	if err != nil {
		t.Fatal(err)
	}
	payload, err := json.Marshal(map[string]any{
		"sha":  treeHash,
		"tree": []map[string]string{{"path": "file.txt", "mode": "100644", "sha": blobHash}},
	})
	if err != nil {
		t.Fatal(err)
	}
	return want, treeHash, payload
}
