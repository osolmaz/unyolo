package gitproxy

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/osolmaz/brokerkit/git/protocol"
)

type fakeMirror struct {
	refs        map[string]string
	objects     map[string]GitObject
	ancestors   map[string]bool
	ensureErr   error
	storedTypes []string
	advanced    []string
	deleted     []string
}

func (m *fakeMirror) Ensure(context.Context) error {
	return m.ensureErr
}

func (m *fakeMirror) CurrentRef(_ context.Context, ref string) (string, bool, error) {
	sha, ok := m.refs[ref]
	return sha, ok, nil
}

func (m *fakeMirror) StoreObject(_ context.Context, objectType string, data []byte) (string, error) {
	sha, err := gitx.ComputeObjectHash(objectType, data)
	if err != nil {
		return "", err
	}
	m.storedTypes = append(m.storedTypes, objectType)
	m.objects[sha] = GitObject{Type: objectType, Data: data, SHA: sha}
	return sha, nil
}

func (m *fakeMirror) ReadObject(_ context.Context, sha string) (string, []byte, bool, error) {
	object, ok := m.objects[sha]
	return object.Type, object.Data, ok, nil
}

func (m *fakeMirror) IsAncestor(_ context.Context, oldSHA, newSHA string) (bool, error) {
	return m.ancestors[oldSHA+".."+newSHA], nil
}

func (m *fakeMirror) AdvanceRef(_ context.Context, ref, newSHA string) error {
	m.refs[ref] = newSHA
	m.advanced = append(m.advanced, ref)
	return nil
}

func (m *fakeMirror) DeleteRef(_ context.Context, ref string) error {
	delete(m.refs, ref)
	m.deleted = append(m.deleted, ref)
	return nil
}

func TestCheckPushStaticAndStaleFailures(t *testing.T) {
	ctx := context.Background()
	mirror := &fakeMirror{refs: map[string]string{}, objects: map[string]GitObject{}, ancestors: map[string]bool{}}
	failures, err := CheckPush(ctx, ReceivePackRequest{Commands: []Command{{Old: zeroSHA, New: zeroSHA, Ref: "refs/heads/main"}}}, mirror)
	if err != nil || len(failures) != 1 || failures[0].Reason != "deletion refused" {
		t.Fatalf("static CheckPush() failures=%+v err=%v", failures, err)
	}

	oldSHA := strings.Repeat("a", 40)
	newSHA := strings.Repeat("b", 40)
	mirror.refs["refs/heads/main"] = oldSHA
	failures, err = CheckPush(ctx, ReceivePackRequest{Commands: []Command{{Old: zeroSHA, New: newSHA, Ref: "refs/heads/main"}}}, mirror)
	if err != nil || len(failures) != 1 || failures[0].Reason != "client ref is stale" {
		t.Fatalf("stale CheckPush() failures=%+v err=%v", failures, err)
	}
}

func TestCheckPushFastForwardStoresObjectsAndAdvances(t *testing.T) {
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git not available")
	}
	ctx := context.Background()
	pack, oldSHA, newSHA, oldCommit := makeTwoCommitPack(t)
	mirror := &fakeMirror{
		refs:      map[string]string{"refs/heads/main": oldSHA},
		objects:   map[string]GitObject{oldSHA: {Type: "commit", Data: oldCommit, SHA: oldSHA}},
		ancestors: map[string]bool{oldSHA + ".." + newSHA: true},
	}
	req := ReceivePackRequest{
		Commands: []Command{{Old: oldSHA, New: newSHA, Ref: "refs/heads/main"}},
		Pack:     pack,
	}
	failures, err := CheckPush(ctx, req, mirror)
	if err != nil || len(failures) != 0 {
		t.Fatalf("CheckPush() failures=%+v err=%v", failures, err)
	}
	if len(mirror.storedTypes) == 0 {
		t.Fatalf("CheckPush() did not store incoming commit objects")
	}
	if err := AdvanceAccepted(ctx, req, mirror); err != nil {
		t.Fatalf("AdvanceAccepted() error = %v", err)
	}
	if mirror.refs["refs/heads/main"] != newSHA || len(mirror.advanced) != 1 {
		t.Fatalf("advanced refs = %+v advanced=%+v", mirror.refs, mirror.advanced)
	}

	deleteReq := ReceivePackRequest{Commands: []Command{{Old: newSHA, New: zeroSHA, Ref: "refs/heads/main"}}}
	if err := AdvanceAccepted(ctx, deleteReq, mirror); err != nil {
		t.Fatalf("AdvanceAccepted(delete) error = %v", err)
	}
	if _, ok := mirror.refs["refs/heads/main"]; ok || len(mirror.deleted) != 1 {
		t.Fatalf("delete advance refs = %+v deleted=%+v", mirror.refs, mirror.deleted)
	}
}

func TestCheckPushNonFastForwardAndEnsureError(t *testing.T) {
	ctx := context.Background()
	oldSHA := strings.Repeat("a", 40)
	newSHA := strings.Repeat("b", 40)
	mirror := &fakeMirror{
		refs:      map[string]string{"refs/heads/main": oldSHA},
		objects:   map[string]GitObject{},
		ancestors: map[string]bool{},
	}
	failures, err := CheckPush(ctx, ReceivePackRequest{Commands: []Command{{Old: oldSHA, New: newSHA, Ref: "refs/heads/main"}}}, mirror)
	if err != nil || len(failures) != 1 || failures[0].Reason != "history rewrite refused" {
		t.Fatalf("non-ff CheckPush() failures=%+v err=%v", failures, err)
	}
	mirror.ensureErr = errors.New("boom")
	_, err = CheckPush(ctx, ReceivePackRequest{Commands: []Command{{Old: oldSHA, New: newSHA, Ref: "refs/heads/main"}}}, mirror)
	if err == nil || !strings.Contains(err.Error(), "boom") {
		t.Fatalf("ensure error = %v", err)
	}
	failures = failureForAll([]Command{{Ref: "refs/heads/main"}}, "nope")
	if len(failures) != 1 || failures[0].Reason != "nope" {
		t.Fatalf("failureForAll() = %+v", failures)
	}
}

func TestCheckPushOverridesGrantableFailuresOnly(t *testing.T) {
	ctx := context.Background()
	oldSHA := strings.Repeat("a", 40)
	newSHA := strings.Repeat("b", 40)
	mirror := &fakeMirror{
		refs:      map[string]string{"refs/heads/main": oldSHA},
		objects:   map[string]GitObject{},
		ancestors: map[string]bool{},
	}
	req := ReceivePackRequest{Commands: []Command{{Old: oldSHA, New: newSHA, Ref: "refs/heads/main"}}}
	failures, err := CheckPushWithOverrides(ctx, req, mirror, func(command Command, reason string) bool {
		return command.Ref == "refs/heads/main" && reason == "history rewrite refused"
	})
	if err != nil || len(failures) != 0 {
		t.Fatalf("overridden non-ff failures=%+v err=%v", failures, err)
	}

	deleteReq := ReceivePackRequest{Commands: []Command{{Old: oldSHA, New: zeroSHA, Ref: "refs/heads/main"}}}
	failures, err = CheckPushWithOverrides(ctx, deleteReq, mirror, func(command Command, reason string) bool {
		return command.Ref == "refs/heads/main" && reason == "deletion refused"
	})
	if err != nil || len(failures) != 0 {
		t.Fatalf("overridden delete failures=%+v err=%v", failures, err)
	}

	staleReq := ReceivePackRequest{Commands: []Command{{Old: zeroSHA, New: newSHA, Ref: "refs/heads/main"}}}
	failures, err = CheckPushWithOverrides(ctx, staleReq, mirror, func(Command, string) bool { return true })
	if err != nil || len(failures) != 1 || failures[0].Reason != "client ref is stale" {
		t.Fatalf("stale override failures=%+v err=%v, want stale failure", failures, err)
	}
}

func TestClassifyPush(t *testing.T) {
	ctx := context.Background()
	oldSHA := strings.Repeat("a", 40)
	newSHA := strings.Repeat("b", 40)
	tagOld := strings.Repeat("c", 40)
	tagNew := strings.Repeat("d", 40)
	mirror := &fakeMirror{
		refs: map[string]string{
			"refs/heads/main": oldSHA,
			"refs/heads/old":  oldSHA,
			"refs/tags/v1":    tagOld,
		},
		objects:   map[string]GitObject{},
		ancestors: map[string]bool{oldSHA + ".." + newSHA: true},
	}
	req := ReceivePackRequest{Commands: []Command{
		{Old: oldSHA, New: newSHA, Ref: "refs/heads/main"},
		{Old: zeroSHA, New: strings.Repeat("e", 40), Ref: "refs/heads/new"},
		{Old: oldSHA, New: zeroSHA, Ref: "refs/heads/old"},
		{Old: tagOld, New: tagNew, Ref: "refs/tags/v1"},
	}}
	classes, failures, err := ClassifyPush(ctx, req, mirror)
	if err != nil || len(failures) != 0 {
		t.Fatalf("ClassifyPush() classes=%+v failures=%+v err=%v", classes, failures, err)
	}
	got := map[string]RefUpdateKind{}
	for _, class := range classes {
		got[class.Command.Ref] = class.Kind
	}
	want := map[string]RefUpdateKind{
		"refs/heads/main": RefUpdateAppend,
		"refs/heads/new":  RefUpdateAppend,
		"refs/heads/old":  RefUpdateRefDelete,
		"refs/tags/v1":    RefUpdateTagUpdate,
	}
	for ref, kind := range want {
		if got[ref] != kind {
			t.Fatalf("classified %s as %s, want %s; all=%+v", ref, got[ref], kind, got)
		}
	}

	mirror.ancestors = map[string]bool{}
	classes, failures, err = ClassifyPush(ctx, ReceivePackRequest{Commands: []Command{{Old: oldSHA, New: newSHA, Ref: "refs/heads/main"}}}, mirror)
	if err != nil || len(failures) != 0 || len(classes) != 1 || classes[0].Kind != RefUpdateHistoryRewrite {
		t.Fatalf("non-ff ClassifyPush() classes=%+v failures=%+v err=%v", classes, failures, err)
	}
}

func TestClassifyPushRejectsReplaceAndStaleRefs(t *testing.T) {
	ctx := context.Background()
	oldSHA := strings.Repeat("a", 40)
	newSHA := strings.Repeat("b", 40)
	mirror := &fakeMirror{
		refs:      map[string]string{"refs/heads/main": oldSHA},
		objects:   map[string]GitObject{},
		ancestors: map[string]bool{},
	}
	_, failures, err := ClassifyPush(ctx, ReceivePackRequest{Commands: []Command{{Old: zeroSHA, New: newSHA, Ref: "refs/replace/abc"}}}, mirror)
	if err != nil || len(failures) != 1 || failures[0].Reason != "replace refs refused" {
		t.Fatalf("replace ClassifyPush() failures=%+v err=%v", failures, err)
	}
	_, failures, err = ClassifyPush(ctx, ReceivePackRequest{Commands: []Command{{Old: zeroSHA, New: newSHA, Ref: "refs/heads/main"}}}, mirror)
	if err != nil || len(failures) != 1 || failures[0].Reason != "client ref is stale" {
		t.Fatalf("stale ClassifyPush() failures=%+v err=%v", failures, err)
	}
}

func TestPackParserRejectsMalformedPacks(t *testing.T) {
	tests := [][]byte{
		nil,
		[]byte("not a pack"),
	}
	for _, pack := range tests {
		if len(pack) == 0 {
			if objects, err := ExtractCommitAndTagObjects(context.Background(), pack, nil); err != nil || len(objects) != 0 {
				t.Fatalf("empty pack objects=%+v err=%v", objects, err)
			}
			continue
		}
		if _, err := ExtractCommitAndTagObjects(context.Background(), pack, nil); err == nil {
			t.Fatalf("ExtractCommitAndTagObjects(%q) succeeded, want error", pack)
		}
	}
}

func TestParseReceivePackRejectsInvalidInput(t *testing.T) {
	tests := [][]byte{
		[]byte("0008bad\n0000"),
		[]byte("003fzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb refs/heads/main\n0000"),
	}
	for _, body := range tests {
		if _, err := ParseReceivePack(body); err == nil {
			t.Fatalf("ParseReceivePack(%q) succeeded, want error", body)
		}
	}
}

func makeTwoCommitPack(t *testing.T) ([]byte, string, string, []byte) {
	t.Helper()
	dir := t.TempDir()
	repo := filepath.Join(dir, "repo")
	runGit(t, dir, "init", repo)
	runGit(t, repo, "config", "user.email", "agent@example.com")
	runGit(t, repo, "config", "user.name", "Agent")
	if err := os.WriteFile(filepath.Join(repo, "file.txt"), []byte("one\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	runGit(t, repo, "add", "file.txt")
	runGit(t, repo, "commit", "-m", "initial")
	oldSHA := strings.TrimSpace(runGit(t, repo, "rev-parse", "HEAD"))
	oldCommit := runGitBytes(t, repo, "cat-file", "commit", oldSHA)
	if err := os.WriteFile(filepath.Join(repo, "file.txt"), []byte("two\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	runGit(t, repo, "commit", "-am", "second")
	newSHA := strings.TrimSpace(runGit(t, repo, "rev-parse", "HEAD"))
	cmd := exec.Command("git", "pack-objects", "--stdout", "--revs")
	cmd.Dir = repo
	cmd.Stdin = strings.NewReader(newSHA + "\n^" + oldSHA + "\n")
	pack, err := cmd.Output()
	if err != nil {
		t.Fatalf("pack-objects: %v", err)
	}
	return pack, oldSHA, newSHA, oldCommit
}
