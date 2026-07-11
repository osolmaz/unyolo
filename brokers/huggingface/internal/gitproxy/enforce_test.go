package gitproxy

import (
	"context"
	"crypto/sha1"
	"encoding/binary"
	"errors"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
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
	sha := hashObject(mustObjectTypeCode(objectType), data)
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

func TestDeltaApplication(t *testing.T) {
	base := []byte("hello world")
	delta := []byte{
		byte(len(base)),
		14,
		0x90, 0x05,
		0x04, ' ', 'g', 'o', ' ',
		0x91, 0x06, 0x05,
	}
	got, err := applyGitDelta(base, delta)
	if err != nil {
		t.Fatalf("applyGitDelta() error = %v", err)
	}
	if string(got) != "hello go world" {
		t.Fatalf("applyGitDelta() = %q", got)
	}
	if _, err := applyGitDelta(base, []byte{byte(len(base)), 1, 0}); err == nil {
		t.Fatalf("applyGitDelta() accepted invalid zero instruction")
	}
	if _, err := applyGitDelta(base, []byte{byte(len(base) + 1), 1, 0x90, 1}); err == nil {
		t.Fatalf("applyGitDelta() accepted wrong base size")
	}
	if _, err := applyGitDelta(base, []byte{byte(len(base)), 1, 0x91, 20, 1}); err == nil {
		t.Fatalf("applyGitDelta() accepted copy past base")
	}
	if _, err := applyGitDelta([]byte("a"), []byte{1, 1, 0x90, 1, 0x90, 1}); err == nil || !strings.Contains(err.Error(), "declared size") {
		t.Fatalf("applyGitDelta() over-append error = %v, want declared-size error", err)
	}
	if _, _, err := readDeltaSize([]byte{0x80}, 0); err == nil {
		t.Fatalf("readDeltaSize() accepted truncated varint")
	}
	if _, _, err := readDeltaSize([]byte{0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x01}, 0); err == nil {
		t.Fatalf("readDeltaSize() accepted overlong varint")
	}
	if _, _, _, err := readCopyInstruction(nil, 0x81); err == nil {
		t.Fatalf("readCopyInstruction() accepted truncated offset")
	}
	if _, _, _, err := readCopyInstruction(nil, 0x90); err == nil {
		t.Fatalf("readCopyInstruction() accepted truncated size")
	}
}

func TestInflatedObjectHandlingBoundsRetainedData(t *testing.T) {
	oversized := int64(maxStoredPackObjectBytes + 1)
	if _, err := readInflatedObject(io.LimitReader(zeroReader{}, oversized), uint64(oversized), false); err == nil {
		t.Fatalf("discarded readInflatedObject() accepted oversized object")
	}
	if _, err := readInflatedObject(io.LimitReader(zeroReader{}, oversized), uint64(oversized), true); err == nil {
		t.Fatalf("retained readInflatedObject() accepted oversized object")
	}
	data, err := readInflatedObject(strings.NewReader("skip"), 4, false)
	if err != nil {
		t.Fatalf("discarded readInflatedObject() error = %v", err)
	}
	if data != nil {
		t.Fatalf("discarded readInflatedObject() retained %d bytes", len(data))
	}
	resolver := newObjectResolver([]packedObject{{offset: 12, objectType: packObjectBlob}}, nil)
	if _, ok, err := resolver.resolve(0); err != nil || ok {
		t.Fatalf("resolve skipped blob ok=%v err=%v, want false nil", ok, err)
	}
}

type zeroReader struct{}

func (zeroReader) Read(p []byte) (int, error) {
	for i := range p {
		p[i] = 0
	}
	return len(p), nil
}

func TestPackParserRejectsMalformedPacks(t *testing.T) {
	tests := [][]byte{
		nil,
		[]byte("not a pack"),
		append([]byte("PACK\x00\x00\x00\x05\x00\x00\x00\x00"), make([]byte, 20)...),
		packWithCount(uint32(maxParsedPackObjects+1), nil),
		packWithCount(2, make([]byte, minPackedObjectBytes)),
	}
	for _, pack := range tests {
		if len(pack) == 0 {
			if objects, err := ExtractCommitAndTagObjects(pack, nil); err != nil || len(objects) != 0 {
				t.Fatalf("empty pack objects=%+v err=%v", objects, err)
			}
			continue
		}
		if _, err := ExtractCommitAndTagObjects(pack, nil); err == nil {
			t.Fatalf("ExtractCommitAndTagObjects(%q) succeeded, want error", pack)
		}
	}
}

func packWithCount(count uint32, payload []byte) []byte {
	pack := make([]byte, 12+len(payload)+sha1.Size)
	copy(pack, "PACK")
	binary.BigEndian.PutUint32(pack[4:8], 2)
	binary.BigEndian.PutUint32(pack[8:12], count)
	copy(pack[12:], payload)
	sum := sha1.Sum(pack[:12+len(payload)])
	copy(pack[12+len(payload):], sum[:])
	return pack
}

func TestResolverHandlesOffsetAndExternalRefDeltas(t *testing.T) {
	base := []byte("base commit")
	delta := []byte{byte(len(base)), byte(len(base)), 0x90, byte(len(base))}
	baseSHA := hashObject(packObjectCommit, base)
	objects := []packedObject{
		{offset: 12, objectType: packObjectCommit, data: base},
		{offset: 40, objectType: packObjectOFSDelta, baseOffset: 12, data: delta},
		{offset: 70, objectType: packObjectREFDelta, baseSHA: baseSHA, data: delta},
	}
	resolver := objectResolver{
		objects:     objects,
		byOffset:    map[int]int{12: 0, 40: 1, 70: 2},
		bySHA:       map[string]int{baseSHA: 0},
		resolved:    map[int]resolvedObject{},
		resolving:   map[int]bool{},
		externalSHA: map[string]resolvedObject{},
		readBase: func(sha string) (GitObject, bool, error) {
			return GitObject{Type: "commit", Data: base, SHA: sha}, true, nil
		},
	}
	resolved, ok, err := resolver.resolve(1)
	if err != nil || !ok || string(resolved.data) != string(base) {
		t.Fatalf("OFS resolve = %+v ok=%v err=%v", resolved, ok, err)
	}
	delete(resolver.bySHA, baseSHA)
	resolved, ok, err = resolver.resolve(2)
	if err != nil || !ok || resolved.sha != baseSHA {
		t.Fatalf("REF resolve = %+v ok=%v err=%v", resolved, ok, err)
	}
	if _, ok := objectTypeCode("nope"); ok {
		t.Fatalf("objectTypeCode(nope) ok = true")
	}
	for _, name := range []string{"tree", "blob", "tag"} {
		if _, ok := objectTypeCode(name); !ok {
			t.Fatalf("objectTypeCode(%q) ok = false", name)
		}
	}
	if got := objectTypeName(99); got != "" {
		t.Fatalf("objectTypeName(99) = %q", got)
	}
}

func TestParseOFSDeltaBase(t *testing.T) {
	pack := make([]byte, 60)
	pack[30] = 0x05
	base, next, err := parseOFSDeltaBase(pack, 30, 35)
	if err != nil || base != 30 || next != 31 {
		t.Fatalf("parseOFSDeltaBase() = base %d next %d err %v", base, next, err)
	}
	if _, _, err := parseOFSDeltaBase(nil, 0, 35); err == nil {
		t.Fatalf("parseOFSDeltaBase() accepted truncated input")
	}
	badPack := make([]byte, 60)
	badPack[30] = 0x20
	if _, _, err := parseOFSDeltaBase(badPack, 30, 35); err == nil {
		t.Fatalf("parseOFSDeltaBase() accepted invalid base")
	}
}

func TestParseObjectBaseBranches(t *testing.T) {
	pack := make([]byte, 80)
	pack[30] = 0x05
	object := packedObject{offset: 35, objectType: packObjectCommit}
	next, err := parseObjectBase(pack, 30, &object)
	if err != nil || next != 30 {
		t.Fatalf("whole parseObjectBase() next=%d err=%v", next, err)
	}
	object = packedObject{offset: 35, objectType: packObjectOFSDelta}
	next, err = parseObjectBase(pack, 30, &object)
	if err != nil || next != 31 || object.baseOffset != 30 {
		t.Fatalf("ofs parseObjectBase() object=%+v next=%d err=%v", object, next, err)
	}
	object = packedObject{offset: 35, objectType: packObjectREFDelta}
	next, err = parseObjectBase(pack, 30, &object)
	if err != nil || next != 50 || object.baseSHA == "" {
		t.Fatalf("ref parseObjectBase() object=%+v next=%d err=%v", object, next, err)
	}
	object = packedObject{offset: 35, objectType: 99}
	if _, err = parseObjectBase(pack, 30, &object); err == nil {
		t.Fatalf("parseObjectBase() accepted unsupported type")
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

func mustObjectTypeCode(name string) int {
	code, ok := objectTypeCode(name)
	if !ok {
		panic(name)
	}
	return code
}
