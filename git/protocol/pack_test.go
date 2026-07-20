package gitx

import (
	"context"
	"crypto/sha1" // #nosec G505 -- test fixtures use the Git pack checksum.
	"encoding/binary"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/go-git/go-git/v5/plumbing"
	"github.com/go-git/go-git/v5/storage/memory"
)

var testPackLimits = PackLimits{
	MaxPackBytes:     8 << 20,
	MaxObjects:       10_000,
	MaxObjectBytes:   2 << 20,
	MaxInflatedBytes: 16 << 20,
}

func TestExtractCommitAndTagObjectsFromGitPack(t *testing.T) {
	repo, oldCommit, newCommit, tag := makePackRepository(t)
	pack := gitOutput(t, repo, strings.NewReader(newCommit+"\n"+tag+"\n"), "pack-objects", "--stdout", "--revs")
	objects, err := ExtractCommitAndTagObjects(context.Background(), pack, testPackLimits, nil)
	if err != nil {
		t.Fatal(err)
	}
	seen := make(map[string]string, len(objects))
	for _, object := range objects {
		seen[object.Hash] = object.Type
	}
	for hash, typ := range map[string]string{oldCommit: "commit", newCommit: "commit", tag: "tag"} {
		if seen[hash] != typ {
			t.Fatalf("object %s type = %q, want %q", hash, seen[hash], typ)
		}
	}
}

func TestExtractCommitAndTagObjectsResolvesThinPack(t *testing.T) {
	repo, oldCommit, newCommit, _ := makePackRepository(t)
	pack := gitOutput(t, repo, strings.NewReader(newCommit+"\n^"+oldCommit+"\n"), "pack-objects", "--stdout", "--revs", "--thin")
	if _, err := ExtractCommitAndTagObjects(context.Background(), pack, testPackLimits, nil); err == nil {
		t.Fatal("thin pack unexpectedly resolved without its external base")
	}
	readBase := func(_ context.Context, hash string) (PackObject, bool, error) {
		typ := strings.TrimSpace(string(gitOutput(t, repo, nil, "cat-file", "-t", hash)))
		data := gitOutput(t, repo, nil, "cat-file", typ, hash)
		return PackObject{Type: typ, Data: data, Hash: hash}, true, nil
	}
	objects, err := ExtractCommitAndTagObjects(context.Background(), pack, testPackLimits, readBase)
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, object := range objects {
		found = found || object.Hash == newCommit
	}
	if !found {
		t.Fatalf("new commit %s not extracted", newCommit)
	}
}

func TestExtractCommitAndTagObjectsEnforcesBounds(t *testing.T) {
	repo, _, commit, _ := makePackRepository(t)
	pack := gitOutput(t, repo, strings.NewReader(commit+"\n"), "pack-objects", "--stdout", "--revs")
	tests := []struct {
		name   string
		limits PackLimits
	}{
		{name: "pack bytes", limits: PackLimits{MaxPackBytes: int64(len(pack) - 1), MaxObjects: 100, MaxObjectBytes: 1 << 20, MaxInflatedBytes: 4 << 20}},
		{name: "object count", limits: PackLimits{MaxPackBytes: 8 << 20, MaxObjects: 1, MaxObjectBytes: 1 << 20, MaxInflatedBytes: 4 << 20}},
		{name: "object bytes", limits: PackLimits{MaxPackBytes: 8 << 20, MaxObjects: 100, MaxObjectBytes: 1, MaxInflatedBytes: 4 << 20}},
		{name: "inflated bytes", limits: PackLimits{MaxPackBytes: 8 << 20, MaxObjects: 100, MaxObjectBytes: 1 << 20, MaxInflatedBytes: 1}},
		{name: "missing limits", limits: PackLimits{}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := ExtractCommitAndTagObjects(context.Background(), pack, tc.limits, nil); err == nil {
				t.Fatal("ExtractCommitAndTagObjects() accepted input outside limits")
			}
		})
	}
}

func TestExtractCommitAndTagObjectsRejectsCancellationAndTrailingData(t *testing.T) {
	repo, _, commit, _ := makePackRepository(t)
	pack := gitOutput(t, repo, strings.NewReader(commit+"\n"), "pack-objects", "--stdout", "--revs")
	cancelled, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := ExtractCommitAndTagObjects(cancelled, pack, testPackLimits, nil); !errors.Is(err, context.Canceled) {
		t.Fatalf("cancelled error = %v", err)
	}
	if _, err := ExtractCommitAndTagObjects(context.Background(), append(pack, "trailing"...), testPackLimits, nil); err == nil {
		t.Fatal("ExtractCommitAndTagObjects() accepted trailing data")
	}
	corrupt := append([]byte(nil), pack...)
	corrupt[len(corrupt)-1] ^= 0xff
	if _, err := ExtractCommitAndTagObjects(context.Background(), corrupt, testPackLimits, nil); err == nil {
		t.Fatal("ExtractCommitAndTagObjects() accepted a bad checksum")
	}
}

func TestComputeObjectHashRejectsUnknownType(t *testing.T) {
	for _, typ := range []string{"commit", "tree", "blob", "tag"} {
		if _, err := ComputeObjectHash(typ, []byte("content")); err != nil {
			t.Fatalf("ComputeObjectHash(%q): %v", typ, err)
		}
	}
	if _, err := ComputeObjectHash("unknown", nil); err == nil {
		t.Fatal("ComputeObjectHash() accepted an unknown type")
	}
}

func TestPackLimitHelpersRejectMalformedValues(t *testing.T) {
	if sizeMismatch(1, 2) == nil || sizeMismatch(2, 2) != nil {
		t.Fatal("sizeMismatch() returned the wrong result")
	}
	for _, delta := range [][]byte{{}, {0x80}, {1}, {1, 0x80}, {1, 2}} {
		if _, err := deltaTargetSize(delta, 1); err == nil {
			t.Fatalf("deltaTargetSize(%x) accepted malformed or oversized data", delta)
		}
	}
}

func TestLoadPackBasesValidatesExternalObjects(t *testing.T) {
	data := []byte("external commit")
	hashString, err := ComputeObjectHash("commit", data)
	if err != nil {
		t.Fatal(err)
	}
	hash := plumbing.NewHash(hashString)
	limits := PackLimits{MaxPackBytes: 1024, MaxObjects: 10, MaxObjectBytes: 64, MaxInflatedBytes: 128}
	storage := memory.NewStorage()
	reads := 0
	err = loadPackBases(context.Background(), storage, []plumbing.Hash{hash, hash}, limits, 0, func(_ context.Context, requested string) (PackObject, bool, error) {
		reads++
		return PackObject{Type: "commit", Data: data, Hash: strings.ToUpper(requested)}, true, nil
	})
	if err != nil || reads != 1 {
		t.Fatalf("loadPackBases() reads=%d err=%v", reads, err)
	}
	if _, err := storage.EncodedObject(plumbing.CommitObject, hash); err != nil {
		t.Fatalf("external object not stored: %v", err)
	}

	missing := memory.NewStorage()
	if err := loadPackBases(context.Background(), missing, []plumbing.Hash{hash}, limits, 0, func(context.Context, string) (PackObject, bool, error) {
		return PackObject{}, false, nil
	}); err != nil {
		t.Fatalf("missing optional base: %v", err)
	}

	sentinel := errors.New("mirror unavailable")
	tests := []struct {
		name   string
		limits PackLimits
		reader PackBaseReader
	}{
		{name: "reader error", limits: limits, reader: func(context.Context, string) (PackObject, bool, error) { return PackObject{}, false, sentinel }},
		{name: "oversized", limits: limits, reader: func(context.Context, string) (PackObject, bool, error) {
			return PackObject{Type: "commit", Data: make([]byte, 65)}, true, nil
		}},
		{name: "total", limits: limits, reader: func(context.Context, string) (PackObject, bool, error) {
			return PackObject{Type: "commit", Data: data}, true, nil
		}},
		{name: "unknown type", limits: limits, reader: func(context.Context, string) (PackObject, bool, error) {
			return PackObject{Type: "unknown", Data: data}, true, nil
		}},
		{name: "hash mismatch", limits: limits, reader: func(context.Context, string) (PackObject, bool, error) {
			return PackObject{Type: "commit", Data: []byte("different")}, true, nil
		}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			inflated := int64(0)
			if tc.name == "total" {
				inflated = tc.limits.MaxInflatedBytes
			}
			if err := loadPackBases(context.Background(), memory.NewStorage(), []plumbing.Hash{hash}, tc.limits, inflated, tc.reader); err == nil {
				t.Fatal("loadPackBases() accepted an invalid external object")
			}
		})
	}
}

func TestPackObserverEnforcesContextAndLimits(t *testing.T) {
	limits := PackLimits{MaxObjects: 1, MaxObjectBytes: 2}
	observer := &objectObserver{ctx: context.Background(), limits: limits}
	if err := observer.OnHeader(2); err == nil {
		t.Fatal("OnHeader() accepted too many objects")
	}
	if err := observer.OnInflatedObjectHeader(plumbing.BlobObject, 3, 0); err == nil {
		t.Fatal("OnInflatedObjectHeader() accepted an oversized object")
	}
	cancelled, cancel := context.WithCancel(context.Background())
	cancel()
	observer.ctx = cancelled
	if !errors.Is(observer.OnHeader(1), context.Canceled) || !errors.Is(observer.OnFooter(plumbing.ZeroHash), context.Canceled) {
		t.Fatal("observer did not propagate cancellation")
	}
	reader := newContextReadSeeker(cancelled, []byte("data"))
	if _, err := reader.Read(make([]byte, 1)); !errors.Is(err, context.Canceled) {
		t.Fatalf("cancelled Read() error = %v", err)
	}
	if _, err := reader.Seek(0, 0); !errors.Is(err, context.Canceled) {
		t.Fatalf("cancelled Seek() error = %v", err)
	}
}

func FuzzExtractCommitAndTagObjects(f *testing.F) {
	f.Add(emptyGitPack())
	f.Add([]byte("not a pack"))
	f.Add([]byte("PACK"))
	limits := PackLimits{MaxPackBytes: 64 << 10, MaxObjects: 100, MaxObjectBytes: 8 << 10, MaxInflatedBytes: 32 << 10}
	f.Fuzz(func(t *testing.T, pack []byte) {
		_, _ = ExtractCommitAndTagObjects(context.Background(), pack, limits, nil)
	})
}

func emptyGitPack() []byte {
	pack := make([]byte, 12+sha1.Size)
	copy(pack, "PACK")
	binary.BigEndian.PutUint32(pack[4:8], 2)
	sum := sha1.Sum(pack[:12]) // #nosec G401 -- test fixture uses the Git pack checksum.
	copy(pack[12:], sum[:])
	return pack
}

func makePackRepository(t *testing.T) (string, string, string, string) {
	t.Helper()
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git not installed")
	}
	repo := filepath.Join(t.TempDir(), "repo")
	gitOutput(t, "", nil, "init", repo)
	gitOutput(t, repo, nil, "config", "user.email", "pack@example.com")
	gitOutput(t, repo, nil, "config", "user.name", "Pack Test")
	path := filepath.Join(repo, "data.txt")
	if err := os.WriteFile(path, []byte(strings.Repeat("first line\n", 4096)), 0o600); err != nil {
		t.Fatal(err)
	}
	gitOutput(t, repo, nil, "add", "data.txt")
	gitOutput(t, repo, nil, "commit", "-m", "first")
	oldCommit := strings.TrimSpace(string(gitOutput(t, repo, nil, "rev-parse", "HEAD")))
	if err := os.WriteFile(path, []byte(strings.Repeat("first line\n", 4095)+"second line\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	gitOutput(t, repo, nil, "commit", "-am", "second")
	newCommit := strings.TrimSpace(string(gitOutput(t, repo, nil, "rev-parse", "HEAD")))
	gitOutput(t, repo, nil, "tag", "-a", "v1", "-m", "version one")
	tag := strings.TrimSpace(string(gitOutput(t, repo, nil, "rev-parse", "refs/tags/v1")))
	return repo, oldCommit, newCommit, tag
}

func gitOutput(t *testing.T, dir string, stdin *strings.Reader, args ...string) []byte {
	t.Helper()
	command := exec.Command("git", args...)
	command.Dir = dir
	if stdin != nil {
		command.Stdin = stdin
	}
	output, err := command.CombinedOutput()
	if err != nil {
		t.Fatalf("git %v: %v\n%s", args, err, output)
	}
	return output
}
