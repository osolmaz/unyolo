package deployment

import (
	"strings"
	"testing"

	"github.com/osolmaz/unyolo/deployment/profile"
)

func TestCompareCompiledBytesRejectsMismatchedDigest(t *testing.T) {
	t.Parallel()
	candidate := profile.Snapshot{Digest: "sha256:" + strings.Repeat("a", 64)}
	compiled := profile.Snapshot{Digest: "sha256:" + strings.Repeat("b", 64)}
	if err := compareCompiledBytes(candidate, compiled); err == nil {
		t.Fatal("compareCompiledBytes() accepted a mismatched pack digest")
	}
}

func TestCompareCompiledBytesRejectsChangedFileBytes(t *testing.T) {
	t.Parallel()
	digest := "sha256:" + strings.Repeat("c", 64)
	candidate := profile.Snapshot{
		Digest: digest,
		Files: map[string]profile.File{
			"deployment.json": {Path: "deployment.json", SHA256: digest, Data: []byte("candidate")},
		},
	}
	compiled := profile.Snapshot{
		Digest: digest,
		Files: map[string]profile.File{
			"deployment.json": {Path: "deployment.json", SHA256: digest, Data: []byte("compiled")},
		},
	}
	if err := compareCompiledBytes(candidate, compiled); err == nil {
		t.Fatal("compareCompiledBytes() accepted a byte-level mismatch")
	}
}

func TestCompareCompiledBytesAcceptsIdenticalPacks(t *testing.T) {
	t.Parallel()
	digest := "sha256:" + strings.Repeat("d", 64)
	pack := profile.Snapshot{
		Digest: digest,
		Files: map[string]profile.File{
			"deployment.json": {Path: "deployment.json", SHA256: digest, Data: []byte("same")},
		},
	}
	if err := compareCompiledBytes(pack, pack); err != nil {
		t.Fatalf("compareCompiledBytes() rejected identical packs: %v", err)
	}
}

func TestCompareCompiledBytesRejectsMissingFile(t *testing.T) {
	t.Parallel()
	digest := "sha256:" + strings.Repeat("e", 64)
	candidate := profile.Snapshot{Digest: digest}
	compiled := profile.Snapshot{
		Digest: digest,
		Files: map[string]profile.File{
			"deployment.json": {Path: "deployment.json", SHA256: digest, Data: []byte("only-in-root")},
		},
	}
	if err := compareCompiledBytes(candidate, compiled); err == nil {
		t.Fatal("compareCompiledBytes() accepted a candidate missing a root-generated file")
	}
}
