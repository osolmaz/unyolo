package httpapi

import (
	"bytes"
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	gitx "github.com/osolmaz/unyolo/git/protocol"
)

func TestReceivePackProvesFastForwardFromUploadedPack(t *testing.T) {
	t.Parallel()
	repo := initClassificationRepo(t)
	first := commitClassificationFile(t, repo, "one")
	second := commitClassificationFile(t, repo, "two")
	pack := classificationPack(t, repo, second, first)
	graph := inspectReceivePackGraph(t.Context(), pack, int64(len(pack)), nil)
	if !graph.provesFastForward(first, second) {
		t.Fatal("uploaded commit graph did not prove a fast-forward")
	}

	runClassificationGit(t, repo, "checkout", "--detach", first)
	divergent := commitClassificationFile(t, repo, "other")
	forcePack := classificationPack(t, repo, divergent, second)
	if inspectReceivePackGraph(t.Context(), forcePack, int64(len(forcePack)), nil).provesFastForward(second, divergent) {
		t.Fatal("divergent uploaded commit graph was classified as a fast-forward")
	}
}

func TestReceivePackFastForwardProofFailsClosed(t *testing.T) {
	t.Parallel()
	if inspectReceivePackGraph(context.Background(), []byte("not a pack"), 1024, nil).provesFastForward(strings.Repeat("a", 40), strings.Repeat("b", 40)) {
		t.Fatal("malformed pack proved a fast-forward")
	}
}

func TestReceivePackProvesFastForwardFromThinPackBases(t *testing.T) {
	t.Parallel()
	repo := initClassificationRepo(t)
	first := commitClassificationFile(t, repo, strings.Repeat("base line\n", 20_000))
	second := commitClassificationFile(t, repo, strings.Repeat("changed line\n", 20_000))
	pack := classificationPackWithOptions(t, repo, second, first, "--thin")
	graph := inspectReceivePackGraph(t.Context(), pack, 25<<20, classificationBaseReader(t, repo))
	if !graph.provesFastForward(first, second) {
		t.Fatalf("thin-pack graph did not prove a fast-forward: %s", graph.failure)
	}
}

func initClassificationRepo(t *testing.T) string {
	t.Helper()
	directory := t.TempDir()
	runClassificationGit(t, directory, "init")
	runClassificationGit(t, directory, "config", "user.name", "unYOLO Test")
	runClassificationGit(t, directory, "config", "user.email", "unyolo@example.invalid")
	return directory
}

func commitClassificationFile(t *testing.T, repo, contents string) string {
	t.Helper()
	if err := os.WriteFile(filepath.Join(repo, "file.txt"), []byte(contents), 0o600); err != nil {
		t.Fatal(err)
	}
	runClassificationGit(t, repo, "add", "file.txt")
	runClassificationGit(t, repo, "commit", "-m", "classification fixture")
	return strings.TrimSpace(runClassificationGit(t, repo, "rev-parse", "HEAD"))
}

func classificationPack(t *testing.T, repo, include, exclude string) []byte {
	return classificationPackWithOptions(t, repo, include, exclude)
}

func classificationPackWithOptions(t *testing.T, repo, include, exclude string, options ...string) []byte {
	t.Helper()
	args := append([]string{"pack-objects", "--stdout", "--revs"}, options...)
	command := exec.Command("git", args...) // #nosec G204 -- executable is fixed and arguments are test-controlled.
	command.Dir = repo
	command.Stdin = strings.NewReader(include + "\n^" + exclude + "\n")
	var output, stderr bytes.Buffer
	command.Stdout = &output
	command.Stderr = &stderr
	if err := command.Run(); err != nil {
		t.Fatalf("git pack-objects: %v: %s", err, stderr.String())
	}
	return output.Bytes()
}

func classificationBaseReader(t *testing.T, repo string) gitx.PackBaseReader {
	t.Helper()
	return func(_ context.Context, oid string) (gitx.PackObject, bool, error) {
		objectType := strings.TrimSpace(runClassificationGit(t, repo, "cat-file", "-t", oid))
		data := []byte(runClassificationGit(t, repo, "cat-file", objectType, oid))
		return gitx.PackObject{Type: objectType, Data: data, Hash: oid}, true, nil
	}
}

func runClassificationGit(t *testing.T, directory string, args ...string) string {
	t.Helper()
	command := exec.Command("git", args...) // #nosec G204 -- executable is fixed and arguments are test-controlled.
	command.Dir = directory
	output, err := command.CombinedOutput()
	if err != nil {
		t.Fatalf("git %s: %v: %s", strings.Join(args, " "), err, output)
	}
	return string(output)
}
