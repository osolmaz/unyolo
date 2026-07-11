package gitproxy

import (
	"bytes"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/osolmaz/hf-broker/internal/gitproxy/pktline"
)

func TestParseReceivePack(t *testing.T) {
	var body []byte
	body = pktline.AppendString(body, "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb refs/heads/main\x00report-status side-band-64k\n")
	body = pktline.AppendString(body, "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa 0000000000000000000000000000000000000000 refs/heads/old\n")
	body = pktline.AppendFlush(body)
	body = append(body, []byte("PACK...")...)

	req, err := ParseReceivePack(body)
	if err != nil {
		t.Fatalf("ParseReceivePack() error = %v", err)
	}
	if len(req.Commands) != 2 {
		t.Fatalf("commands = %+v", req.Commands)
	}
	if !req.Capabilities["report-status"] || !req.Capabilities["side-band-64k"] {
		t.Fatalf("capabilities = %+v", req.Capabilities)
	}
	if string(req.Pack) != "PACK..." {
		t.Fatalf("pack = %q", req.Pack)
	}
}

func TestParseReceivePackSkipsShallowLines(t *testing.T) {
	oldSHA := "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	newSHA := "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
	var body []byte
	body = pktline.AppendString(body, "shallow "+oldSHA+"\n")
	body = pktline.AppendString(body, oldSHA+" "+newSHA+" refs/heads/main\x00report-status\n")
	body = pktline.AppendFlush(body)
	body = append(body, []byte("PACK...")...)

	req, err := ParseReceivePack(body)
	if err != nil {
		t.Fatalf("ParseReceivePack() error = %v", err)
	}
	if len(req.Commands) != 1 || req.Commands[0].Ref != "refs/heads/main" {
		t.Fatalf("commands = %+v", req.Commands)
	}
	if !req.Capabilities["report-status"] {
		t.Fatalf("capabilities = %+v", req.Capabilities)
	}
	if string(req.Pack) != "PACK..." {
		t.Fatalf("pack = %q", req.Pack)
	}
}

func TestParseReceivePackSkipsPushOptions(t *testing.T) {
	oldSHA := "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	newSHA := "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
	var body []byte
	body = pktline.AppendString(body, oldSHA+" "+newSHA+" refs/heads/main\x00report-status push-options\n")
	body = pktline.AppendFlush(body)
	body = pktline.AppendString(body, "ci.skip")
	body = pktline.AppendFlush(body)
	body = append(body, []byte("PACK...")...)

	req, err := ParseReceivePack(body)
	if err != nil {
		t.Fatalf("ParseReceivePack() error = %v", err)
	}
	if len(req.Commands) != 1 || !req.Capabilities["push-options"] {
		t.Fatalf("request = %+v", req)
	}
	if string(req.Pack) != "PACK..." {
		t.Fatalf("pack = %q", req.Pack)
	}

	body = nil
	body = pktline.AppendString(body, oldSHA+" "+newSHA+" refs/heads/main\x00report-status push-options\n")
	body = pktline.AppendFlush(body)
	body = append(body, []byte("PACK...")...)
	req, err = ParseReceivePack(body)
	if err != nil {
		t.Fatalf("ParseReceivePack() without option section error = %v", err)
	}
	if string(req.Pack) != "PACK..." {
		t.Fatalf("pack without option section = %q", req.Pack)
	}
}

func TestCheckStaticRules(t *testing.T) {
	failures := CheckStaticRules([]Command{
		{Old: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", New: zeroSHA, Ref: "refs/heads/main"},
		{Old: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", New: "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb", Ref: "refs/tags/v1"},
		{Old: zeroSHA, New: "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb", Ref: "refs/replace/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"},
		{Old: zeroSHA, New: "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb", Ref: "refs/heads/new"},
	})
	if len(failures) != 3 {
		t.Fatalf("failures = %+v", failures)
	}
	if failures[0].Reason != "deletion refused" || failures[1].Reason != "tag update refused" || failures[2].Reason != "replace refs refused" {
		t.Fatalf("unexpected failures = %+v", failures)
	}
}

func TestBuildRefusalReportSideBand(t *testing.T) {
	req := ReceivePackRequest{
		Commands:     []Command{{Ref: "refs/heads/main"}, {Ref: "refs/heads/side"}},
		Capabilities: map[string]bool{"side-band-64k": true},
	}
	report := BuildRefusalReport(req, []RefFailure{{Ref: "refs/heads/main", Reason: "history rewrite refused"}})
	if !bytes.Contains(report, []byte("hf-broker: history rewrite refused")) {
		t.Fatalf("report missing reason: %q", report)
	}
	if !bytes.Contains(report, []byte("ng refs/heads/side hf-broker: "+defaultCascadeReason)) {
		t.Fatalf("report missing cascade: %q", report)
	}
}

func TestBuildRefusalReportPlainCleansReason(t *testing.T) {
	req := ReceivePackRequest{
		Commands:     []Command{{Ref: "refs/heads/main"}},
		Capabilities: map[string]bool{},
	}
	report := BuildRefusalReport(req, []RefFailure{{Ref: "refs/heads/main", Reason: "bad\nreason"}})
	if bytes.Contains(report, []byte("\nbad\n")) || !bytes.Contains(report, []byte("bad reason")) {
		t.Fatalf("plain report did not clean reason: %q", report)
	}
}

func TestExtractCommitAndTagObjectsFromGitPack(t *testing.T) {
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git not available")
	}
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
	commit := strings.TrimSpace(runGit(t, repo, "rev-parse", "HEAD"))
	runGit(t, repo, "tag", "-a", "v1", "-m", "v1")
	tag := strings.TrimSpace(runGit(t, repo, "rev-parse", "refs/tags/v1"))
	stdin := commit + "\n" + tag + "\n"
	cmd := exec.Command("git", "pack-objects", "--stdout", "--revs")
	cmd.Dir = repo
	cmd.Stdin = strings.NewReader(stdin)
	pack, err := cmd.Output()
	if err != nil {
		t.Fatalf("pack-objects: %v", err)
	}
	objects, err := ExtractCommitAndTagObjects(pack, nil)
	if err != nil {
		t.Fatalf("ExtractCommitAndTagObjects() error = %v", err)
	}
	seen := map[string]string{}
	for _, object := range objects {
		seen[object.SHA] = object.Type
	}
	if seen[commit] != "commit" {
		t.Fatalf("commit object not extracted: %+v", objects)
	}
	if seen[tag] != "tag" {
		t.Fatalf("tag object not extracted: %+v", objects)
	}
}

func runGit(t *testing.T, dir string, args ...string) string {
	t.Helper()
	return string(runGitBytes(t, dir, args...))
}

func runGitBytes(t *testing.T, dir string, args ...string) []byte {
	t.Helper()
	cmd := exec.Command("git", args...)
	cmd.Dir = dir
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("git %v: %v\n%s", args, err, out)
	}
	return out
}
