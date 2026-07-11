package mirror

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestRepositoryAncestryAndRefs(t *testing.T) {
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git not available")
	}
	ctx := context.Background()
	dir := t.TempDir()
	upstream, work, oldSHA := seedMirrorRepo(t, dir)

	manager := New(filepath.Join(dir, "state"), "hf_token_value", 10*time.Second)
	repo := Repo{Kind: "dataset", Owner: "acme", Name: "repo", UpstreamURL: upstream}
	err := manager.WithLock(repo, func(mir *Repository) error {
		if err := mir.Ensure(ctx); err != nil {
			return err
		}
		current, ok, err := mir.CurrentRef(ctx, "refs/heads/main")
		if err != nil {
			return err
		}
		if !ok || current != oldSHA {
			t.Fatalf("CurrentRef() = %q %v, want %q true", current, ok, oldSHA)
		}
		if _, ok, err := mir.CurrentRef(ctx, "refs/heads/missing"); err != nil || ok {
			t.Fatalf("CurrentRef(missing) ok=%v err=%v", ok, err)
		}
		if err := mir.Ensure(ctx); err != nil {
			return err
		}
		return nil
	})
	if err != nil {
		t.Fatalf("WithLock() error = %v", err)
	}

	writeFile(t, filepath.Join(work, "file.txt"), "two\n")
	runGit(t, work, "commit", "-am", "second")
	newSHA := strings.TrimSpace(runGit(t, work, "rev-parse", "HEAD"))
	newCommit := runGitBytes(t, work, "cat-file", "commit", newSHA)

	err = manager.WithLock(repo, func(mir *Repository) error {
		if _, err := mir.StoreObject(ctx, "commit", newCommit); err != nil {
			return err
		}
		ok, err := mir.IsAncestor(ctx, oldSHA, newSHA)
		if err != nil {
			return err
		}
		if !ok {
			t.Fatalf("IsAncestor(%s, %s) = false", oldSHA, newSHA)
		}
		if err := mir.AdvanceRef(ctx, "refs/heads/main", newSHA); err != nil {
			return err
		}
		objectType, data, found, err := mir.ReadObject(ctx, newSHA)
		if err != nil {
			return err
		}
		if !found || objectType != "commit" || len(data) == 0 {
			t.Fatalf("ReadObject() = %q len=%d found=%v", objectType, len(data), found)
		}
		if _, _, found, err := mir.ReadObject(ctx, strings.Repeat("f", 40)); err != nil || found {
			t.Fatalf("ReadObject(missing) found=%v err=%v", found, err)
		}
		ok, err = mir.IsAncestor(ctx, newSHA, oldSHA)
		if err != nil {
			return err
		}
		if ok {
			t.Fatalf("IsAncestor(%s, %s) = true, want false", newSHA, oldSHA)
		}
		current, ok, err := mir.CurrentRef(ctx, "refs/heads/main")
		if err != nil {
			return err
		}
		if !ok || current != newSHA {
			t.Fatalf("advanced ref = %q %v, want %q true", current, ok, newSHA)
		}
		if _, err := mir.StoreObject(ctx, "not-a-type", []byte("bad")); err == nil {
			t.Fatalf("StoreObject() accepted invalid type")
		}
		if err := mir.AdvanceRef(ctx, "bad ref", newSHA); err == nil {
			t.Fatalf("AdvanceRef() accepted invalid ref")
		}
		return nil
	})
	if err != nil {
		t.Fatalf("WithLock() error = %v", err)
	}
	if got := sanitizeGitOutput(nil); got != "no output" {
		t.Fatalf("sanitizeGitOutput(nil) = %q", got)
	}
	if env := New(filepath.Join(dir, "empty"), "", time.Second).gitAuthEnv(); env != nil {
		t.Fatalf("gitAuthEnv without token = %+v, want nil", env)
	}
}

func TestRepositoryFetchesNonHeadRefs(t *testing.T) {
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git not available")
	}
	ctx := context.Background()
	dir := t.TempDir()
	upstream, _, oldSHA := seedMirrorRepo(t, dir)
	runGit(t, upstream, "update-ref", "refs/changes/topic", oldSHA)

	manager := New(filepath.Join(dir, "state"), "hf_token_value", 10*time.Second)
	repo := Repo{Kind: "dataset", Owner: "acme", Name: "repo", UpstreamURL: upstream}
	err := manager.WithLock(repo, func(mir *Repository) error {
		if err := mir.Ensure(ctx); err != nil {
			return err
		}
		changeRef, ok, err := mir.CurrentRef(ctx, "refs/changes/topic")
		if err != nil {
			return err
		}
		if !ok || changeRef != oldSHA {
			t.Fatalf("CurrentRef(non-head) = %q %v, want %q true", changeRef, ok, oldSHA)
		}
		return nil
	})
	if err != nil {
		t.Fatalf("WithLock() error = %v", err)
	}
}

func TestIsAncestorIgnoresReplaceRefs(t *testing.T) {
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git not available")
	}
	ctx := context.Background()
	dir := t.TempDir()
	repo := filepath.Join(dir, "repo")
	runGit(t, dir, "init", repo)
	runGit(t, repo, "config", "user.email", "agent@example.com")
	runGit(t, repo, "config", "user.name", "Agent")
	writeFile(t, filepath.Join(repo, "base.txt"), "base\n")
	runGit(t, repo, "add", "base.txt")
	runGit(t, repo, "commit", "-m", "base")
	base := strings.TrimSpace(runGit(t, repo, "rev-parse", "HEAD"))

	runGit(t, repo, "checkout", "--orphan", "attack")
	runGit(t, repo, "rm", "-rf", ".")
	writeFile(t, filepath.Join(repo, "attack.txt"), "attack\n")
	runGit(t, repo, "add", "attack.txt")
	runGit(t, repo, "commit", "-m", "attack")
	attack := strings.TrimSpace(runGit(t, repo, "rev-parse", "HEAD"))
	tree := strings.TrimSpace(runGit(t, repo, "write-tree"))
	replacement := strings.TrimSpace(runGit(t, repo, "commit-tree", tree, "-p", base, "-m", "replacement"))
	runGit(t, repo, "update-ref", "refs/replace/"+attack, replacement)

	mir := &Repository{manager: New(filepath.Join(dir, "state"), "", time.Second), path: repo}
	ok, err := mir.IsAncestor(ctx, base, attack)
	if err != nil {
		t.Fatalf("IsAncestor() error = %v", err)
	}
	if ok {
		t.Fatalf("IsAncestor() honored refs/replace and reported unrelated commit as descendant")
	}
}

func TestReadObjectDisablesLazyFetch(t *testing.T) {
	dir := t.TempDir()
	bin := filepath.Join(dir, "bin")
	if err := os.MkdirAll(bin, 0o700); err != nil {
		t.Fatal(err)
	}
	capture := filepath.Join(dir, "lazy-fetch")
	fakeGit := filepath.Join(bin, "git")
	script := "#!/bin/sh\nprintf '%s' \"$GIT_NO_LAZY_FETCH\" > \"$CAPTURE\"\necho 'fatal: could not get object info' >&2\nexit 1\n"
	if err := os.WriteFile(fakeGit, []byte(script), 0o700); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", bin)
	t.Setenv("CAPTURE", capture)

	repoPath := filepath.Join(dir, "repo.git")
	if err := os.MkdirAll(repoPath, 0o700); err != nil {
		t.Fatal(err)
	}
	mir := &Repository{
		manager: New(filepath.Join(dir, "state"), "", time.Second),
		path:    repoPath,
	}
	_, _, found, err := mir.ReadObject(context.Background(), strings.Repeat("a", 40))
	if err != nil || found {
		t.Fatalf("ReadObject() found=%v err=%v, want missing without error", found, err)
	}
	got, err := os.ReadFile(capture)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != "1" {
		t.Fatalf("GIT_NO_LAZY_FETCH = %q, want 1", got)
	}
}

func seedMirrorRepo(t *testing.T, dir string) (upstream, work, oldSHA string) {
	t.Helper()
	upstream = filepath.Join(dir, "upstream.git")
	work = filepath.Join(dir, "work")
	runGit(t, dir, "init", "--bare", upstream)
	runGit(t, dir, "init", work)
	runGit(t, work, "config", "user.email", "agent@example.com")
	runGit(t, work, "config", "user.name", "Agent")
	writeFile(t, filepath.Join(work, "file.txt"), "one\n")
	runGit(t, work, "add", "file.txt")
	runGit(t, work, "commit", "-m", "initial")
	runGit(t, work, "branch", "-M", "main")
	runGit(t, work, "remote", "add", "origin", upstream)
	runGit(t, work, "push", "origin", "main")
	return upstream, work, strings.TrimSpace(runGit(t, work, "rev-parse", "HEAD"))
}

func writeFile(t *testing.T, path, contents string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(contents), 0o600); err != nil {
		t.Fatal(err)
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
