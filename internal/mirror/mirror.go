// Package mirror manages commits-only bare mirrors used for append-only
// ancestry checks.
package mirror

import (
	"bytes"
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

// Repo identifies one upstream repository mirror.
type Repo struct {
	Kind        string
	Owner       string
	Name        string
	UpstreamURL string
}

// Manager owns the mirror state directory and per-repo locks.
type Manager struct {
	stateDir string
	hfToken  string
	timeout  time.Duration

	mu    sync.Mutex
	locks map[string]*sync.Mutex
}

// Repository is one locked mirror checkout.
type Repository struct {
	manager *Manager
	repo    Repo
	path    string
}

// New returns a mirror manager rooted under stateDir.
func New(stateDir, hfToken string, timeout time.Duration) *Manager {
	return &Manager{
		stateDir: stateDir,
		hfToken:  hfToken,
		timeout:  timeout,
		locks:    map[string]*sync.Mutex{},
	}
}

// WithLock serializes fn with other operations for the same repository.
func (m *Manager) WithLock(repo Repo, fn func(*Repository) error) error {
	lock := m.lockFor(repo)
	lock.Lock()
	defer lock.Unlock()
	return fn(&Repository{manager: m, repo: repo, path: m.pathFor(repo)})
}

func (m *Manager) lockFor(repo Repo) *sync.Mutex {
	key := repo.Kind + "/" + repo.Owner + "/" + repo.Name
	m.mu.Lock()
	defer m.mu.Unlock()
	lock := m.locks[key]
	if lock == nil {
		lock = &sync.Mutex{}
		m.locks[key] = lock
	}
	return lock
}

func (m *Manager) pathFor(repo Repo) string {
	return filepath.Join(m.stateDir, "mirrors", repo.Kind, repo.Owner, repo.Name+".git")
}

// Ensure initializes and refreshes the bare mirror.
func (r *Repository) Ensure(ctx context.Context) error {
	if err := os.MkdirAll(filepath.Dir(r.path), 0o700); err != nil {
		return fmt.Errorf("create mirror parent: %w", err)
	}
	if err := r.initialize(ctx); err != nil {
		return err
	}
	if err := r.configure(ctx); err != nil {
		return err
	}
	return r.fetch(ctx)
}

func (r *Repository) initialize(ctx context.Context) error {
	if _, err := os.Stat(filepath.Join(r.path, "HEAD")); errors.Is(err, os.ErrNotExist) {
		if _, err := r.git(ctx, "", "init", "--bare", r.path); err != nil {
			return fmt.Errorf("initialize mirror: %w", err)
		}
	} else if err != nil {
		return fmt.Errorf("stat mirror: %w", err)
	}
	return nil
}

func (r *Repository) configure(ctx context.Context) error {
	configs := [][]string{
		{"remote.origin.url", r.repo.UpstreamURL},
		{"remote.origin.promisor", "true"},
		{"remote.origin.partialclonefilter", "tree:0"},
	}
	for _, config := range configs {
		if _, err := r.git(ctx, r.path, "config", config[0], config[1]); err != nil {
			return fmt.Errorf("configure mirror: %w", err)
		}
	}
	return nil
}

func (r *Repository) fetch(ctx context.Context) error {
	_, err := r.git(ctx, r.path,
		"fetch", "--filter=tree:0", "--prune", "origin",
		"+refs/*:refs/*",
	)
	if err != nil {
		return fmt.Errorf("refresh mirror: %w", err)
	}
	return nil
}

// CurrentRef returns the current SHA for ref, if the mirror has it.
func (r *Repository) CurrentRef(ctx context.Context, ref string) (string, bool, error) {
	out, err := r.git(ctx, r.path, "show-ref", "--verify", "--hash", ref)
	if err == nil {
		return strings.TrimSpace(string(out)), true, nil
	}
	var exitErr *exec.ExitError
	if errors.As(err, &exitErr) && exitErr.ExitCode() == 1 {
		return "", false, nil
	}
	if strings.Contains(err.Error(), "not a valid ref") {
		return "", false, nil
	}
	return "", false, fmt.Errorf("read ref %s: %w", ref, err)
}

// StoreObject validates and writes an object into the mirror object store.
func (r *Repository) StoreObject(ctx context.Context, objectType string, data []byte) (string, error) {
	out, err := r.gitWithInput(ctx, r.path, data, "hash-object", "-w", "-t", objectType, "--stdin")
	if err != nil {
		return "", fmt.Errorf("store %s object: %w", objectType, err)
	}
	return strings.TrimSpace(string(out)), nil
}

// ReadObject returns a raw commit or tag object from the mirror.
func (r *Repository) ReadObject(ctx context.Context, sha string) (objectType string, data []byte, found bool, err error) {
	typeOut, err := r.gitNoLazyFetch(ctx, r.path, "cat-file", "-t", sha)
	if err != nil {
		if missingObjectError(err) {
			return "", nil, false, nil
		}
		return "", nil, false, fmt.Errorf("read object type: %w", err)
	}
	objectType = strings.TrimSpace(string(typeOut))
	if objectType != "commit" && objectType != "tag" {
		return "", nil, false, nil
	}
	data, err = r.gitNoLazyFetch(ctx, r.path, "cat-file", objectType, sha)
	if err != nil {
		return "", nil, false, fmt.Errorf("read object data: %w", err)
	}
	return objectType, data, true, nil
}

func missingObjectError(err error) bool {
	var exitErr *exec.ExitError
	if errors.As(err, &exitErr) && exitErr.ExitCode() == 1 {
		return true
	}
	return strings.Contains(err.Error(), "could not get object info") || strings.Contains(err.Error(), "not our ref")
}

// IsAncestor reports whether oldSHA is an ancestor of newSHA.
func (r *Repository) IsAncestor(ctx context.Context, oldSHA, newSHA string) (bool, error) {
	_, err := r.git(ctx, r.path, "merge-base", "--is-ancestor", oldSHA, newSHA)
	if err == nil {
		return true, nil
	}
	var exitErr *exec.ExitError
	if errors.As(err, &exitErr) && exitErr.ExitCode() == 1 {
		return false, nil
	}
	return false, fmt.Errorf("check ancestry: %w", err)
}

// AdvanceRef updates the mirror ref after a successful upstream push.
func (r *Repository) AdvanceRef(ctx context.Context, ref, newSHA string) error {
	if _, err := r.git(ctx, r.path, "update-ref", ref, newSHA); err != nil {
		return fmt.Errorf("advance ref %s: %w", ref, err)
	}
	return nil
}

func (r *Repository) git(ctx context.Context, dir string, args ...string) ([]byte, error) {
	return r.gitWithInput(ctx, dir, nil, args...)
}

func (r *Repository) gitWithInput(ctx context.Context, dir string, input []byte, args ...string) ([]byte, error) {
	return r.gitWithInputAndEnv(ctx, dir, input, nil, args...)
}

func (r *Repository) gitNoLazyFetch(ctx context.Context, dir string, args ...string) ([]byte, error) {
	return r.gitWithInputAndEnv(ctx, dir, nil, []string{"GIT_NO_LAZY_FETCH=1"}, args...)
}

func (r *Repository) gitWithInputAndEnv(ctx context.Context, dir string, input []byte, extraEnv []string, args ...string) ([]byte, error) {
	if r.manager.timeout > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, r.manager.timeout)
		defer cancel()
	}
	cmd := exec.CommandContext(ctx, "git", args...)
	if dir != "" {
		cmd.Dir = dir
	}
	if input != nil {
		cmd.Stdin = bytes.NewReader(input)
	}
	cmd.Env = append(os.Environ(), "GIT_NO_REPLACE_OBJECTS=1")
	cmd.Env = append(cmd.Env, r.manager.gitAuthEnv()...)
	cmd.Env = append(cmd.Env, extraEnv...)
	out, err := cmd.CombinedOutput()
	if ctx.Err() != nil {
		return out, ctx.Err()
	}
	if err != nil {
		return out, fmt.Errorf("git %s: %w: %s", args[0], err, sanitizeGitOutput(out))
	}
	return out, nil
}

func (m *Manager) gitAuthEnv() []string {
	if m.hfToken == "" {
		return nil
	}
	header := "Authorization: Basic " + base64.StdEncoding.EncodeToString([]byte("x-access-token:"+m.hfToken))
	return []string{
		"GIT_CONFIG_COUNT=1",
		"GIT_CONFIG_KEY_0=http.extraheader",
		"GIT_CONFIG_VALUE_0=" + header,
	}
}

func sanitizeGitOutput(out []byte) string {
	text := strings.TrimSpace(string(out))
	if text == "" {
		return "no output"
	}
	return text
}
