package gitclient

import (
	"bytes"
	"fmt"
	"io"
	"net/http"
	"net/http/cgi"
	"net/http/httptest"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"

	clientconfig "github.com/osolmaz/unyolo/internal/config/client"
)

// The relay observes key names only and passes the original protocol bytes to
// the actual production command. No credentials or challenge values are logged.
func TestCredentialHTTPRelay(t *testing.T) {
	if os.Getenv("UNYOLO_TEST_CREDENTIAL_RELAY") != "1" {
		return
	}
	input, err := io.ReadAll(os.Stdin)
	if err != nil {
		os.Exit(2)
	}
	var keys strings.Builder
	for _, line := range strings.Split(string(input), "\n") {
		if key, _, ok := strings.Cut(line, "="); ok {
			fmt.Fprintln(&keys, key)
		}
	}
	file, err := os.OpenFile(os.Getenv("UNYOLO_TEST_KEY_LOG"), os.O_APPEND|os.O_WRONLY, 0600)
	if err != nil {
		os.Exit(2)
	}
	_, err = io.WriteString(file, keys.String())
	closeErr := file.Close()
	if err != nil || closeErr != nil {
		os.Exit(2)
	}
	command := exec.Command(os.Getenv("UNYOLO_TEST_HELPER"), "--provider", "github", os.Args[len(os.Args)-1])
	command.Stdin = bytes.NewReader(input)
	command.Stdout, command.Stderr = os.Stdout, os.Stderr
	if command.Run() != nil {
		os.Exit(1)
	}
	os.Exit(0)
}

func TestCredentialAdvisoryArraysWithRealGitClone(t *testing.T) {
	git, err := exec.LookPath("git")
	if err != nil {
		t.Skip("Git is not installed")
	}
	root := t.TempDir()
	home := filepath.Join(root, "home")
	if err := os.Mkdir(home, 0700); err != nil {
		t.Fatal(err)
	}
	// Do not inherit operator config, repository selectors, proxies, or tokens.
	env := []string{"PATH=" + os.Getenv("PATH"), "HOME=" + home,
		"GIT_CONFIG_GLOBAL=" + filepath.Join(root, "global"),
		"GIT_CONFIG_SYSTEM=" + filepath.Join(root, "system"),
		"GIT_TERMINAL_PROMPT=0", "GIT_ASKPASS=false"}
	runGit := func(args ...string) []byte {
		t.Helper()
		command := exec.CommandContext(t.Context(), git, args...)
		command.Dir, command.Env = root, env
		output, err := command.CombinedOutput()
		if err != nil {
			t.Fatalf("synthetic Git command failed: %v\n%s", err, output)
		}
		return output
	}
	source := filepath.Join(root, "source")
	runGit("init", "-b", "main", source)
	if err := os.WriteFile(filepath.Join(source, "fixture.txt"), []byte("synthetic fixture\n"), 0600); err != nil {
		t.Fatal(err)
	}
	runGit("-C", source, "add", "fixture.txt")
	runGit("-C", source, "-c", "user.name=Fixture", "-c", "user.email=fixture@example.invalid", "-c", "commit.gpgsign=false", "commit", "-m", "fixture")
	runGit("clone", "--bare", source, filepath.Join(root, "repo.git"))
	wantHead := string(runGit("-C", source, "rev-parse", "HEAD"))
	backend := &cgi.Handler{Path: git, Args: []string{"http-backend"}, Dir: root,
		Env: []string{"GIT_PROJECT_ROOT=" + root, "GIT_HTTP_EXPORT_ALL=1"}}
	const secret = "synthetic-http-credential-canary"
	var anonymous, authenticated atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		user, password, ok := r.BasicAuth()
		if !ok || user != "unyolo" || password != secret {
			anonymous.Add(1)
			w.Header().Add("WWW-Authenticate", `Basic realm="fixture"`)
			w.Header().Add("WWW-Authenticate", `Bearer realm="fixture"`)
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		authenticated.Add(1)
		backend.ServeHTTP(w, r)
	}))
	defer server.Close()
	parsed, err := url.Parse(server.URL)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := clientconfig.Write(clientconfig.Config{BrokerName: "gh-broker", EnvPrefix: "GH_BROKER", ClientID: "fixture",
		Endpoint: "unix:///unused/agent.sock", GitEndpoint: "tcp://" + parsed.Host, Secret: secret, HomeDir: home}); err != nil {
		t.Fatal(err)
	}
	helper := filepath.Join(root, "git-credential-unyolo")
	build := exec.CommandContext(t.Context(), "go", "build", "-o", helper, "./cmd/git-credential-unyolo")
	build.Dir = filepath.Join("..", "..")
	if output, err := build.CombinedOutput(); err != nil {
		t.Fatalf("build production helper: %v\n%s", err, output)
	}
	relay, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	log := filepath.Join(root, "key-names")
	if err := os.WriteFile(log, nil, 0600); err != nil {
		t.Fatal(err)
	}
	env = append(env, "UNYOLO_TEST_CREDENTIAL_RELAY=1", "UNYOLO_TEST_HELPER="+helper, "UNYOLO_TEST_KEY_LOG="+log)
	// Git shell helper quoting is required for arbitrary test-binary paths.
	quote := func(value string) string { return "'" + strings.ReplaceAll(value, "'", "'\\''") + "'" }
	helperCommand := "!" + quote(relay) + " -test.run='^TestCredentialHTTPRelay$' --"
	clone := filepath.Join(root, "clone")
	runGit("-c", "credential.helper=", "-c", "credential.helper="+helperCommand,
		"-c", "credential.useHttpPath=true", "clone", server.URL+"/repo.git", clone)
	if anonymous.Load() == 0 || authenticated.Load() == 0 {
		t.Fatal("clone did not perform a challenged authenticated retry")
	}
	keys, err := os.ReadFile(log)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Count(string(keys), "wwwauth[]\n") < 2 {
		t.Fatalf("real Git did not send repeated challenge keys: %s", keys)
	}
	if got := string(runGit("-C", clone, "rev-parse", "HEAD")); got != wantHead {
		t.Fatalf("cloned HEAD = %q; want %q", got, wantHead)
	}
	content, err := os.ReadFile(filepath.Join(clone, "fixture.txt"))
	if err != nil || string(content) != "synthetic fixture\n" {
		t.Fatal("cloned content mismatch")
	}
	t.Logf("authenticated smart-HTTP clone; observed %d wwwauth[] and %d capability[] keys (values not logged)", strings.Count(string(keys), "wwwauth[]\n"), strings.Count(string(keys), "capability[]\n"))
}
