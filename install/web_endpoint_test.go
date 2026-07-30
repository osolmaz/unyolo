package installer

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"testing"
)

const endpointScript = "../web/public/install.sh"

var endpointBrokerCase = regexp.MustCompile(`(?m)^\s*([a-z0-9-]+(?:\s*\|\s*[a-z0-9-]+)*)\)\s*$`)

func TestWebInstallEndpointListsEveryBroker(t *testing.T) {
	entries, err := os.ReadDir("../brokers")
	if err != nil {
		t.Fatalf("read brokers directory: %v", err)
	}
	var onDisk []string
	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}
		if _, err := os.Stat(filepath.Join("../brokers", entry.Name(), "install.sh")); err == nil {
			onDisk = append(onDisk, entry.Name())
		}
	}
	sort.Strings(onDisk)
	accepted := acceptedBrokers(t)
	if strings.Join(accepted, ",") != strings.Join(onDisk, ",") {
		t.Fatalf("%s accepts %v, but brokers/ holds %v", endpointScript, accepted, onDisk)
	}
}

func TestWebInstallEndpointRunsNamedBrokerBootstrap(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/main/brokers/github/install.sh" {
			http.NotFound(w, r)
			return
		}
		if _, err := fmt.Fprint(w, "#!/bin/sh\necho bootstrap-ran\n"); err != nil {
			t.Errorf("write bootstrap script: %v", err)
		}
	}))
	defer server.Close()

	output, err := endpointCommand(t, server.URL, "github").CombinedOutput()
	if err != nil || !strings.Contains(string(output), "bootstrap-ran") {
		t.Fatalf("named endpoint = %q, %v", output, err)
	}
}

func TestWebInstallEndpointPinsGuidedBootstrapToReleaseCommit(t *testing.T) {
	commit := strings.Repeat("a", 40)
	var requested []string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requested = append(requested, r.URL.Path)
		var err error
		switch r.URL.Path {
		case "/releases":
			_, err = fmt.Fprint(w, `[{"tag_name":"gh-broker/v9.0.0"},{"tag_name":"unyolo/v1.2.3"}]`)
		case "/refs/unyolo/v1.2.3":
			_, err = fmt.Fprintf(w, `{"object":{"type":"commit","sha":"%s"}}`, commit)
		case "/" + commit + "/install/bootstrap.sh":
			_, err = fmt.Fprint(w, "#!/bin/sh\necho release=$2 source=$UNYOLO_SOURCE_COMMIT\n")
		default:
			http.NotFound(w, r)
		}
		if err != nil {
			t.Errorf("write endpoint response: %v", err)
		}
	}))
	defer server.Close()

	output, err := endpointCommand(t, server.URL).CombinedOutput()
	if err != nil {
		t.Fatalf("guided endpoint failed: %v\n%s", err, output)
	}
	if !strings.Contains(string(output), "release=unyolo/v1.2.3 source="+commit) {
		t.Fatalf("guided output = %s", output)
	}
	want := []string{"/releases", "/refs/unyolo/v1.2.3", "/" + commit + "/install/bootstrap.sh"}
	if strings.Join(requested, "\n") != strings.Join(want, "\n") {
		t.Fatalf("requests = %v, want %v", requested, want)
	}
}

func TestWebInstallEndpointRejectsUnknownComponents(t *testing.T) {
	for _, name := range []string{"gitlab", "../etc"} {
		output, err := endpointCommand(t, "http://127.0.0.1:1", name).CombinedOutput()
		if err == nil || !strings.Contains(string(output), "usage: curl") {
			t.Fatalf("component %q = %q, %v", name, output, err)
		}
	}
}

func acceptedBrokers(t *testing.T) []string {
	t.Helper()
	script, err := os.ReadFile(endpointScript)
	if err != nil {
		t.Fatalf("read %s: %v", endpointScript, err)
	}
	match := endpointBrokerCase.FindSubmatch(script)
	if match == nil {
		t.Fatalf("%s has no broker case arm", endpointScript)
	}
	var names []string
	for _, name := range strings.Split(string(match[1]), "|") {
		names = append(names, strings.TrimSpace(name))
	}
	sort.Strings(names)
	return names
}

func endpointCommand(t *testing.T, rawBase string, args ...string) *exec.Cmd {
	t.Helper()
	command := exec.Command("sh", append([]string{endpointScript}, args...)...)
	command.Env = append(os.Environ(),
		"UNYOLO_RAW_URL_BASE="+rawBase,
		"UNYOLO_RELEASES_URL="+rawBase+"/releases",
		"UNYOLO_REF_URL_BASE="+rawBase+"/refs",
		"UNYOLO_TAG_URL_BASE="+rawBase+"/tags",
	)
	return command
}
