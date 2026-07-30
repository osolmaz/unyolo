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

// endpointScript is the short installer served from https://unyolo.io/install.sh.
const endpointScript = "../web/public/install.sh"

var endpointBrokerCase = regexp.MustCompile(`(?m)^\s*([a-z0-9-]+(?:\s*\|\s*[a-z0-9-]+)*)\)\s*;;`)

// The endpoint hardcodes the brokers it accepts so an unknown name fails with a
// usable message instead of a 404 from curl. That list has to track the
// brokers/ directory, and nothing else would notice if it stopped.
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
	if len(onDisk) == 0 {
		t.Fatal("found no brokers with an install.sh")
	}
	sort.Strings(onDisk)

	accepted := acceptedBrokers(t)
	if strings.Join(accepted, ",") != strings.Join(onDisk, ",") {
		t.Fatalf("%s accepts %v, but brokers/ holds %v", endpointScript, accepted, onDisk)
	}
}

func TestWebInstallEndpointRunsTheBrokerBootstrap(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/main/brokers/github/install.sh" {
			http.NotFound(w, r)
			return
		}
		fmt.Fprint(w, "#!/bin/sh\necho bootstrap ran\n")
	}))
	defer server.Close()

	output, err := endpointCommand(t, server.URL, "github").CombinedOutput()
	if err != nil {
		t.Fatalf("endpoint failed: %v\n%s", err, output)
	}
	if !strings.Contains(string(output), "bootstrap ran") {
		t.Fatalf("endpoint output = %s", output)
	}
}

// With no argument the endpoint installs the GitHub broker, which is the one
// the docs lead with everywhere else.
func TestWebInstallEndpointDefaultsToGitHub(t *testing.T) {
	var requested string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requested = r.URL.Path
		fmt.Fprint(w, "#!/bin/sh\necho bootstrap ran\n")
	}))
	defer server.Close()

	output, err := endpointCommand(t, server.URL).CombinedOutput()
	if err != nil {
		t.Fatalf("endpoint failed: %v\n%s", err, output)
	}
	if requested != "/main/brokers/github/install.sh" {
		t.Fatalf("endpoint fetched %q", requested)
	}
	if !strings.Contains(string(output), "installing the github broker") {
		t.Fatalf("endpoint did not say which broker it picked: %s", output)
	}
}

func TestWebInstallEndpointRejectsUnknownBrokers(t *testing.T) {
	for _, name := range []string{"gitlab", "../etc"} {
		output, err := endpointCommand(t, "http://127.0.0.1:1", name).CombinedOutput()
		if err == nil {
			t.Fatalf("broker %q was accepted: %s", name, output)
		}
		if !strings.Contains(string(output), "usage: curl") {
			t.Fatalf("broker %q gave no usage line: %s", name, output)
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
	command.Env = append(os.Environ(), "UNYOLO_RAW_URL_BASE="+rawBase)
	return command
}
