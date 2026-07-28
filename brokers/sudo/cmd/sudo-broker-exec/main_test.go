package main

import (
	"context"
	"net"
	"os"
	"os/user"
	"path/filepath"
	"syscall"
	"testing"

	"github.com/osolmaz/unyolo/brokers/sudo/internal/plan"
)

func TestParseOptions(t *testing.T) {
	t.Parallel()
	opts, err := parseOptions([]string{"--catalog", "/etc/sudo-broker/catalog.json", "--state", "/var/lib/sudo-broker/executions.json", "--socket", "/run/sudo-broker/helper.sock", "--broker-user", "sudo-broker"})
	if err != nil || opts.brokerUser != "sudo-broker" {
		t.Fatalf("parseOptions() = %+v, %v", opts, err)
	}
	if _, err := parseOptions(nil); err == nil {
		t.Fatal("empty options were accepted")
	}
}

func TestListenUnixCreatesPrivateOwnedSocket(t *testing.T) {
	t.Parallel()
	path := filepath.Join(t.TempDir(), "helper.sock")
	listener, err := listenUnix(path, uint32(os.Getuid()), uint32(os.Getgid())) // #nosec G115 -- ids are non-negative.
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = listener.Close() }()
	info, err := os.Lstat(path)
	if err != nil {
		t.Fatal(err)
	}
	stat := info.Sys().(*syscall.Stat_t)
	if info.Mode()&os.ModeSocket == 0 || info.Mode().Perm() != 0o600 || stat.Uid != uint32(os.Getuid()) { // #nosec G115 -- uid is non-negative.
		t.Fatalf("socket info = mode %v uid %d", info.Mode(), stat.Uid)
	}
	connection, err := net.Dial("unix", path)
	if err != nil {
		t.Fatal(err)
	}
	_ = connection.Close()
}

func TestMainCodeAndUnprivilegedRunFailClosed(t *testing.T) {
	t.Parallel()
	if code := mainCode([]string{"--version"}); code != 0 {
		t.Fatalf("version code = %d", code)
	}
	if code := mainCode(nil); code != 2 {
		t.Fatalf("invalid args code = %d", code)
	}
	if err := run(context.Background(), options{}); err == nil {
		t.Fatalf("unprivileged run error = %v", err)
	}
}

func TestRuntimeValidationHelpersFailClosed(t *testing.T) {
	t.Parallel()
	if err := validateSocketPath("/definitely-missing-sudo-broker-helper-test.sock", uint32(os.Getuid())); err != nil { // #nosec G115 -- uid is non-negative.
		t.Fatal(err)
	}
	badOptions := options{catalogPath: filepath.Join(t.TempDir(), "catalog.json"), statePath: "/var/lib/sudo-broker/state.json"}
	if err := validateStaticInputs(badOptions); err == nil {
		t.Fatal("user-owned catalog passed static validation")
	}
	if _, err := validateRuntime(badOptions); err == nil {
		t.Fatal("invalid runtime options passed validation")
	}
	if _, _, err := runtimeServerAndListener(badOptions); err == nil {
		t.Fatal("invalid runtime options produced a server")
	}
	if _, err := newExecutorServer(badOptions, testIdentity()); err == nil {
		t.Fatal("invalid executor server inputs were accepted")
	}
	if _, _, err := buildRuntimeServerAndListener(badOptions, testIdentity()); err == nil {
		t.Fatal("invalid runtime build inputs were accepted")
	}
	current, err := user.Current()
	if err == nil && os.Getuid() != 0 {
		identity, lookupErr := lookupBrokerIdentity(current.Username)
		if lookupErr != nil || identity.UID != uint32(os.Getuid()) { // #nosec G115 -- uid is non-negative.
			t.Fatalf("lookupBrokerIdentity() = %+v, %v", identity, lookupErr)
		}
	}
	if _, err := newPrivilegedRunner(uint32(os.Getuid())); err == nil { // #nosec G115 -- uid is non-negative.
		t.Fatal("user-owned test binary was accepted as privileged runner")
	}
}

func testIdentity() plan.Identity {
	return plan.Identity{Name: "broker", UID: uint32(os.Getuid()), GID: uint32(os.Getgid())} // #nosec G115 -- ids are non-negative.
}
