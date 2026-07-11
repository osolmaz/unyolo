package main

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/osolmaz/brokerkit/brokers/sudo/internal/executorprotocol"
	"github.com/osolmaz/brokerkit/brokers/sudo/internal/routes"
)

func TestParseServeOptionsAndHTTPServerHardening(t *testing.T) {
	t.Parallel()
	args := []string{"--policy", "/etc/sudo/policy", "--catalog", "/etc/sudo/catalog", "--secrets", "/etc/sudo/secrets",
		"--operator-secrets", "/etc/sudo/operators", "--grants", "/var/lib/sudo/grants", "--plans", "/var/lib/sudo/plans",
		"--helper-socket", "/run/sudo/helper.sock", "--bind", "127.0.0.1:9000", "--operator-bind", "127.0.0.1:9001"}
	opts, err := parseServeOptions(args)
	if err != nil || opts.bindAddress != "127.0.0.1:9000" {
		t.Fatalf("parseServeOptions() = %+v, %v", opts, err)
	}
	agent := httpServer(opts.bindAddress, http.NotFoundHandler(), false)
	operator := httpServer(opts.operatorAddress, http.NotFoundHandler(), true)
	if agent.ReadHeaderTimeout != 5*time.Second || agent.WriteTimeout == 0 || operator.WriteTimeout != 0 {
		t.Fatalf("server timeouts agent=%+v operator=%+v", agent, operator)
	}
	for _, address := range []string{"0.0.0.0:80", "example.com:80", "127.0.0.1:0", "bad"} {
		if err := validateLoopbackAddress(address); err == nil {
			t.Fatalf("address %q was accepted", address)
		}
	}
}

func TestRunServeOrchestrationFailsBeforeListening(t *testing.T) {
	t.Parallel()
	if err := runServeWith(t.Context(), nil, io.Discard, io.Discard, func() int { return 0 }, buildServer, serveHTTP); err == nil {
		t.Fatal("root frontend was accepted")
	}
	args := []string{"--policy", "/p", "--catalog", "/c", "--secrets", "/s", "--operator-secrets", "/o",
		"--grants", "/g", "--plans", "/plans", "--helper-socket", "/run/helper.sock"}
	want := errors.New("build failed")
	err := runServeWith(t.Context(), args, io.Discard, io.Discard, func() int { return 1000 },
		func(serveOptions, io.Writer) (*routes.Server, error) { return nil, want }, serveHTTP)
	if !errors.Is(err, want) {
		t.Fatalf("build failure = %v", err)
	}
	if err := runServeWith(t.Context(), args, io.Discard, io.Discard, nil, nil, nil); err == nil {
		t.Fatal("nil serve dependencies were accepted")
	}
}

func TestBuildServerAssemblesBrokerkitRuntime(t *testing.T) {
	directory := t.TempDir()
	write := func(name string, data string) string {
		path := filepath.Join(directory, name)
		if err := os.WriteFile(path, []byte(data), 0o600); err != nil {
			t.Fatal(err)
		}
		return path
	}
	catalogPath := write("catalog.json", `{"version":1,"commands":[{"id":"true","executable":"/usr/bin/true","arguments":[],"target_users":["root"],"working_directory":"/","timeout_seconds":5,"max_output_bytes":100}]}`)
	policyPath := write("policy.json", `{"rules":[{"id":"request","effect":"request","clients":["bob"],"operations":["exec.command"],"targets":[{"kind":"user","name":"root"}],"attrs":{"command_id":["true"]},"grant_policy":{"mode":"execution","default_minutes":1,"max_minutes":1,"request_ttl_minutes":1,"default_max_uses":1,"max_uses":1}}]}`)
	secretsPath := write("secrets", "bob = "+strings.Repeat("s", 32)+"\n")
	operatorsPath := write("operators", "onur = "+strings.Repeat("o", 32)+"\n")
	opts := serveOptions{policyPath: policyPath, catalogPath: catalogPath, secretsPath: secretsPath, operatorSecrets: operatorsPath,
		grantsPath: filepath.Join(directory, "grants.json"), plansDirectory: filepath.Join(directory, "plans"), helperSocket: filepath.Join(directory, "helper.sock")}
	server, err := buildServerWithValidator(opts, &bytes.Buffer{}, func(string) error { return nil })
	if err != nil || server.Handler() == nil || server.OperatorHandler() == nil {
		t.Fatalf("buildServerWithValidator() = %+v, %v", server, err)
	}
	if err := serverHelperReady(t.Context(), server); err == nil {
		t.Fatal("server reported ready without helper")
	}
	if _, err := buildServerWithValidator(opts, &bytes.Buffer{}, nil); err == nil {
		t.Fatal("nil trust validator was accepted")
	}
	if _, err := buildServer(opts, &bytes.Buffer{}); err == nil {
		t.Fatal("user-owned security files passed the production validator")
	}
	listener, err := net.Listen("unix", opts.helperSocket)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = listener.Close() }()
	go func() {
		connection, acceptErr := listener.Accept()
		if acceptErr != nil {
			return
		}
		defer func() { _ = connection.Close() }()
		_, _ = executorprotocol.ReadRequest(connection)
		_ = executorprotocol.WriteResponse(connection, executorprotocol.Response{Version: executorprotocol.Version, Status: executorprotocol.StatusReady})
	}()
	args := []string{"--policy", policyPath, "--catalog", catalogPath, "--secrets", secretsPath, "--operator-secrets", operatorsPath,
		"--grants", opts.grantsPath, "--plans", opts.plansDirectory, "--helper-socket", opts.helperSocket}
	var output bytes.Buffer
	err = runServeWith(t.Context(), args, &output, &bytes.Buffer{}, func() int { return 1000 },
		func(serveOptions, io.Writer) (*routes.Server, error) { return server, nil },
		func(_ context.Context, servers []*http.Server) error {
			if len(servers) != 2 {
				t.Fatalf("HTTP servers = %d", len(servers))
			}
			return nil
		})
	if err != nil || !strings.Contains(output.String(), "sudo-broker listening") {
		t.Fatalf("runServeWith() output=%q err=%v", output.String(), err)
	}
}

func TestParseServeOptionsRejectsUnsafeCombinations(t *testing.T) {
	t.Parallel()
	base := []string{"--policy", "/p", "--catalog", "/c", "--secrets", "/s", "--grants", "/g", "--plans", "/plans", "--helper-socket", "/run/helper.sock"}
	for _, extra := range [][]string{
		nil,
		{"--operator-secrets", "/o", "--bind", "127.0.0.1:8084", "--operator-bind", "127.0.0.1:8084"},
		{"--operator-secrets", "/o", "--helper-socket", "relative"},
		{"--operator-secrets", "/o", "--telegram-token-file", "/t"},
	} {
		if _, err := parseServeOptions(append(append([]string(nil), base...), extra...)); err == nil {
			t.Fatalf("unsafe options %v were accepted", extra)
		}
	}
}

func TestStatusRecorderAndShutdown(t *testing.T) {
	t.Parallel()
	recorder := &statusRecorder{header: make(http.Header)}
	if _, err := recorder.Write([]byte("ok")); err != nil || recorder.status != http.StatusOK || recorder.Header() == nil {
		t.Fatalf("recorder = %+v, %v", recorder, err)
	}
	recorder.WriteHeader(http.StatusTeapot)
	if recorder.status != http.StatusTeapot {
		t.Fatalf("recorder status = %d", recorder.status)
	}
	server := &http.Server{}
	if err := shutdownHTTP([]*http.Server{server}); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := serveHTTP(ctx, nil); err != nil && !errors.Is(err, context.Canceled) && !strings.Contains(err.Error(), "closed") {
		t.Fatalf("serveHTTP canceled = %v", err)
	}
	badServer := &http.Server{Addr: "invalid-address"}
	if err := serveHTTP(context.Background(), []*http.Server{badServer}); err == nil {
		t.Fatal("invalid HTTP listen address was accepted")
	}
}
