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
	"github.com/osolmaz/brokerkit/transport/http/server"
)

func TestParseServeOptionsAndHTTPServerHardening(t *testing.T) {
	t.Parallel()
	args := []string{"--policy", "/etc/sudo/policy", "--catalog", "/etc/sudo/catalog", "--secrets", "/etc/sudo/secrets",
		"--operator-secrets", "/etc/sudo/operators", "--state", "/var/lib/sudo",
		"--helper-socket", "/run/sudo/helper.sock", "--agent-endpoint", "tcp://127.0.0.1:9000", "--operator-endpoint", "tcp://127.0.0.1:9001",
		"--admission-config", "/etc/sudo/admission.json"}
	opts, err := parseServeOptions(args)
	if err != nil || opts.agentEndpoint.String() != "tcp://127.0.0.1:9000" || opts.admissionConfig != "/etc/sudo/admission.json" {
		t.Fatalf("parseServeOptions() = %+v, %v", opts, err)
	}
	agent, _ := serverhttp.New(http.NotFoundHandler(), serverhttp.ProfileStreaming)
	operator, _ := serverhttp.New(http.NotFoundHandler(), serverhttp.ProfileOperator)
	if agent.ReadHeaderTimeout != 5*time.Second || agent.WriteTimeout != 0 || operator.WriteTimeout != 0 {
		t.Fatalf("server timeouts agent=%+v operator=%+v", agent, operator)
	}
}

func TestRunServeOrchestrationFailsBeforeListening(t *testing.T) {
	t.Parallel()
	if err := runServeWith(t.Context(), nil, io.Discard, io.Discard, func() int { return 0 }, buildServer, serveHTTP); err == nil {
		t.Fatal("root frontend was accepted")
	}
	args := []string{"--policy", "/p", "--catalog", "/c", "--secrets", "/s", "--operator-secrets", "/o",
		"--state", "/state", "--helper-socket", "/run/helper.sock", "--agent-endpoint", "tcp://127.0.0.1:9000", "--operator-endpoint", "tcp://127.0.0.1:9001"}
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
		stateDirectory: filepath.Join(directory, "state"), helperSocket: filepath.Join(directory, "helper.sock")}
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
		"--state", opts.stateDirectory, "--helper-socket", opts.helperSocket,
		"--agent-endpoint", "unix://" + filepath.Join(directory, "agent.sock"), "--operator-endpoint", "unix://" + filepath.Join(directory, "operator.sock"), "--development"}
	if err := os.Chmod(directory, 0o700); err != nil {
		t.Fatal(err)
	}
	var output bytes.Buffer
	err = runServeWith(t.Context(), args, &output, &bytes.Buffer{}, func() int { return 1000 },
		func(serveOptions, io.Writer) (*routes.Server, error) { return server, nil },
		func(_ context.Context, bindings []serverhttp.Binding) error {
			defer func() { _ = serverhttp.Shutdown(bindings) }()
			if len(bindings) != 2 {
				t.Fatalf("HTTP bindings = %d", len(bindings))
			}
			return nil
		})
	if err != nil || !strings.Contains(output.String(), "sudo-broker listening") {
		t.Fatalf("runServeWith() output=%q err=%v", output.String(), err)
	}
}

func TestParseServeOptionsRejectsUnsafeCombinations(t *testing.T) {
	t.Parallel()
	base := []string{"--policy", "/p", "--catalog", "/c", "--secrets", "/s", "--state", "/state", "--helper-socket", "/run/helper.sock", "--agent-endpoint", "tcp://127.0.0.1:9000"}
	for _, extra := range [][]string{
		nil,
		{"--operator-secrets", "/o", "--operator-endpoint", "tcp://127.0.0.1:9000"},
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
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := serveHTTP(ctx, nil); err == nil {
		t.Fatal("empty HTTP bindings were accepted")
	}
}
