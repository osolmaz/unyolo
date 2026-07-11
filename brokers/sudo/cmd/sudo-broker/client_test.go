package main

import (
	"bytes"
	"context"
	"encoding/base64"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestClientCommandsUseAuthenticatedLoopbackAPI(t *testing.T) {
	secret := "test-client-secret-abcdefghijklmnopqrstuvwxyz"
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		if request.Header.Get("Authorization") != "Bearer "+secret {
			http.Error(writer, `{"message":"unauthorized"}`, http.StatusUnauthorized)
			return
		}
		switch request.URL.Path {
		case "/api/v1/requests":
			writer.WriteHeader(http.StatusCreated)
			_, _ = writer.Write([]byte(`{"request":{"id":"request-1","status":"pending"}}`))
		case "/api/v1/requests/request-1":
			_, _ = writer.Write([]byte(`{"request":{"id":"request-1","status":"active"}}`))
		case "/api/v1/executions":
			_, _ = fmt.Fprintf(writer, `{"execution":{"exit_code":0,"stdout_base64":%q,"stderr_base64":%q}}`,
				base64.StdEncoding.EncodeToString([]byte("stdout")), base64.StdEncoding.EncodeToString([]byte("stderr")))
		default:
			http.NotFound(writer, request)
		}
	}))
	defer server.Close()
	t.Setenv("SUDO_BROKER_URL", server.URL)
	t.Setenv("SUDO_BROKER_SHARED_SECRET", secret)

	var stdout, stderr bytes.Buffer
	if err := runRequest(context.Background(), []string{"scale", "--as", "root", "--reason", "release", "--arg-json", "replicas=2"}, &stdout); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(stdout.String(), "request-1") {
		t.Fatalf("request output = %q", stdout.String())
	}
	stdout.Reset()
	if err := runStatus(context.Background(), []string{"request-1"}, &stdout); err != nil || !strings.Contains(stdout.String(), "active") {
		t.Fatalf("status output=%q err=%v", stdout.String(), err)
	}
	stdout.Reset()
	if err := run(context.Background(), []string{"status", "request-1"}, &stdout, &stderr); err != nil {
		t.Fatalf("dispatched status = %v", err)
	}
	stdout.Reset()
	if err := runCommand(context.Background(), []string{"scale", "--as", "root", "--arg-json", "replicas=2"}, &stdout, &stderr); err != nil {
		t.Fatal(err)
	}
	if stdout.String() != "stdout" || stderr.String() != "stderr" {
		t.Fatalf("command streams = %q / %q", stdout.String(), stderr.String())
	}
}

func TestClientValidationAndBrokerErrors(t *testing.T) {
	for _, args := range [][]string{nil, {"--bad"}, {"scale"}} {
		if err := runRequest(context.Background(), args, &bytes.Buffer{}); err == nil {
			t.Fatalf("runRequest(%v) error = nil", args)
		}
	}
	var arguments rawArguments
	if err := arguments.Set("value=1"); err != nil || arguments.String() != "" {
		t.Fatalf("arguments = %v, %v", arguments, err)
	}
	for _, value := range []string{"bad", "=1", "value=", "value={", "value=1"} {
		err := arguments.Set(value)
		if value == "value=1" {
			if err == nil {
				t.Fatal("duplicate argument was accepted")
			}
		} else if err == nil {
			t.Fatalf("argument %q was accepted", value)
		}
	}
	if _, _, err := leadingCommand("run", nil); err == nil {
		t.Fatal("missing command id was accepted")
	}
	if err := runStatus(context.Background(), nil, &bytes.Buffer{}); err == nil {
		t.Fatal("missing status id was accepted")
	}

	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
		writer.WriteHeader(http.StatusForbidden)
		_, _ = writer.Write([]byte(`{"message":"denied"}`))
	}))
	defer server.Close()
	t.Setenv("SUDO_BROKER_URL", server.URL)
	t.Setenv("SUDO_BROKER_SHARED_SECRET", "secret")
	if _, err := clientCall(context.Background(), http.MethodGet, "/denied", nil); err == nil || !strings.Contains(err.Error(), "denied") {
		t.Fatalf("broker error = %v", err)
	}
	t.Setenv("SUDO_BROKER_URL", "http://example.com")
	if _, err := loadClientConfig(); err == nil {
		t.Fatal("non-loopback broker URL was accepted")
	}
	t.Setenv("SUDO_BROKER_URL", "")
	if _, err := loadClientConfig(); err == nil {
		t.Fatal("missing broker URL was accepted")
	}
	if err := writePrettyJSON(&bytes.Buffer{}, []byte("not-json")); err == nil {
		t.Fatal("invalid response JSON was accepted")
	}
	if id, err := randomClientID("test-"); err != nil || !strings.HasPrefix(id, "test-") {
		t.Fatalf("random id = %q, %v", id, err)
	}
	invalidServer := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
		_, _ = writer.Write([]byte("not-json"))
	}))
	defer invalidServer.Close()
	t.Setenv("SUDO_BROKER_URL", invalidServer.URL)
	t.Setenv("SUDO_BROKER_SHARED_SECRET", "secret")
	if err := runCommand(context.Background(), []string{"true", "--as", "root"}, &bytes.Buffer{}, &bytes.Buffer{}); err == nil {
		t.Fatal("invalid execution response was accepted")
	}
	largeServer := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
		_, _ = writer.Write(bytes.Repeat([]byte("x"), maxClientResponseBytes+1))
	}))
	defer largeServer.Close()
	t.Setenv("SUDO_BROKER_URL", largeServer.URL)
	if _, err := clientCall(context.Background(), http.MethodGet, "/", nil); err == nil {
		t.Fatal("oversized broker response was accepted")
	}
}

func TestCommandDispatcherAndMainExitCodes(t *testing.T) {
	var stdout, stderr bytes.Buffer
	if err := run(context.Background(), []string{"version"}, &stdout, &stderr); err != nil || !strings.Contains(stdout.String(), version) {
		t.Fatalf("version output=%q err=%v", stdout.String(), err)
	}
	if err := run(context.Background(), []string{"unknown"}, &stdout, &stderr); err == nil {
		t.Fatal("unknown command was accepted")
	}
	if code := mainCode(nil, &stdout, &stderr); code != 1 {
		t.Fatalf("mainCode() = %d", code)
	}
	if code := mainCode([]string{"run", "missing", "--as", "root"}, &stdout, &stderr); code != 1 {
		t.Fatalf("failed run mainCode() = %d", code)
	}
	if message := (exitError{code: 7, message: "failed"}).Error(); message != "failed" {
		t.Fatalf("exit error = %q", message)
	}
	if err := run(context.Background(), []string{"serve"}, &stdout, &stderr); err == nil {
		t.Fatal("incomplete serve command was accepted")
	}
	if err := run(context.Background(), []string{"doctor"}, &stdout, &stderr); err == nil {
		t.Fatal("incomplete doctor command was accepted")
	}
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
		_, _ = fmt.Fprintf(writer, `{"execution":{"exit_code":7,"stdout_base64":"","stderr_base64":""}}`)
	}))
	defer server.Close()
	t.Setenv("SUDO_BROKER_URL", server.URL)
	t.Setenv("SUDO_BROKER_SHARED_SECRET", "secret")
	if code := mainCode([]string{"run", "false", "--as", "root"}, &stdout, &stderr); code != 7 {
		t.Fatalf("command exit code = %d", code)
	}
	if err := run(context.Background(), []string{"setup", "unknown"}, &stdout, &stderr); err == nil {
		t.Fatal("unknown setup command was accepted")
	}
}
