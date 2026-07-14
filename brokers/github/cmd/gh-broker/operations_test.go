package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/osolmaz/brokerkit/agentv1"
	"github.com/osolmaz/brokerkit/brokers/github/internal/opcatalog"
	"github.com/osolmaz/brokerkit/sealedpayload"
	"github.com/osolmaz/brokerkit/sealedstore"
	"github.com/osolmaz/brokerkit/streamstore"
)

const operationTestSecret = "0123456789abcdef0123456789abcdef"

func githubTestOperation(state agentv1.State) agentv1.Operation {
	now := time.Date(2026, 7, 14, 0, 0, 0, 0, time.UTC)
	return agentv1.Operation{
		APIVersion: agentv1.APIVersion, ID: "op_test", Broker: "gh-broker", ClientID: "agent",
		IdempotencyKey: "request-1", Operation: "repo.metadata.read",
		Target: json.RawMessage(`{"kind":"repo","owner":"osolmaz","name":"brokerkit"}`), Arguments: json.RawMessage(`{}`),
		Reason: "test", State: state, Revision: 2, CreatedAt: now, UpdatedAt: now,
		Presentation: agentv1.Presentation{Title: "Read repository metadata"},
	}
}

func configureOperationTestClient(t *testing.T, handler http.Handler) *httptest.Server {
	t.Helper()
	server := httptest.NewServer(handler)
	t.Setenv("GH_BROKER_URL", server.URL)
	t.Setenv("GH_BROKER_SHARED_SECRET", operationTestSecret)
	return server
}

func TestOperationsListAndDescribeUseGeneratedCatalog(t *testing.T) {
	var output bytes.Buffer
	if err := runOperations(&output, []string{"list", "--family", "pull_request", "--risk", "high"}); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(output.String(), "pull_request.merge") || strings.Contains(output.String(), "repo.visibility.update") {
		t.Fatalf("list=%q", output.String())
	}
	output.Reset()
	if err := runOperations(&output, []string{"describe", "repo.visibility.update"}); err != nil {
		t.Fatal(err)
	}
	var value map[string]any
	if json.Unmarshal(output.Bytes(), &value) != nil || value["name"] != "repo.visibility.update" || value["explicit_only"] != true {
		t.Fatalf("describe=%s", output.String())
	}
}

func TestGeneratedCLIFailsClosedBeforeTransport(t *testing.T) {
	var output bytes.Buffer
	found, err := runGeneratedCLI(t.Context(), &output, []string{"pull_request", "create", "--target-json", `{"kind":"repo","owner":"o","name":"r"}`, "--arguments-json", `{"method":"POST"}`})
	if !found || err == nil || !strings.Contains(err.Error(), "closed schema") {
		t.Fatalf("found=%v err=%v", found, err)
	}
	if found, err = runGeneratedCLI(t.Context(), &output, []string{"http", "request"}); found || err != nil {
		t.Fatalf("raw command found=%v err=%v", found, err)
	}
}

func TestOperationSubmissionAndLifecycleUseAgentV1(t *testing.T) {
	var submitted map[string]any
	server := configureOperationTestClient(t, http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		writer.Header().Set("Content-Type", "application/json")
		if request.Header.Get("Authorization") != "Bearer "+operationTestSecret {
			t.Errorf("authorization header = %q", request.Header.Get("Authorization"))
		}
		switch {
		case request.Method == http.MethodPost && request.URL.Path == "/api/agent/v1/operations":
			if err := json.NewDecoder(request.Body).Decode(&submitted); err != nil {
				t.Error(err)
			}
			writer.WriteHeader(http.StatusAccepted)
			_ = json.NewEncoder(writer).Encode(githubTestOperation(agentv1.StatePending))
		case request.Method == http.MethodGet && strings.HasSuffix(request.URL.Path, "/wait"):
			_ = json.NewEncoder(writer).Encode(githubTestOperation(agentv1.StateSucceeded))
		case request.Method == http.MethodGet && strings.Contains(request.URL.Path, "/api/agent/v1/operations/"):
			_ = json.NewEncoder(writer).Encode(githubTestOperation(agentv1.StateSucceeded))
		case request.Method == http.MethodPost && strings.HasSuffix(request.URL.Path, "/cancel"):
			_ = json.NewEncoder(writer).Encode(githubTestOperation(agentv1.StateCanceled))
		default:
			http.NotFound(writer, request)
		}
	}))
	defer server.Close()

	descriptor, found := opcatalog.ByName("repo.metadata.read")
	if !found {
		t.Fatal("repo.metadata.read missing")
	}
	var output bytes.Buffer
	err := submitCatalogOperation(t.Context(), &output, descriptor, []string{
		"--target-json", `{"kind":"repo","owner":"osolmaz","name":"brokerkit"}`,
		"--arguments-json", `{}`, "--idempotency-key", "request-1", "--reason", "test", "--wait",
	})
	if err != nil || submitted["operation"] != "repo.metadata.read" || !strings.Contains(output.String(), `"state": "succeeded"`) {
		t.Fatalf("submitted=%#v output=%s err=%v", submitted, output.String(), err)
	}

	for _, action := range []string{"get", "wait", "cancel"} {
		output.Reset()
		if err := runOperationLifecycle(t.Context(), &output, action, []string{"op_test"}); err != nil {
			t.Fatalf("%s: %v", action, err)
		}
		if !strings.Contains(output.String(), `"id": "op_test"`) {
			t.Fatalf("%s output=%s", action, output.String())
		}
	}
}

func TestSealedOperationUploadsSecretBeforeSubmission(t *testing.T) {
	const operation = "workflow.actions_create_or_update_repo_secret"
	const requestKey = "sealed-request"
	const secret = "Y2FuYXJ5"
	var uploaded, submitted []byte
	server := configureOperationTestClient(t, http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		switch request.URL.Path {
		case "/api/agent/v1/sealed-payloads":
			if request.Header.Get("X-Broker-Operation") != operation || request.Header.Get("X-Broker-Idempotency-Key") != requestKey {
				t.Errorf("sealed headers = %#v", request.Header)
			}
			uploaded, _ = io.ReadAll(request.Body)
			writer.WriteHeader(http.StatusCreated)
			_ = json.NewEncoder(writer).Encode(sealedstore.Reference{
				ID: "sealed_012345678901234567890123", Owner: "bob", Purpose: operation, RequestKey: requestKey,
				Digest: strings.Repeat("a", 64), Size: len(uploaded), ExpiresAt: time.Now().Add(time.Hour).Unix(),
			})
		case "/api/agent/v1/operations":
			submitted, _ = io.ReadAll(request.Body)
			writer.Header().Set("Content-Type", "application/json")
			writer.WriteHeader(http.StatusAccepted)
			_ = json.NewEncoder(writer).Encode(githubTestOperation(agentv1.StatePending))
		default:
			http.NotFound(writer, request)
		}
	}))
	defer server.Close()
	sealedFile := filepath.Join(t.TempDir(), "secret.json")
	if err := os.WriteFile(sealedFile, []byte(`{"input":{"encrypted_value":"`+secret+`","key_id":"key-1"}}`), 0o600); err != nil {
		t.Fatal(err)
	}
	descriptor, _ := opcatalog.ByName(operation)
	var output bytes.Buffer
	err := submitCatalogOperation(t.Context(), &output, descriptor, []string{
		"--target-json", `{"kind":"repo","owner":"osolmaz","name":"brokerkit"}`,
		"--arguments-json", `{"secret_name":"DEPLOY_TOKEN"}`,
		"--sealed-file", sealedFile,
		"--idempotency-key", requestKey,
		"--reason", "rotate deploy secret",
	})
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(uploaded, []byte(secret)) || bytes.Contains(submitted, []byte(secret)) {
		t.Fatalf("uploaded=%s submitted=%s", uploaded, submitted)
	}
	if !bytes.Contains(submitted, []byte(`"sealed_payload"`)) || !bytes.Contains(submitted, []byte(`"secret_name":"DEPLOY_TOKEN"`)) {
		t.Fatalf("submitted=%s", submitted)
	}
}

func TestCredentialOutputSubmissionRequiresEncryptedSlot(t *testing.T) {
	const operation = "runner.actions_create_registration_token_for_repo"
	var submitted []byte
	server := configureOperationTestClient(t, http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		if request.URL.Path != "/api/agent/v1/operations" {
			t.Fatalf("unexpected credential output route %s", request.URL.Path)
		}
		submitted, _ = io.ReadAll(request.Body)
		writer.Header().Set("Content-Type", "application/json")
		writer.WriteHeader(http.StatusAccepted)
		_ = json.NewEncoder(writer).Encode(githubTestOperation(agentv1.StatePending))
	}))
	defer server.Close()
	descriptor, _ := opcatalog.ByName(operation)
	var output bytes.Buffer
	withoutSlot := []string{"--target-json", `{"kind":"repo","owner":"osolmaz","name":"brokerkit"}`, "--arguments-json", `{}`}
	if err := submitCatalogOperation(t.Context(), &output, descriptor, withoutSlot); err == nil {
		t.Fatal("credential output accepted without a slot")
	}
	err := submitCatalogOperation(t.Context(), &output, descriptor, append(withoutSlot,
		"--credential-slot", "ci-runner", "--idempotency-key", "runner-token", "--reason", "enroll runner"))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(submitted, []byte(`"credential_slot":"ci-runner"`)) || bytes.Contains(submitted, []byte(`"sealed_payload"`)) {
		t.Fatalf("submitted = %s", submitted)
	}
}

func TestStreamUploadSubmissionAndDownloadCLI(t *testing.T) {
	const operation = "release.repos_upload_release_asset"
	const content = "asset-canary"
	var submitted []byte
	streamID := "stream_012345678901234567890123"
	digest := sha256.Sum256([]byte(content))
	server := configureOperationTestClient(t, http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		switch {
		case request.Method == http.MethodPost && request.URL.Path == "/api/agent/v1/streams":
			body, _ := io.ReadAll(request.Body)
			if string(body) != content || request.Header.Get("X-Broker-Operation") != operation {
				t.Errorf("upload body = %q headers = %v", body, request.Header)
			}
			writer.WriteHeader(http.StatusCreated)
			_ = json.NewEncoder(writer).Encode(streamstore.Reference{ID: streamID, Owner: "bob", Purpose: operation, RequestKey: "asset-request",
				Digest: hex.EncodeToString(digest[:]), Size: int64(len(content)), MediaType: "application/octet-stream", ExpiresAt: time.Now().Add(time.Hour).Unix()})
		case request.Method == http.MethodPost && request.URL.Path == "/api/agent/v1/operations":
			submitted, _ = io.ReadAll(request.Body)
			writer.Header().Set("Content-Type", "application/json")
			writer.WriteHeader(http.StatusAccepted)
			_ = json.NewEncoder(writer).Encode(githubTestOperation(agentv1.StatePending))
		case request.Method == http.MethodGet && request.URL.Path == "/api/agent/v1/streams/"+streamID:
			writer.Header().Set("Content-Type", "application/octet-stream")
			writer.Header().Set("Content-Length", fmt.Sprint(len(content)))
			writer.Header().Set("X-Broker-Content-SHA256", hex.EncodeToString(digest[:]))
			_, _ = writer.Write([]byte(content))
		default:
			http.NotFound(writer, request)
		}
	}))
	defer server.Close()
	input := filepath.Join(t.TempDir(), "asset.bin")
	if err := os.WriteFile(input, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	descriptor, _ := opcatalog.ByName(operation)
	var output bytes.Buffer
	err := submitCatalogOperation(t.Context(), &output, descriptor, []string{
		"--target-json", `{"kind":"release","id":9,"owner":"osolmaz","name":"brokerkit"}`,
		"--arguments-json", `{"name":"asset.bin"}`, "--stream-file", input, "--stream-media-type", "application/octet-stream",
		"--idempotency-key", "asset-request", "--reason", "upload release asset",
	})
	if err != nil || !bytes.Contains(submitted, []byte(`"stream_input"`)) || bytes.Contains(submitted, []byte(content)) {
		t.Fatalf("submitted = %s err = %v", submitted, err)
	}
	destination := filepath.Join(t.TempDir(), "download.bin")
	if err := runStream(t.Context(), &output, []string{"download", streamID, "--output", destination}); err != nil {
		t.Fatal(err)
	}
	downloaded, _ := os.ReadFile(destination)
	if string(downloaded) != content {
		t.Fatalf("downloaded = %q", downloaded)
	}
}

func TestOperationCommandValidationAndClientConfiguration(t *testing.T) {
	var output bytes.Buffer
	for _, args := range [][]string{nil, {"submit"}, {"submit", "not.real"}, {"bogus"}, {"get"}} {
		if err := runOperation(t.Context(), &output, args); err == nil {
			t.Fatalf("accepted operation args %#v", args)
		}
	}
	descriptor, _ := opcatalog.ByName("repo.metadata.read")
	for _, args := range [][]string{
		{},
		{"--target-json", `{}`},
		{"--target-json", `{"kind":"repo","owner":"o","name":"r"}`, "--reason", ""},
	} {
		if err := submitCatalogOperation(t.Context(), &output, descriptor, args); err == nil {
			t.Fatalf("accepted submit args %#v", args)
		}
	}
	sealed, _ := opcatalog.ByName("agent_task.create_or_update_repo_secret")
	if err := submitCatalogOperation(t.Context(), &output, sealed, []string{"--target-json", `{"kind":"repo","owner":"o","name":"r"}`}); err == nil {
		t.Fatal("accepted sealed operation")
	}

	if _, err := loadOperationClient(func(string) string { return "" }); err == nil {
		t.Fatal("accepted empty client configuration")
	}
	credential := filepath.Join(t.TempDir(), "credential")
	if err := os.WriteFile(credential, []byte(operationTestSecret+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	client, err := loadOperationClient(func(name string) string {
		switch name {
		case "GH_BROKER_URL":
			return "http://127.0.0.1:1"
		case "GH_BROKER_SHARED_SECRET_FILE":
			return credential
		default:
			return ""
		}
	})
	if err != nil || client == nil {
		t.Fatalf("file client=%#v err=%v", client, err)
	}
	if _, err := loadOperationClient(func(name string) string {
		if name == "GH_BROKER_URL" {
			return "http://127.0.0.1:1"
		}
		if name == "GH_BROKER_SHARED_SECRET_FILE" {
			return filepath.Join(t.TempDir(), "missing")
		}
		return ""
	}); err == nil {
		t.Fatal("accepted missing credential file")
	}
	if id, err := operationRequestID(); err != nil || !strings.HasPrefix(id, "cli_") {
		t.Fatalf("request ID=%q err=%v", id, err)
	}
}

func TestOperationSurfaceFailureBoundaries(t *testing.T) {
	var output bytes.Buffer
	for _, args := range [][]string{nil, {"describe"}, {"describe", "not.real"}, {"list", "--bad"}, {"unknown"}} {
		if err := runOperations(&output, args); err == nil {
			t.Fatalf("operations accepted %#v", args)
		}
	}
	if err := runOperations(&output, []string{"list", "--family", "repo.*", "--json"}); err != nil || !strings.Contains(output.String(), "repo.delete") {
		t.Fatalf("JSON operation list = %s, %v", output.String(), err)
	}
	for _, args := range [][]string{nil, {"download"}, {"upload", "id", "--output", "file"}, {"download", "id"}} {
		if err := runStream(t.Context(), &output, args); err == nil {
			t.Fatalf("stream command accepted %#v", args)
		}
	}

	missing := filepath.Join(t.TempDir(), "missing")
	empty := filepath.Join(t.TempDir(), "empty")
	invalid := filepath.Join(t.TempDir(), "invalid")
	oversized := filepath.Join(t.TempDir(), "oversized")
	if os.WriteFile(empty, nil, 0o600) != nil || os.WriteFile(invalid, []byte(`[]`), 0o600) != nil ||
		os.WriteFile(oversized, bytes.Repeat([]byte("x"), sealedpayload.MaxPayloadBytes+1), 0o600) != nil {
		t.Fatal("write sealed fixtures")
	}
	for _, path := range []string{missing, empty, invalid, oversized} {
		if _, err := readSealedArguments(path); err == nil {
			t.Fatalf("sealed arguments accepted %q", path)
		}
	}

	connection := operationConnection{baseURL: "http://127.0.0.1:1", secret: operationTestSecret}
	if _, err := connection.uploadStream(t.Context(), "repo.metadata.read", "request", missing, "application/octet-stream"); err == nil {
		t.Fatal("non-stream operation accepted upload")
	}
	descriptor, _ := opcatalog.ByName("release.repos_upload_release_asset")
	if _, err := connection.uploadStream(t.Context(), descriptor.Name, "request", missing, "application/octet-stream"); err == nil {
		t.Fatal("missing stream file uploaded")
	}
	if _, err := connection.uploadSealedPayload(t.Context(), "repo.delete", "request", []byte(`{}`)); err == nil {
		t.Fatal("offline sealed payload upload succeeded")
	}
}

func TestStreamAndSealedResponsesRejectInvalidBrokerData(t *testing.T) {
	server := configureOperationTestClient(t, http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		switch request.URL.Path {
		case "/api/agent/v1/sealed-payloads":
			writer.WriteHeader(http.StatusCreated)
			_, _ = writer.Write([]byte(`{"id":"wrong","purpose":"other"}`))
		case "/api/agent/v1/streams":
			writer.WriteHeader(http.StatusCreated)
			_, _ = writer.Write([]byte(`{"id":"wrong","purpose":"other"}`))
		case "/api/agent/v1/streams/stream_bad":
			writer.Header().Set("Content-Length", "4")
			writer.Header().Set("X-Broker-Content-SHA256", strings.Repeat("0", 64))
			_, _ = writer.Write([]byte("data"))
		default:
			http.NotFound(writer, request)
		}
	}))
	defer server.Close()
	connection := operationConnection{baseURL: server.URL, secret: operationTestSecret}
	if _, err := connection.uploadSealedPayload(t.Context(), "repo.delete", "request", []byte(`{}`)); err == nil {
		t.Fatal("invalid sealed payload reference accepted")
	}
	file := filepath.Join(t.TempDir(), "asset")
	if err := os.WriteFile(file, []byte("asset"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := connection.uploadStream(t.Context(), "release.repos_upload_release_asset", "request", file, "application/octet-stream"); err == nil {
		t.Fatal("invalid stream reference accepted")
	}
	if err := connection.downloadStream(t.Context(), "stream_bad", filepath.Join(t.TempDir(), "download")); err == nil {
		t.Fatal("invalid stream digest accepted")
	}
}

func TestTopLevelDispatchesGeneratedSurfaces(t *testing.T) {
	var stdout, stderr bytes.Buffer
	for _, test := range []struct {
		args []string
		want string
	}{
		{[]string{"version"}, version},
		{[]string{"operations", "describe", "repo.metadata.read"}, `"name": "repo.metadata.read"`},
		{[]string{"operation"}, ""},
		{[]string{"mcp", "extra"}, ""},
		{[]string{"not-a-command"}, ""},
	} {
		stdout.Reset()
		err := runWithArgs(t.Context(), test.args, &stdout, &stderr)
		if test.want != "" {
			if err != nil || !strings.Contains(stdout.String(), test.want) {
				t.Fatalf("args=%v output=%q err=%v", test.args, stdout.String(), err)
			}
		} else if err == nil {
			t.Fatalf("args=%v unexpectedly succeeded", test.args)
		}
	}
}
