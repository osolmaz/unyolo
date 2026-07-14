package main

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestSetupGitHubUserEnrollAndRevokeHaveNoReadback(t *testing.T) {
	now := time.Now().UTC()
	var revoked string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/user":
			if r.Header.Get("Authorization") != "Bearer access-setup-canary" {
				t.Fatalf("enrollment authorization = %q", r.Header.Get("Authorization"))
			}
			_, _ = io.WriteString(w, `{"id":7,"login":"bob"}`)
		case "/applications/client-id/token":
			var payload struct {
				AccessToken string `json:"access_token"`
			}
			_ = json.NewDecoder(r.Body).Decode(&payload)
			revoked = payload.AccessToken
			w.WriteHeader(http.StatusNoContent)
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(server.Close)
	dir := t.TempDir()
	stateDir := filepath.Join(dir, "state")
	if err := os.Mkdir(stateDir, 0o700); err != nil {
		t.Fatal(err)
	}
	clientID := writeProtectedTestFile(t, dir, "client-id", `client-id`)
	clientSecret := writeProtectedTestFile(t, dir, "client-secret", `client-secret-canary`)
	enrollment := writeProtectedTestFile(t, dir, "enrollment.json", `{
		"user_id":7,"login":"bob","access_token":"access-setup-canary","refresh_token":"refresh-setup-canary",
		"access_expires_at":"`+now.Add(time.Hour).Format(time.RFC3339)+`","refresh_expires_at":"`+now.Add(24*time.Hour).Format(time.RFC3339)+`"}`)
	common := []string{"--state-dir", stateDir, "--github-app-client-id-file", clientID, "--github-app-client-secret-file", clientSecret,
		"--github-api-url", server.URL, "--github-web-url", server.URL}
	var output bytes.Buffer
	args := append([]string{"enroll"}, common...)
	args = append(args, "--credential-file", enrollment)
	if err := runSetupGitHubUser(t.Context(), &output, io.Discard, args); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(output.String(), "canary") || !strings.Contains(output.String(), "user 7") {
		t.Fatalf("enrollment output = %q", output.String())
	}
	storeRoot := filepath.Join(stateDir, "credential-namespaces", "github-users")
	files, _ := filepath.Glob(filepath.Join(storeRoot, "credential-slots", "*.json"))
	if len(files) != 1 {
		t.Fatalf("encrypted credential files = %v", files)
	}
	stored, _ := os.ReadFile(files[0])
	if bytes.Contains(stored, []byte("access-setup-canary")) || bytes.Contains(stored, []byte("refresh-setup-canary")) {
		t.Fatal("setup stored a user credential in plaintext")
	}
	assertSetupStateOwnership(t, stateDir, append(files, filepath.Join(stateDir, "credential-namespaces"), storeRoot,
		filepath.Join(storeRoot, "credential-slots.key"), filepath.Join(storeRoot, "credential-slots"))...)

	output.Reset()
	revokeArgs := append([]string{"revoke"}, common...)
	revokeArgs = append(revokeArgs, "--user-id", "7")
	if err := runSetupGitHubUser(t.Context(), &output, io.Discard, revokeArgs); err != nil {
		t.Fatal(err)
	}
	if revoked != "access-setup-canary" || strings.Contains(output.String(), "canary") {
		t.Fatalf("revoked=%q output=%q", revoked, output.String())
	}
}

func TestSetupGitHubUserRejectsUnprotectedAndMalformedFiles(t *testing.T) {
	dir := t.TempDir()
	unsafe := filepath.Join(dir, "unsafe")
	if err := os.WriteFile(unsafe, []byte("secret"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := readProtectedSetupFile(unsafe); err == nil {
		t.Fatal("unprotected credential file accepted")
	}
	if err := runSetupGitHubUser(t.Context(), io.Discard, io.Discard, []string{"unknown"}); err == nil {
		t.Fatal("unknown github-user action accepted")
	}
}

func writeProtectedTestFile(t *testing.T, dir, name, value string) string {
	t.Helper()
	path := filepath.Join(dir, name)
	if err := os.WriteFile(path, []byte(value), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}
