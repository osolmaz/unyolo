//go:build linux

package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"os/user"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/osolmaz/brokerkit/approval/notifier/telegram"
	"github.com/osolmaz/brokerkit/internal/host/service"
	"github.com/osolmaz/brokerkit/operator/client"
	"github.com/osolmaz/brokerkit/operator/v1"
	"github.com/osolmaz/brokerkit/protocol/contract"
)

func TestParseSetupOptionsCapturesConfiguredRoutes(t *testing.T) {
	bot, operator := setupSecretFiles(t)
	opts, err := parseSetupOptions([]string{
		"--binary", os.Args[0], "--telegram-bot-token-file", bot, "--telegram-chat-id", "42",
		"--hf-operator-token-file", operator, "--hf-operator-endpoint", "unix:///tmp/hf.sock",
	}, &strings.Builder{})
	if err != nil {
		t.Fatal(err)
	}
	if got := opts.Routes[telegram.RouteHuggingFace]; got.TokenFile != operator || got.Endpoint != "unix:///tmp/hf.sock" {
		t.Fatalf("HF route = %+v", got)
	}
	if got := configuredRoutes(opts); !slices.Equal(got, []string{telegram.RouteHuggingFace}) {
		t.Fatalf("configured routes = %v", got)
	}
}

func TestIngressInstallPlanManagesConfigSecretsAndAccess(t *testing.T) {
	bot, operator := setupSecretFiles(t)
	account, err := user.Current()
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	opts := defaultSetupOptions()
	opts.User, opts.Group = account.Username, account.Username
	opts.ConfigDir, opts.StateDir, opts.SystemdDir = filepath.Join(dir, "etc"), filepath.Join(dir, "state"), filepath.Join(dir, "systemd")
	opts.BinaryPath, opts.TelegramBotTokenFile, opts.TelegramChatID = os.Args[0], bot, 42
	hf := opts.Routes[telegram.RouteHuggingFace]
	hf.TokenFile = operator
	opts.Routes[telegram.RouteHuggingFace] = hf
	opts.NoStart, opts.AllowNonRoot = true, true
	plan, err := ingressInstallPlan(opts)
	if err != nil {
		t.Fatal(err)
	}
	if err := plan.Validate(); err != nil {
		t.Fatal(err)
	}
	if !slices.Contains(plan.AdditionalGroups, "hf-broker-operator") || len(plan.GroupMembers) != 0 ||
		!slices.Contains(plan.Unit.SupplementaryGroups, "hf-broker-operator") {
		t.Fatalf("operator access groups = %v members=%v unit=%v", plan.AdditionalGroups, plan.GroupMembers, plan.Unit.SupplementaryGroups)
	}
	if len(plan.RemoveFiles) != 2 || plan.ReadyCheck == nil {
		t.Fatalf("route retirement = %+v readiness=%v", plan.RemoveFiles, plan.ReadyCheck != nil)
	}
	configFile := managedFile(t, plan.Files, "config.json")
	var cfg ingressConfig
	if err := json.Unmarshal(configFile.Data, &cfg); err != nil {
		t.Fatal(err)
	}
	if cfg.Routes["h"].OperatorTokenFile != filepath.Join(opts.ConfigDir, "operator-token-h") {
		t.Fatalf("managed config = %+v", cfg)
	}
	if managedFile(t, plan.Files, "telegram-bot-token").Owner != service.ManagedFileOwnerService ||
		managedFile(t, plan.Files, "operator-token-h").Mode != 0o600 {
		t.Fatalf("managed secret metadata = %+v", plan.Files)
	}
}

func TestSetupDryRunDoesNotExposeSecrets(t *testing.T) {
	bot, operator := setupSecretFiles(t)
	var stdout strings.Builder
	err := runSetup(t.Context(), []string{"systemd", "--dry-run", "--binary", os.Args[0],
		"--telegram-bot-token-file", bot, "--telegram-chat-id", "42", "--hf-operator-token-file", operator}, &stdout, &strings.Builder{})
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(stdout.String(), "telegram-token") || strings.Contains(stdout.String(), strings.Repeat("o", 32)) {
		t.Fatalf("dry run leaked credentials: %s", stdout.String())
	}
}

func TestIngressReadyCheckAuthenticatesOperatorRoute(t *testing.T) {
	token := strings.Repeat("o", 32)
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		writer.Header().Set("Content-Type", "application/json")
		if request.Header.Get("Authorization") != "Bearer "+token {
			writer.WriteHeader(http.StatusUnauthorized)
			_, _ = writer.Write([]byte(`{"error":{"code":"unauthorized","message":"denied","correlation_id":"test"}}`))
			return
		}
		_ = json.NewEncoder(writer).Encode(operatorv1.Descriptor{APIVersion: operatorv1.APIVersion,
			ContractDigest: contract.OperatorV1Digest, BuildID: "test"})
	}))
	defer server.Close()
	endpoint := strings.Replace(server.URL, "http://", "tcp://", 1)
	valid, err := operatorclient.New(endpoint, token, server.Client())
	if err != nil {
		t.Fatal(err)
	}
	if err := ingressReadyCheck([]*operatorclient.Client{valid})(t.Context()); err != nil {
		t.Fatal(err)
	}
	invalid, err := operatorclient.New(endpoint, strings.Repeat("x", 32), server.Client())
	if err != nil {
		t.Fatal(err)
	}
	if err := ingressReadyCheck([]*operatorclient.Client{invalid})(t.Context()); err == nil {
		t.Fatal("readiness accepted an invalid operator credential")
	}
}

func setupSecretFiles(t *testing.T) (string, string) {
	t.Helper()
	dir := t.TempDir()
	bot := filepath.Join(dir, "bot")
	operator := filepath.Join(dir, "operator")
	writeTestFile(t, bot, "telegram-token\n")
	writeTestFile(t, operator, strings.Repeat("o", 32)+"\n")
	return bot, operator
}

func managedFile(t *testing.T, files []service.ManagedFile, name string) service.ManagedFile {
	t.Helper()
	for _, file := range files {
		if file.Name == name {
			return file
		}
	}
	t.Fatalf("managed file %q not found", name)
	return service.ManagedFile{}
}
