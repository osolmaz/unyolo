package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestLoadFromLookupReadsExplicitDevelopmentConfiguration(t *testing.T) {
	values := developmentValues()
	values["GH_BROKER_GITHUB_HTTP_TIMEOUT"] = "11"
	values["GH_BROKER_GITHUB_STREAM_TIMEOUT"] = "601"
	values["GH_BROKER_MAX_RECEIVE_PACK_BYTES"] = "12345"
	cfg, err := LoadFromLookup(mapLookup(values))
	if err != nil {
		t.Fatal(err)
	}
	if !cfg.Development || cfg.Environment != "development" || cfg.AgentEndpoint.String() != "tcp://127.0.0.1:0" {
		t.Fatalf("runtime config = %+v", cfg)
	}
	if cfg.ClientID != "agent-a" || cfg.ScopeFile != "scope.json" || cfg.StateDir != "state" {
		t.Fatalf("identity and paths = %+v", cfg)
	}
	if cfg.GitHubHTTPTimeout != 11*time.Second || cfg.GitHubStreamTimeout != 601*time.Second || cfg.MaxReceivePackBytes != 12345 {
		t.Fatalf("numeric config = %+v", cfg)
	}
}

func TestLoadRejectsMalformedPresentValues(t *testing.T) {
	for name, value := range map[string]string{
		"GH_BROKER_DEVELOPMENT":            "yes",
		"GH_BROKER_GITHUB_HTTP_TIMEOUT":    "bad",
		"GH_BROKER_GITHUB_STREAM_TIMEOUT":  "-1",
		"GH_BROKER_MAX_RECEIVE_PACK_BYTES": "0",
		"GH_BROKER_GITHUB_USER_ID":         "bad",
		"GH_BROKER_TELEGRAM_CHAT_ID":       "0",
		"GH_BROKER_NETWORK_EXPOSURE":       "yes",
	} {
		t.Run(name, func(t *testing.T) {
			values := developmentValues()
			values[name] = value
			if _, err := LoadFromLookup(mapLookup(values)); err == nil || !strings.Contains(err.Error(), name) {
				t.Fatalf("LoadFromLookup() error = %v", err)
			}
		})
	}
}

func TestLoadAdmissionOverridesForConfiguredClient(t *testing.T) {
	values := developmentValues()
	path := writeFile(t, t.TempDir(), "admission.json",
		`{"requests_per_window":30,"window_seconds":60,"client_active":20,"client_pending":8,"global_active":100,"global_executing":12,"clients":{"agent-a":{"requests_per_window":5,"window_seconds":120,"active":4,"pending":2}}}`)
	values["GH_BROKER_ADMISSION_CONFIG"] = path
	cfg, err := LoadFromLookup(mapLookup(values))
	if err != nil || cfg.Admission.Clients["agent-a"].Pending != 2 {
		t.Fatalf("admission config = %+v, %v", cfg.Admission, err)
	}
}

func TestLoadRequiresExplicitNetworkExposure(t *testing.T) {
	values := developmentValues()
	values["GH_BROKER_AGENT_ENDPOINT"] = "tcp://192.0.2.10:9000"
	if _, err := LoadFromLookup(mapLookup(values)); err == nil || !strings.Contains(err.Error(), "network exposure") {
		t.Fatalf("unacknowledged network endpoint error = %v", err)
	}
	values["GH_BROKER_NETWORK_EXPOSURE"] = "allow"
	if _, err := LoadFromLookup(mapLookup(values)); err != nil {
		t.Fatalf("acknowledged network endpoint: %v", err)
	}
}

func TestLoadRejectsPlaintextProductionUpstream(t *testing.T) {
	values := developmentValues()
	values["GH_BROKER_GITHUB_API_URL"] = "http://127.0.0.1:9000/"
	if _, err := LoadFromLookup(mapLookup(values)); err != nil {
		t.Fatalf("development loopback upstream: %v", err)
	}
	values["GH_BROKER_DEVELOPMENT"] = "false"
	values["GH_BROKER_AGENT_ENDPOINT"] = "unix:///run/brokerkit/github/agent/broker.sock"
	values["GH_BROKER_SCOPE_FILE"] = "/etc/gh-broker/scope.json"
	values["GH_BROKER_STATE_DIR"] = "/var/lib/gh-broker"
	if _, err := LoadFromLookup(mapLookup(values)); err == nil || !strings.Contains(err.Error(), "GITHUB_API_URL") {
		t.Fatalf("production plaintext upstream error = %v", err)
	}
}

func TestLoadRequiresExplicitEndpointIdentityAndPaths(t *testing.T) {
	for _, name := range []string{"GH_BROKER_AGENT_ENDPOINT", "GH_BROKER_CLIENT_ID", "GH_BROKER_SCOPE_FILE", "GH_BROKER_STATE_DIR"} {
		t.Run(name, func(t *testing.T) {
			values := developmentValues()
			delete(values, name)
			if _, err := LoadFromLookup(mapLookup(values)); err == nil || !strings.Contains(err.Error(), name) {
				t.Fatalf("LoadFromLookup() error = %v", err)
			}
		})
	}
}

func TestProductionRequiresAbsolutePaths(t *testing.T) {
	values := developmentValues()
	values["GH_BROKER_DEVELOPMENT"] = "false"
	values["GH_BROKER_AGENT_ENDPOINT"] = "unix:///run/gh-broker/agent.sock"
	if _, err := LoadFromLookup(mapLookup(values)); err == nil || !strings.Contains(err.Error(), "absolute") {
		t.Fatalf("relative production paths error = %v", err)
	}
	values["GH_BROKER_SCOPE_FILE"] = "/etc/gh-broker/scope.json"
	values["GH_BROKER_STATE_DIR"] = "/var/lib/gh-broker"
	if _, err := LoadFromLookup(mapLookup(values)); err != nil {
		t.Fatalf("absolute production config: %v", err)
	}
}

func TestLoadReadsNamedClientAndOperatorSecrets(t *testing.T) {
	dir := t.TempDir()
	clientSecret := strings.Repeat("c", minimumSharedSecretBytes)
	operatorSecret := strings.Repeat("o", minimumSharedSecretBytes)
	clients := writeFile(t, dir, "clients", "agent-a = "+clientSecret+"\n")
	operators := writeFile(t, dir, "operators", "operator-a = "+operatorSecret+"\n")
	values := developmentValues()
	delete(values, "GH_BROKER_SHARED_SECRET")
	values["GH_BROKER_SECRETS_FILE"] = clients
	values["GH_BROKER_OPERATOR_ID"] = "operator-a"
	values["GH_BROKER_OPERATOR_SECRETS_FILE"] = operators
	values["GH_BROKER_OPERATOR_ENDPOINT"] = "tcp://127.0.0.1:32192"
	cfg, err := LoadFromLookup(mapLookup(values))
	if err != nil || cfg.SharedSecret != clientSecret || cfg.OperatorSecret != operatorSecret || cfg.OperatorEndpoint == nil {
		t.Fatalf("named credentials = %+v, %v", cfg, err)
	}
	if err := os.WriteFile(operators, []byte("operator-a = "+clientSecret+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadFromLookup(mapLookup(values)); err == nil || !strings.Contains(err.Error(), "must differ") || strings.Contains(err.Error(), clientSecret) {
		t.Fatalf("reused operator secret error = %v", err)
	}
}

func TestOperatorRequiresDistinctEndpoint(t *testing.T) {
	values := developmentValues()
	values["GH_BROKER_OPERATOR_ID"] = "operator-a"
	values["GH_BROKER_OPERATOR_SHARED_SECRET"] = strings.Repeat("o", minimumSharedSecretBytes)
	values["GH_BROKER_OPERATOR_ENDPOINT"] = values["GH_BROKER_AGENT_ENDPOINT"]
	if _, err := LoadFromLookup(mapLookup(values)); err == nil || !strings.Contains(err.Error(), "must differ") {
		t.Fatalf("shared endpoint error = %v", err)
	}
}

func TestLoadReadsGitHubAppCredentialFiles(t *testing.T) {
	dir := t.TempDir()
	values := developmentValues()
	delete(values, "GH_BROKER_GITHUB_TOKEN")
	delete(values, "GH_BROKER_GITHUB_TOKEN_FILE")
	values["GH_BROKER_GITHUB_APP_ID_FILE"] = writeFile(t, dir, "app-id", "12345\n")
	values["GH_BROKER_GITHUB_APP_PRIVATE_KEY_FILE"] = writeFile(t, dir, "private-key", "private-key\n")
	values["GH_BROKER_GITHUB_WEBHOOK_SECRET_FILE"] = writeFile(t, dir, "webhook", "webhook-secret\n")
	values["GH_BROKER_GITHUB_APP_CLIENT_ID_FILE"] = writeFile(t, dir, "client-id", "Iv1.client\n")
	values["GH_BROKER_GITHUB_APP_CLIENT_SECRET_FILE"] = writeFile(t, dir, "client-secret", "client-secret\n")
	values["GH_BROKER_GITHUB_USER_ID"] = "1234"
	cfg, err := LoadFromLookup(mapLookup(values))
	if err != nil || cfg.GitHubAppID != "12345" || cfg.GitHubAppClientID != "Iv1.client" || cfg.GitHubUserID != 1234 {
		t.Fatalf("GitHub App config = %+v, %v", cfg, err)
	}
	delete(values, "GH_BROKER_GITHUB_USER_ID")
	if _, err := LoadFromLookup(mapLookup(values)); err == nil {
		t.Fatal("GitHub App user credentials without user id were accepted")
	}
}

func TestLoadReadsTelegramTokenFile(t *testing.T) {
	dir := t.TempDir()
	values := developmentValues()
	values["GH_BROKER_TELEGRAM_BOT_TOKEN_FILE"] = writeFile(t, dir, "telegram", "telegram-token\n")
	values["GH_BROKER_TELEGRAM_CHAT_ID"] = "-1001234567890"
	cfg, err := LoadFromLookup(mapLookup(values))
	if err != nil || cfg.TelegramBotToken != "telegram-token" || cfg.TelegramChatID != -1001234567890 {
		t.Fatalf("Telegram config = %+v, %v", cfg, err)
	}
}

func TestValidateCredentialBoundaries(t *testing.T) {
	base := validConfig()
	base.SharedSecret = "short"
	if err := base.Validate(); err == nil {
		t.Fatal("weak client secret was accepted")
	}
	base = validConfig()
	base.GitHubToken = ""
	base.GitHubTokenFile = ""
	if err := base.Validate(); err == nil {
		t.Fatal("missing GitHub credential was accepted")
	}
	base = validConfig()
	base.GitHubTokenFile = ""
	if err := base.Validate(); err == nil || strings.Contains(err.Error(), base.GitHubToken) {
		t.Fatalf("inline development token error = %v", err)
	}
}

func TestAppCredentialRequiresBoundUserSelector(t *testing.T) {
	base := Config{GitHubAppID: "123", GitHubAppPrivateKey: []byte("key"), GitHubWebhookSecret: "webhook",
		GitHubAPIBaseURL: "https://api.github.com/", GitHubWebBaseURL: "https://github.com/"}
	tests := []struct {
		name    string
		mutate  func(*Config)
		wantErr bool
	}{
		{"base app", func(*Config) {}, false},
		{"missing webhook", func(value *Config) { value.GitHubWebhookSecret = "" }, true},
		{"unpaired client", func(value *Config) { value.GitHubAppClientID = "client" }, true},
		{"missing user id", func(value *Config) {
			value.GitHubAppClientID, value.GitHubAppClientSecret, value.GitHubAppClientSecretFile = "client", "secret", "file"
		}, true},
		{"user credential", func(value *Config) {
			value.GitHubAppClientID, value.GitHubAppClientSecret, value.GitHubAppClientSecretFile, value.GitHubUserID = "client", "secret", "file", 1234
		}, false},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			value := base
			test.mutate(&value)
			if err := appCredential(value); (err != nil) != test.wantErr {
				t.Fatalf("appCredential() error = %v", err)
			}
		})
	}
}

func TestReadSecretFileRejectsEmpty(t *testing.T) {
	dir := t.TempDir()
	path := writeFile(t, dir, "secret", " value\n")
	value, err := readSecretFile(path, "secret")
	if err != nil || value != "value" {
		t.Fatalf("readSecretFile() = %q, %v", value, err)
	}
	empty := writeFile(t, dir, "empty", " \n")
	if _, err := readSecretFile(empty, "secret"); err == nil {
		t.Fatal("empty secret was accepted")
	}
}

func developmentValues() map[string]string {
	return map[string]string{
		"GH_BROKER_DEVELOPMENT":       "true",
		"GH_BROKER_AGENT_ENDPOINT":    "tcp://127.0.0.1:0",
		"GH_BROKER_CLIENT_ID":         "agent-a",
		"GH_BROKER_SHARED_SECRET":     strings.Repeat("s", minimumSharedSecretBytes),
		"GH_BROKER_GITHUB_TOKEN":      "github-token",
		"GH_BROKER_GITHUB_TOKEN_FILE": "/protected/github-token",
		"GH_BROKER_SCOPE_FILE":        "scope.json",
		"GH_BROKER_STATE_DIR":         "state",
	}
}

func validConfig() Config {
	values := developmentValues()
	cfg, err := LoadFromLookup(mapLookup(values))
	if err != nil {
		panic(err)
	}
	return cfg
}

func mapLookup(values map[string]string) func(string) (string, bool) {
	return func(key string) (string, bool) {
		value, ok := values[key]
		return value, ok
	}
}

func writeFile(t *testing.T, dir, name, value string) string {
	t.Helper()
	path := filepath.Join(dir, name)
	if err := os.WriteFile(path, []byte(value), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}
