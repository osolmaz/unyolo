package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestLoadRequiresRuntimeAndAppliesTuningDefaults(t *testing.T) {
	dir := t.TempDir()
	secrets := filepath.Join(dir, "secrets")
	if err := os.WriteFile(secrets, []byte("agent = abcdefghijklmnopqrstuvwxyz123456\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	env := map[string]string{
		"HF_BROKER_HF_TOKEN":     "hf_token_value",
		"HF_BROKER_SECRETS_FILE": secrets,
	}
	cfg, err := Load(testGetenv(env))
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}
	if cfg.AgentEndpoint.String() != "tcp://127.0.0.1:32191" || cfg.ScopeFile != "/tmp/hf-broker-scope.json" || cfg.StateDir != "/tmp/hf-broker-state" {
		t.Fatalf("runtime not loaded: %+v", cfg)
	}
	if cfg.MaxPackBytes != DefaultMaxPackBytes || cfg.HFTimeout != DefaultHFTimeout {
		t.Fatalf("size/timeout defaults not applied: %+v", cfg)
	}
	if cfg.UpstreamHubURL != DefaultUpstreamHubURL || cfg.UpstreamRouterURL != DefaultUpstreamRouterURL || cfg.XetPython != "python3" {
		t.Fatalf("upstream defaults not applied: %+v", cfg)
	}
	if len(cfg.Clients) != 1 || cfg.Clients[0].Name != "agent" {
		t.Fatalf("clients = %+v", cfg.Clients)
	}
}

func TestLoadAllowsExplicitEmptyClientStore(t *testing.T) {
	dir := t.TempDir()
	secrets := filepath.Join(dir, "secrets")
	if err := os.WriteFile(secrets, []byte("# no clients yet\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg, err := Load(testGetenv(map[string]string{
		"HF_BROKER_HF_TOKEN": "hf_token_value", "HF_BROKER_SECRETS_FILE": secrets,
	}))
	if err != nil || len(cfg.Clients) != 0 {
		t.Fatalf("Load() clients = %#v, %v", cfg.Clients, err)
	}
}

func TestLoadReadsAndValidatesGitEndpoint(t *testing.T) {
	env := map[string]string{
		"HF_BROKER_HF_TOKEN": "hf_token_value", "HF_BROKER_SHARED_SECRET": "abcdefghijklmnopqrstuvwxyz123456",
		"HF_BROKER_DEVELOPMENT": "true", "HF_BROKER_AGENT_ENDPOINT": "tcp://127.0.0.1:0",
		"HF_BROKER_GIT_ENDPOINT": "tcp://127.0.0.1:0",
	}
	cfg, err := Load(testGetenv(env))
	if err != nil || cfg.GitEndpoint == nil || cfg.GitEndpoint.String() != "tcp://127.0.0.1:0" {
		t.Fatalf("Git endpoint = %+v, %v", cfg.GitEndpoint, err)
	}
	env["HF_BROKER_AGENT_ENDPOINT"] = "tcp://127.0.0.1:32192"
	env["HF_BROKER_GIT_ENDPOINT"] = env["HF_BROKER_AGENT_ENDPOINT"]
	if _, err := Load(testGetenv(env)); err == nil || !strings.Contains(err.Error(), "must differ") {
		t.Fatalf("shared Git endpoint error = %v", err)
	}
	env["HF_BROKER_GIT_ENDPOINT"] = "unix:///tmp/git.sock"
	if _, err := Load(testGetenv(env)); err == nil || !strings.Contains(err.Error(), "must use tcp") {
		t.Fatalf("invalid Git endpoint error = %v", err)
	}
}

func TestLoadHFTokenFile(t *testing.T) {
	dir := t.TempDir()
	tokenFile := filepath.Join(dir, "hf-token")
	if err := os.WriteFile(tokenFile, []byte("hf_token_value\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	secrets := filepath.Join(dir, "secrets")
	if err := os.WriteFile(secrets, []byte("agent = abcdefghijklmnopqrstuvwxyz123456\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	env := map[string]string{
		"HF_BROKER_HF_TOKEN_FILE": tokenFile,
		"HF_BROKER_SECRETS_FILE":  secrets,
	}
	cfg, err := Load(testGetenv(env))
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}
	if cfg.HFToken != "hf_token_value" || cfg.HFTokenFile != tokenFile {
		t.Fatalf("HF credential config = token %q file %q", cfg.HFToken, cfg.HFTokenFile)
	}
}

func TestLoadAdmissionOverridesForNamedClients(t *testing.T) {
	dir := t.TempDir()
	secrets := filepath.Join(dir, "secrets")
	if err := os.WriteFile(secrets, []byte("agent = abcdefghijklmnopqrstuvwxyz123456\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	admissionPath := filepath.Join(dir, "admission.json")
	admissionJSON := `{"requests_per_window":30,"window_seconds":60,"client_active":20,"client_pending":8,"global_active":100,"global_executing":12,"clients":{"agent":{"requests_per_window":5,"window_seconds":120,"active":4,"pending":2}}}`
	if err := os.WriteFile(admissionPath, []byte(admissionJSON), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg, err := Load(testGetenv(map[string]string{"HF_BROKER_HF_TOKEN": "hf_token_value",
		"HF_BROKER_SECRETS_FILE": secrets, "HF_BROKER_ADMISSION_CONFIG": admissionPath}))
	if err != nil || cfg.Admission.Clients["agent"].Active != 4 {
		t.Fatalf("admission config = %+v, %v", cfg.Admission, err)
	}
}

func TestLoadValidatesSecretsAndNumbers(t *testing.T) {
	tests := []struct {
		name string
		env  map[string]string
		want string
	}{
		{name: "missing token", env: map[string]string{"HF_BROKER_SHARED_SECRET": "abcdefghijklmnopqrstuvwxyz123456"}, want: "HF_BROKER_HF_TOKEN"},
		{name: "token and token file", env: map[string]string{"HF_BROKER_HF_TOKEN": "hf_token_value", "HF_BROKER_HF_TOKEN_FILE": "/tmp/hf-token", "HF_BROKER_SHARED_SECRET": "abcdefghijklmnopqrstuvwxyz123456"}, want: "mutually exclusive"},
		{name: "missing token file", env: map[string]string{"HF_BROKER_HF_TOKEN_FILE": "/tmp/does-not-exist", "HF_BROKER_SHARED_SECRET": "abcdefghijklmnopqrstuvwxyz123456"}, want: "HF_BROKER_HF_TOKEN_FILE"},
		{name: "missing client", env: map[string]string{"HF_BROKER_HF_TOKEN": "hf_token_value"}, want: "HF_BROKER_SHARED_SECRET"},
		{name: "short secret", env: map[string]string{"HF_BROKER_HF_TOKEN": "hf_token_value", "HF_BROKER_SHARED_SECRET": "short"}, want: "shorter than"},
		{name: "bad endpoint", env: map[string]string{"HF_BROKER_HF_TOKEN": "hf_token_value", "HF_BROKER_SHARED_SECRET": "abcdefghijklmnopqrstuvwxyz123456", "HF_BROKER_AGENT_ENDPOINT": "http://127.0.0.1:1"}, want: "HF_BROKER_AGENT_ENDPOINT"},
		{name: "bad network exposure", env: map[string]string{"HF_BROKER_HF_TOKEN": "hf_token_value", "HF_BROKER_SHARED_SECRET": "abcdefghijklmnopqrstuvwxyz123456", "HF_BROKER_NETWORK_EXPOSURE": "yes"}, want: "HF_BROKER_NETWORK_EXPOSURE"},
		{name: "plaintext upstream", env: map[string]string{"HF_BROKER_HF_TOKEN": "hf_token_value", "HF_BROKER_SHARED_SECRET": "abcdefghijklmnopqrstuvwxyz123456", "HF_BROKER_UPSTREAM_HUB_URL": "http://127.0.0.1:9000"}, want: "HF_BROKER_UPSTREAM_HUB_URL"},
		{name: "operator endpoint missing", env: map[string]string{"HF_BROKER_HF_TOKEN": "hf_token_value", "HF_BROKER_SHARED_SECRET": "abcdefghijklmnopqrstuvwxyz123456", "HF_BROKER_OPERATOR_SHARED_SECRET": "operator-secret-abcdefghijklmnopqrstuvwxyz", "HF_BROKER_OPERATOR_ENDPOINT": ""}, want: "HF_BROKER_OPERATOR_ENDPOINT"},
		{name: "shared endpoint", env: map[string]string{"HF_BROKER_HF_TOKEN": "hf_token_value", "HF_BROKER_SHARED_SECRET": "abcdefghijklmnopqrstuvwxyz123456", "HF_BROKER_OPERATOR_SHARED_SECRET": "operator-secret-abcdefghijklmnopqrstuvwxyz", "HF_BROKER_OPERATOR_ENDPOINT": "tcp://127.0.0.1:32191"}, want: "must differ"},
		{name: "telegram token without chat", env: map[string]string{"HF_BROKER_HF_TOKEN": "hf_token_value", "HF_BROKER_SHARED_SECRET": "abcdefghijklmnopqrstuvwxyz123456", "HF_BROKER_TELEGRAM_BOT_TOKEN": "telegram_token_value"}, want: "HF_BROKER_TELEGRAM"},
		{name: "bad telegram chat", env: map[string]string{"HF_BROKER_HF_TOKEN": "hf_token_value", "HF_BROKER_SHARED_SECRET": "abcdefghijklmnopqrstuvwxyz123456", "HF_BROKER_TELEGRAM_BOT_TOKEN": "telegram_token_value", "HF_BROKER_TELEGRAM_CHAT_ID": "chat"}, want: "HF_BROKER_TELEGRAM_CHAT_ID"},
		{name: "telegram base without token", env: map[string]string{"HF_BROKER_HF_TOKEN": "hf_token_value", "HF_BROKER_SHARED_SECRET": "abcdefghijklmnopqrstuvwxyz123456", "HF_BROKER_TELEGRAM_API_BASE": "https://telegram.example"}, want: "HF_BROKER_TELEGRAM"},
		{name: "plaintext remote telegram base", env: map[string]string{"HF_BROKER_HF_TOKEN": "hf_token_value", "HF_BROKER_SHARED_SECRET": "abcdefghijklmnopqrstuvwxyz123456", "HF_BROKER_TELEGRAM_BOT_TOKEN": "telegram_token_value", "HF_BROKER_TELEGRAM_CHAT_ID": "1", "HF_BROKER_TELEGRAM_API_BASE": "http://telegram.example"}, want: "HF_BROKER_TELEGRAM_API_BASE"},
		{name: "telegram base query", env: map[string]string{"HF_BROKER_HF_TOKEN": "hf_token_value", "HF_BROKER_SHARED_SECRET": "abcdefghijklmnopqrstuvwxyz123456", "HF_BROKER_TELEGRAM_BOT_TOKEN": "telegram_token_value", "HF_BROKER_TELEGRAM_CHAT_ID": "1", "HF_BROKER_TELEGRAM_API_BASE": "https://telegram.example?"}, want: "HF_BROKER_TELEGRAM_API_BASE"},
		{name: "token pasted into token file", env: map[string]string{"HF_BROKER_HF_TOKEN_FILE": "hf_token_value", "HF_BROKER_SHARED_SECRET": "abcdefghijklmnopqrstuvwxyz123456"}, want: "HF_BROKER_HF_TOKEN_FILE"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			_, err := Load(testGetenv(tc.env))
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("Load() error = %v, want containing %q", err, tc.want)
			}
			if err != nil && strings.Contains(err.Error(), "hf_token_value") {
				t.Fatalf("error leaked token: %v", err)
			}
			if err != nil && strings.Contains(err.Error(), "telegram_token_value") {
				t.Fatalf("error leaked telegram token: %v", err)
			}
		})
	}
}

func TestLoadAllowsDevelopmentLoopbackUpstreamAndAcknowledgedNetworkEndpoint(t *testing.T) {
	env := map[string]string{
		"HF_BROKER_HF_TOKEN": "hf_token_value", "HF_BROKER_SHARED_SECRET": "abcdefghijklmnopqrstuvwxyz123456",
		"HF_BROKER_DEVELOPMENT": "true", "HF_BROKER_AGENT_ENDPOINT": "tcp://192.0.2.10:9000",
		"HF_BROKER_NETWORK_EXPOSURE": "allow", "HF_BROKER_UPSTREAM_HUB_URL": "http://127.0.0.1:9001",
		"HF_BROKER_UPSTREAM_ROUTER_URL": "http://[::1]:9002",
	}
	if _, err := Load(testGetenv(env)); err != nil {
		t.Fatal(err)
	}
}

func TestLoadRejectsDuplicateClientSecrets(t *testing.T) {
	dir := t.TempDir()
	duplicateSecret := "abcdefghijklmnopqrstuvwxyz123456"
	secrets := filepath.Join(dir, "secrets")
	if err := os.WriteFile(secrets, []byte("agent = "+duplicateSecret+"\nci = "+duplicateSecret+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	env := map[string]string{
		"HF_BROKER_HF_TOKEN":     "hf_token_value",
		"HF_BROKER_SECRETS_FILE": secrets,
	}

	_, err := Load(testGetenv(env))
	if err == nil || !strings.Contains(err.Error(), "duplicate client secret") {
		t.Fatalf("Load() error = %v, want duplicate client secret", err)
	}
	if strings.Contains(err.Error(), duplicateSecret) {
		t.Fatalf("error leaked client secret: %v", err)
	}
}

func TestLoadOperatorCredentialsAreSeparate(t *testing.T) {
	dir := t.TempDir()
	clients := filepath.Join(dir, "clients")
	operators := filepath.Join(dir, "operators")
	clientSecret := "client-secret-abcdefghijklmnopqrstuvwxyz"
	operatorSecret := "operator-secret-abcdefghijklmnopqrstuvwxyz"
	if err := os.WriteFile(clients, []byte("agent = "+clientSecret+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(operators, []byte("onur = "+operatorSecret+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	env := map[string]string{
		"HF_BROKER_HF_TOKEN": "hf_token_value", "HF_BROKER_SECRETS_FILE": clients,
		"HF_BROKER_OPERATOR_SECRETS_FILE": operators, "HF_BROKER_OPERATOR_ENDPOINT": "tcp://[::1]:32192",
	}
	cfg, err := Load(testGetenv(env))
	if err != nil {
		t.Fatal(err)
	}
	if len(cfg.Operators) != 1 || cfg.Operators[0].Name != "onur" || cfg.OperatorEndpoint == nil || cfg.OperatorEndpoint.String() != "tcp://[::1]:32192" {
		t.Fatalf("operator config = %+v", cfg)
	}
	if err := os.WriteFile(operators, []byte("onur = "+clientSecret+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(testGetenv(env)); err == nil || !strings.Contains(err.Error(), "reuses a client secret") || strings.Contains(err.Error(), clientSecret) {
		t.Fatalf("reused operator error = %v", err)
	}
}

func TestLoadOverrides(t *testing.T) {
	env := map[string]string{
		"HF_BROKER_HF_TOKEN":            "hf_token_value",
		"HF_BROKER_SHARED_SECRET":       "abcdefghijklmnopqrstuvwxyz123456",
		"HF_BROKER_AGENT_ENDPOINT":      "unix:///run/hf-broker/agent.sock",
		"HF_BROKER_SCOPE_FILE":          "/tmp/scope.json",
		"HF_BROKER_STATE_DIR":           "/tmp/state",
		"HF_BROKER_MAX_PACK_BYTES":      "64",
		"HF_BROKER_HF_TIMEOUT":          "5",
		"HF_BROKER_UPSTREAM_HUB_URL":    "https://hub.example.test",
		"HF_BROKER_UPSTREAM_ROUTER_URL": "https://router.example.test",
		"HF_BROKER_XET_PYTHON":          "/opt/hf-broker/bin/python",
		"HF_BROKER_TELEGRAM_BOT_TOKEN":  "telegram_token_value",
		"HF_BROKER_TELEGRAM_API_BASE":   "http://127.0.0.1:8080/client/unyolo/",
		"HF_BROKER_TELEGRAM_CHAT_ID":    "12345",
	}
	cfg, err := Load(testGetenv(env))
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}
	if cfg.AgentEndpoint.String() != "unix:///run/hf-broker/agent.sock" || cfg.ScopeFile != "/tmp/scope.json" || cfg.StateDir != "/tmp/state" {
		t.Fatalf("overrides not applied: %+v", cfg)
	}
	if cfg.MaxPackBytes != 64 || cfg.HFTimeout != 5*time.Second {
		t.Fatalf("numeric overrides not applied: %+v", cfg)
	}
	if cfg.UpstreamHubURL != "https://hub.example.test" || cfg.UpstreamRouterURL != "https://router.example.test" || cfg.XetPython != "/opt/hf-broker/bin/python" {
		t.Fatalf("upstream overrides not applied: %+v", cfg)
	}
	if cfg.TelegramBotToken != "telegram_token_value" || cfg.TelegramAPIBase != "http://127.0.0.1:8080/client/unyolo" || cfg.TelegramChatID != 12345 {
		t.Fatalf("telegram config not applied: %+v", cfg)
	}
}

func TestLoadTelegramTokenFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "telegram-token")
	if err := os.WriteFile(path, []byte("telegram_file_token\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	env := map[string]string{
		"HF_BROKER_HF_TOKEN": "hf_token_value", "HF_BROKER_SHARED_SECRET": "abcdefghijklmnopqrstuvwxyz123456",
		"HF_BROKER_TELEGRAM_BOT_TOKEN_FILE": path, "HF_BROKER_TELEGRAM_CHAT_ID": "12345",
	}
	cfg, err := Load(testGetenv(env))
	if err != nil || cfg.TelegramBotToken != "telegram_file_token" || cfg.TelegramChatID != 12345 {
		t.Fatalf("Load(token file) cfg=%+v err=%v", cfg, err)
	}
	env["HF_BROKER_TELEGRAM_BOT_TOKEN"] = "inline"
	if _, err := Load(testGetenv(env)); err == nil || !strings.Contains(err.Error(), "mutually exclusive") {
		t.Fatalf("Load(inline and file) error = %v", err)
	}
}

func TestLoadTelegramTokenFileRejectsOversizedSecret(t *testing.T) {
	path := filepath.Join(t.TempDir(), "telegram-token")
	if err := os.WriteFile(path, []byte(strings.Repeat("x", maxSecretFileBytes+1)), 0o600); err != nil {
		t.Fatal(err)
	}
	env := map[string]string{
		"HF_BROKER_HF_TOKEN": "hf_token_value", "HF_BROKER_SHARED_SECRET": "abcdefghijklmnopqrstuvwxyz123456",
		"HF_BROKER_TELEGRAM_BOT_TOKEN_FILE": path, "HF_BROKER_TELEGRAM_CHAT_ID": "12345",
	}
	_, err := Load(testGetenv(env))
	if err == nil || !strings.Contains(err.Error(), "exceeds") || strings.Contains(err.Error(), path) {
		t.Fatalf("Load(oversized token file) error = %v", err)
	}
}

func testGetenv(values map[string]string) func(string) string {
	defaults := map[string]string{
		"HF_BROKER_AGENT_ENDPOINT":    "tcp://127.0.0.1:32191",
		"HF_BROKER_OPERATOR_ENDPOINT": "tcp://127.0.0.1:32192",
		"HF_BROKER_SCOPE_FILE":        "/tmp/hf-broker-scope.json",
		"HF_BROKER_STATE_DIR":         "/tmp/hf-broker-state",
	}
	return func(key string) string {
		if value, ok := values[key]; ok {
			return value
		}
		return defaults[key]
	}
}
