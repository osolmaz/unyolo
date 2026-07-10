package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestLoadDefaultsAndSecretsFile(t *testing.T) {
	dir := t.TempDir()
	secrets := filepath.Join(dir, "secrets")
	if err := os.WriteFile(secrets, []byte("agent = abcdefghijklmnopqrstuvwxyz123456\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	env := map[string]string{
		"HF_BROKER_HF_TOKEN":     "hf_token_value",
		"HF_BROKER_SECRETS_FILE": secrets,
	}
	cfg, err := Load(func(key string) string { return env[key] })
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}
	if cfg.BindAddr != DefaultBindAddr || cfg.Port != DefaultPort || cfg.ScopeFile != DefaultScopeFile {
		t.Fatalf("defaults not applied: %+v", cfg)
	}
	if cfg.MaxPackBytes != DefaultMaxPackBytes || cfg.HFTimeout != DefaultHFTimeout {
		t.Fatalf("size/timeout defaults not applied: %+v", cfg)
	}
	if len(cfg.Clients) != 1 || cfg.Clients[0].Name != "agent" {
		t.Fatalf("clients = %+v", cfg.Clients)
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
	cfg, err := Load(func(key string) string { return env[key] })
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}
	if cfg.HFToken != "hf_token_value" {
		t.Fatalf("HFToken = %q, want file token", cfg.HFToken)
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
		{name: "bad port", env: map[string]string{"HF_BROKER_HF_TOKEN": "hf_token_value", "HF_BROKER_SHARED_SECRET": "abcdefghijklmnopqrstuvwxyz123456", "HF_BROKER_PORT": "zero"}, want: "HF_BROKER_PORT"},
		{name: "bad operator port", env: map[string]string{"HF_BROKER_HF_TOKEN": "hf_token_value", "HF_BROKER_SHARED_SECRET": "abcdefghijklmnopqrstuvwxyz123456", "HF_BROKER_OPERATOR_SHARED_SECRET": "operator-secret-abcdefghijklmnopqrstuvwxyz", "HF_BROKER_OPERATOR_PORT": "zero"}, want: "HF_BROKER_OPERATOR_PORT"},
		{name: "shared listener port", env: map[string]string{"HF_BROKER_HF_TOKEN": "hf_token_value", "HF_BROKER_SHARED_SECRET": "abcdefghijklmnopqrstuvwxyz123456", "HF_BROKER_OPERATOR_SHARED_SECRET": "operator-secret-abcdefghijklmnopqrstuvwxyz", "HF_BROKER_OPERATOR_PORT": "8080"}, want: "different ports"},
		{name: "telegram token without chat", env: map[string]string{"HF_BROKER_HF_TOKEN": "hf_token_value", "HF_BROKER_SHARED_SECRET": "abcdefghijklmnopqrstuvwxyz123456", "HF_BROKER_TELEGRAM_BOT_TOKEN": "telegram_token_value"}, want: "HF_BROKER_TELEGRAM"},
		{name: "bad telegram chat", env: map[string]string{"HF_BROKER_HF_TOKEN": "hf_token_value", "HF_BROKER_SHARED_SECRET": "abcdefghijklmnopqrstuvwxyz123456", "HF_BROKER_TELEGRAM_BOT_TOKEN": "telegram_token_value", "HF_BROKER_TELEGRAM_CHAT_ID": "chat"}, want: "HF_BROKER_TELEGRAM_CHAT_ID"},
		{name: "token pasted into token file", env: map[string]string{"HF_BROKER_HF_TOKEN_FILE": "hf_token_value", "HF_BROKER_SHARED_SECRET": "abcdefghijklmnopqrstuvwxyz123456"}, want: "HF_BROKER_HF_TOKEN_FILE"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			_, err := Load(func(key string) string { return tc.env[key] })
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

	_, err := Load(func(key string) string { return env[key] })
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
		"HF_BROKER_OPERATOR_SECRETS_FILE": operators, "HF_BROKER_OPERATOR_BIND_ADDR": "::1", "HF_BROKER_OPERATOR_PORT": "9091",
	}
	cfg, err := Load(func(key string) string { return env[key] })
	if err != nil {
		t.Fatal(err)
	}
	if len(cfg.Operators) != 1 || cfg.Operators[0].Name != "onur" || cfg.OperatorBindAddr != "::1" || cfg.OperatorPort != 9091 {
		t.Fatalf("operator config = %+v", cfg)
	}
	if err := os.WriteFile(operators, []byte("onur = "+clientSecret+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(func(key string) string { return env[key] }); err == nil || !strings.Contains(err.Error(), "reuses a client secret") || strings.Contains(err.Error(), clientSecret) {
		t.Fatalf("reused operator error = %v", err)
	}
}

func TestLoadOverrides(t *testing.T) {
	env := map[string]string{
		"HF_BROKER_HF_TOKEN":           "hf_token_value",
		"HF_BROKER_SHARED_SECRET":      "abcdefghijklmnopqrstuvwxyz123456",
		"HF_BROKER_BIND_ADDR":          "0.0.0.0",
		"HF_BROKER_PORT":               "9090",
		"HF_BROKER_SCOPE_FILE":         "/tmp/scope.json",
		"HF_BROKER_STATE_DIR":          "/tmp/state",
		"HF_BROKER_MAX_PACK_BYTES":     "64",
		"HF_BROKER_HF_TIMEOUT":         "5",
		"HF_BROKER_TELEGRAM_BOT_TOKEN": "telegram_token_value",
		"HF_BROKER_TELEGRAM_CHAT_ID":   "12345",
	}
	cfg, err := Load(func(key string) string { return env[key] })
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}
	if cfg.BindAddr != "0.0.0.0" || cfg.Port != 9090 || cfg.ScopeFile != "/tmp/scope.json" || cfg.StateDir != "/tmp/state" {
		t.Fatalf("overrides not applied: %+v", cfg)
	}
	if cfg.MaxPackBytes != 64 || cfg.HFTimeout != 5*time.Second {
		t.Fatalf("numeric overrides not applied: %+v", cfg)
	}
	if cfg.TelegramBotToken != "telegram_token_value" || cfg.TelegramChatID != 12345 {
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
	cfg, err := Load(func(key string) string { return env[key] })
	if err != nil || cfg.TelegramBotToken != "telegram_file_token" || cfg.TelegramChatID != 12345 {
		t.Fatalf("Load(token file) cfg=%+v err=%v", cfg, err)
	}
	env["HF_BROKER_TELEGRAM_BOT_TOKEN"] = "inline"
	if _, err := Load(func(key string) string { return env[key] }); err == nil || !strings.Contains(err.Error(), "mutually exclusive") {
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
	_, err := Load(func(key string) string { return env[key] })
	if err == nil || !strings.Contains(err.Error(), "exceeds") || strings.Contains(err.Error(), path) {
		t.Fatalf("Load(oversized token file) error = %v", err)
	}
}
