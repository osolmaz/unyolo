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

func TestLoadValidatesSecretsAndNumbers(t *testing.T) {
	tests := []struct {
		name string
		env  map[string]string
		want string
	}{
		{name: "missing token", env: map[string]string{"HF_BROKER_SHARED_SECRET": "abcdefghijklmnopqrstuvwxyz123456"}, want: "HF_BROKER_HF_TOKEN"},
		{name: "missing client", env: map[string]string{"HF_BROKER_HF_TOKEN": "hf_token_value"}, want: "HF_BROKER_SHARED_SECRET"},
		{name: "short secret", env: map[string]string{"HF_BROKER_HF_TOKEN": "hf_token_value", "HF_BROKER_SHARED_SECRET": "short"}, want: "shorter than"},
		{name: "bad port", env: map[string]string{"HF_BROKER_HF_TOKEN": "hf_token_value", "HF_BROKER_SHARED_SECRET": "abcdefghijklmnopqrstuvwxyz123456", "HF_BROKER_PORT": "zero"}, want: "HF_BROKER_PORT"},
		{name: "telegram token without chat", env: map[string]string{"HF_BROKER_HF_TOKEN": "hf_token_value", "HF_BROKER_SHARED_SECRET": "abcdefghijklmnopqrstuvwxyz123456", "HF_BROKER_TELEGRAM_BOT_TOKEN": "telegram_token_value"}, want: "HF_BROKER_TELEGRAM"},
		{name: "bad telegram chat", env: map[string]string{"HF_BROKER_HF_TOKEN": "hf_token_value", "HF_BROKER_SHARED_SECRET": "abcdefghijklmnopqrstuvwxyz123456", "HF_BROKER_TELEGRAM_BOT_TOKEN": "telegram_token_value", "HF_BROKER_TELEGRAM_CHAT_ID": "chat"}, want: "HF_BROKER_TELEGRAM_CHAT_ID"},
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
