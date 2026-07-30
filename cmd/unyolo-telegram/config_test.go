package main

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/osolmaz/unyolo/approval/notifier/telegram"
)

func TestLoadIngressConfigStrictly(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.json")
	writeTestFile(t, path, `{
  "telegram_bot_token_file": "/etc/unyolo-telegram/telegram-bot-token",
  "telegram_api_base": "http://127.0.0.1:8080/client/unyolo",
  "telegram_chat_id": 42,
  "inbox_path": "/var/lib/unyolo-telegram/callbacks.db",
  "inbox_key_file": "/etc/unyolo-telegram/inbox-key",
  "routes": {"h": {"operator_endpoint": "unix:///run/hf/operator.sock", "operator_token_file": "/etc/unyolo-telegram/operator-token-h"}}
}`)
	cfg, err := loadIngressConfig(path)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.TelegramChatID != 42 || cfg.TelegramAPIBase != "http://127.0.0.1:8080/client/unyolo" || cfg.Routes[telegram.RouteHuggingFace].OperatorEndpoint != "unix:///run/hf/operator.sock" {
		t.Fatalf("loadIngressConfig() = %+v", cfg)
	}

	writeTestFile(t, path, `{"telegram_bot_token_file":"/t","telegram_bot_token_file":"/u","telegram_chat_id":1,"routes":{"h":{"operator_endpoint":"unix:///s","operator_token_file":"/o"}}}`)
	if _, err := loadIngressConfig(path); err == nil || !strings.Contains(err.Error(), "duplicate") {
		t.Fatalf("duplicate config error = %v", err)
	}
}

func TestValidateIngressConfigRejectsIncompleteAndUnknownRoutes(t *testing.T) {
	valid := ingressConfig{TelegramBotTokenFile: "/t", TelegramChatID: 1, InboxPath: "/state.db", InboxKeyFile: "/key",
		Routes: map[string]routeConfig{"h": {OperatorEndpoint: "unix:///s", OperatorTokenFile: "/o"}}}
	tests := []func(*ingressConfig){
		func(cfg *ingressConfig) { cfg.TelegramBotTokenFile = "relative" },
		func(cfg *ingressConfig) { cfg.TelegramChatID = 0 },
		func(cfg *ingressConfig) { cfg.Routes = nil },
		func(cfg *ingressConfig) {
			cfg.Routes = map[string]routeConfig{"x": {OperatorEndpoint: "unix:///s", OperatorTokenFile: "/o"}}
		},
		func(cfg *ingressConfig) { cfg.Routes["h"] = routeConfig{OperatorTokenFile: "/o"} },
		func(cfg *ingressConfig) {
			cfg.Routes["h"] = routeConfig{OperatorEndpoint: "unix:///s", OperatorTokenFile: "relative"}
		},
	}
	for index, mutate := range tests {
		cfg := valid
		cfg.Routes = cloneRoutes(valid.Routes)
		mutate(&cfg)
		if err := validateIngressConfig(cfg); err == nil {
			t.Fatalf("case %d accepted: %+v", index, cfg)
		}
	}
}

func TestValidateTelegramAPIBase(t *testing.T) {
	for _, value := range []string{"", "https://bots.example.test/client/unyolo", "http://127.0.0.1:8080/client/unyolo", "http://[::1]:8080/client/unyolo"} {
		if err := validateTelegramAPIBase(value); err != nil {
			t.Fatalf("validateTelegramAPIBase(%q) = %v", value, err)
		}
	}
	for _, value := range []string{
		"http://example.test", "ftp://127.0.0.1", "/relative", "https://example.test?token=secret",
		"https://example.test?", "https://example.test#", "https://user:secret@example.test",
	} {
		if err := validateTelegramAPIBase(value); err == nil {
			t.Fatalf("validateTelegramAPIBase(%q) succeeded", value)
		}
	}
}

func TestBuildIngressReadsManagedSecrets(t *testing.T) {
	dir := t.TempDir()
	bot := filepath.Join(dir, "bot")
	operator := filepath.Join(dir, "operator")
	key := filepath.Join(dir, "key")
	writeTestFile(t, bot, "telegram-token\n")
	writeTestFile(t, operator, strings.Repeat("o", 32)+"\n")
	writeTestFile(t, key, strings.Repeat("0", 64)+"\n")
	cfg := ingressConfig{TelegramBotTokenFile: bot, TelegramChatID: 1, InboxPath: filepath.Join(dir, "callbacks.db"), InboxKeyFile: key,
		Routes: map[string]routeConfig{"h": {OperatorEndpoint: "unix:///tmp/operator.sock", OperatorTokenFile: operator}}}
	client, dispatcher, inbox, err := buildIngress(t.Context(), cfg)
	if err != nil || client == nil || dispatcher == nil || inbox == nil {
		t.Fatalf("buildIngress() client=%v dispatcher=%v error=%v", client, dispatcher, err)
	}
	_ = inbox.Close()
}

func TestRunServeStopsWithCanceledContext(t *testing.T) {
	dir := t.TempDir()
	bot := filepath.Join(dir, "bot")
	operator := filepath.Join(dir, "operator")
	key := filepath.Join(dir, "key")
	inbox := filepath.Join(dir, "callbacks.db")
	config := filepath.Join(dir, "config.json")
	writeTestFile(t, bot, "telegram-token\n")
	writeTestFile(t, operator, strings.Repeat("o", 32)+"\n")
	writeTestFile(t, key, strings.Repeat("0", 64)+"\n")
	writeTestFile(t, config, `{"telegram_bot_token_file":"`+bot+`","telegram_chat_id":1,"inbox_path":"`+inbox+`","inbox_key_file":"`+key+`","routes":{"h":{"operator_endpoint":"unix:///tmp/operator.sock","operator_token_file":"`+operator+`"}}}`)
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if err := runServe(ctx, []string{"--config", config}, &strings.Builder{}); err != nil {
		t.Fatal(err)
	}
}

func cloneRoutes(routes map[string]routeConfig) map[string]routeConfig {
	cloned := make(map[string]routeConfig, len(routes))
	for route, value := range routes {
		cloned[route] = value
	}
	return cloned
}

func writeTestFile(t *testing.T, path, content string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
}
