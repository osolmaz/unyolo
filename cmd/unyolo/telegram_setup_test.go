package main

import (
	"encoding/hex"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/osolmaz/unyolo/deployment/api"
	"github.com/osolmaz/unyolo/setup/capability"
	setupintent "github.com/osolmaz/unyolo/setup/intent"
)

func TestReadTelegramBotTokenFile(t *testing.T) {
	directory := t.TempDir()
	write := func(name, data string) string {
		path := filepath.Join(directory, name)
		if err := os.WriteFile(path, []byte(data), 0o600); err != nil {
			t.Fatal(err)
		}
		return path
	}
	token := "123456789:" + strings.Repeat("A", 35)
	value, err := readTelegramBotTokenFile(write("token", token+"\n"))
	if err != nil || string(value) != token {
		t.Fatalf("readTelegramBotTokenFile() = %q, %v", value, err)
	}
	link := filepath.Join(directory, "link")
	if err := os.Symlink(filepath.Join(directory, "token"), link); err != nil {
		t.Fatal(err)
	}
	for name, path := range map[string]string{
		"relative":     "token",
		"missing":      filepath.Join(directory, "missing"),
		"symlink":      link,
		"empty":        write("empty", ""),
		"no separator": write("plain", strings.Repeat("A", 40)),
		"bad bot id":   write("bot", "bot:"+strings.Repeat("A", 35)),
		"short secret": write("short", "123:abc"),
		"two tokens":   write("two", token+" "+token),
		"too large":    write("large", strings.Repeat("1", 2048)),
	} {
		if _, err := readTelegramBotTokenFile(path); err == nil {
			t.Fatalf("%s token file was accepted", name)
		}
	}
}

func TestCollectPlanSecretHandlesTelegramSlots(t *testing.T) {
	token := "123456789:" + strings.Repeat("B", 35)
	path := filepath.Join(t.TempDir(), "token")
	if err := os.WriteFile(path, []byte(token), 0o600); err != nil {
		t.Fatal(err)
	}
	prompter := &scriptedPrompter{t: t, answers: []scriptedAnswer{{kind: "text", stringValue: path}}}
	value, err := collectPlanSecret(t.Context(), prompter, telegramBotTokenSlot, api.RenderSecretPrompt{})
	if err != nil || string(value) != token {
		t.Fatalf("bot token = %q, %v", value, err)
	}
	key, err := collectPlanSecret(t.Context(), &scriptedPrompter{t: t}, telegramInboxKeySlot, api.RenderSecretPrompt{})
	decoded, decodeErr := hex.DecodeString(string(key))
	if err != nil || decodeErr != nil || len(decoded) != 32 {
		t.Fatalf("inbox key = %q, %v, %v", key, err, decodeErr)
	}
}

func TestTelegramInstallationChoices(t *testing.T) {
	intent := setupintent.Intent{
		APIVersion: setupintent.APIVersion, Goal: setupintent.GoalCredentialService,
		CredentialService: &setupintent.CredentialService{Location: setupintent.ServiceNative, Providers: []string{"github"}},
		Telegram:          &setupintent.Telegram{ChatID: -100},
	}
	value, err := installationFromIntent(intent, "onur", "")
	if err != nil || value.Telegram == nil || value.Telegram.ChatID != -100 {
		t.Fatalf("installation = %#v, %v", value.Telegram, err)
	}
	restored, err := intentFromInstallation(value)
	if err != nil || restored.Telegram == nil || restored.Telegram.ChatID != -100 {
		t.Fatalf("intent = %#v, %v", restored.Telegram, err)
	}
	if !strings.Contains(installationSummary(value), "Telegram chat: -100") {
		t.Fatalf("summary = %q", installationSummary(value))
	}
	systemd := setupOptions{Capabilities: capability.Snapshot{ServiceBackend: "systemd", Features: []capability.Feature{capability.FeatureLocalAccounts}}}
	if actions := telegramActions(value, systemd); len(actions) != 2 || actions[1].Value != "telegram-off" {
		t.Fatalf("enabled actions = %#v", actions)
	}
	value.Telegram = nil
	if actions := telegramActions(value, systemd); len(actions) != 1 || actions[0].Value != "telegram-chat" {
		t.Fatalf("available actions = %#v", actions)
	}
	if actions := telegramActions(value, setupOptions{}); len(actions) != 0 {
		t.Fatalf("unavailable actions = %#v", actions)
	}
}

func TestEditInstallationTurnsTelegramOnAndOff(t *testing.T) {
	value := installationWithProviders()
	options := setupOptions{Capabilities: capability.Snapshot{ServiceBackend: "systemd", Features: []capability.Feature{capability.FeatureLocalAccounts}}}
	prompter := &scriptedPrompter{t: t, answers: []scriptedAnswer{
		{kind: "select", stringValue: "telegram-chat"},
		{kind: "text", stringValue: "-1001234"},
		{kind: "select", stringValue: "done"},
	}}
	updated, err := editInstallation(t.Context(), prompter, value, options)
	if err != nil || updated.Telegram == nil || updated.Telegram.ChatID != -1001234 {
		t.Fatalf("telegram on = %#v, %v", updated.Telegram, err)
	}
	prompter = &scriptedPrompter{t: t, answers: []scriptedAnswer{
		{kind: "select", stringValue: "telegram-off"},
		{kind: "select", stringValue: "done"},
	}}
	updated, err = editInstallation(t.Context(), prompter, updated, options)
	if err != nil || updated.Telegram != nil {
		t.Fatalf("telegram off = %#v, %v", updated.Telegram, err)
	}
}
