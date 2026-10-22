package main

import (
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/osolmaz/unyolo/approval/notifier/telegram"
)

// stubBotAPI serves the Bot API methods that the owner start and the doctor
// call. A nonzero conflict status answers getUpdates with that status.
func stubBotAPI(t *testing.T, webhook string, conflict bool) string {
	t.Helper()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch {
		case strings.HasSuffix(r.URL.Path, "/getWebhookInfo"):
			_, _ = w.Write([]byte(`{"ok":true,"result":{"url":"` + webhook + `"}}`))
		case strings.HasSuffix(r.URL.Path, "/getUpdates") && conflict:
			w.WriteHeader(http.StatusConflict)
			_, _ = w.Write([]byte(`{"ok":false,"error_code":409,"description":"Conflict"}`))
		case strings.HasSuffix(r.URL.Path, "/getUpdates"):
			_, _ = w.Write([]byte(`{"ok":true,"result":[]}`))
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	t.Cleanup(server.Close)
	return server.URL
}

// ownerTestConfig writes the files of one owner config whose bot API is base
// and whose only route points to a socket that does not exist.
func ownerTestConfig(t *testing.T, base string) ingressConfig {
	t.Helper()
	dir := t.TempDir()
	bot, operator, key := filepath.Join(dir, "bot"), filepath.Join(dir, "operator.json"), filepath.Join(dir, "key")
	writeTestFile(t, bot, "123:token\n")
	writeOperatorClient(t, operator)
	writeTestFile(t, key, strings.Repeat("0", 64)+"\n")
	return ingressConfig{
		TelegramBotTokenFile: bot, TelegramAPIBase: base, TelegramChatID: 1,
		InboxPath: filepath.Join(dir, "callbacks.db"), InboxKeyFile: key,
		Routes: map[string]routeConfig{"g": {OperatorClientFile: operator}},
	}
}

func TestStartOwnerRecordsAndClearsConflicts(t *testing.T) {
	cfg := ownerTestConfig(t, stubBotAPI(t, "", true))
	built, err := buildIngress(t.Context(), cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = built.inbox.Close() }()
	if err := startOwner(t.Context(), cfg, built); !errors.Is(err, telegram.ErrAnotherOwner) || !strings.Contains(err.Error(), "exactly one unyolo-telegram") {
		t.Fatalf("startOwner() with a competing poller = %v", err)
	}
	if _, err := os.Stat(ownerConflictPath(cfg)); err != nil {
		t.Fatalf("conflict was not recorded: %v", err)
	}

	clean := ownerTestConfig(t, stubBotAPI(t, "", false))
	clean.InboxPath = cfg.InboxPath
	cleanBuilt, err := buildIngress(t.Context(), ingressConfig{
		TelegramBotTokenFile: clean.TelegramBotTokenFile, TelegramAPIBase: clean.TelegramAPIBase, TelegramChatID: 1,
		InboxPath: filepath.Join(t.TempDir(), "callbacks.db"), InboxKeyFile: clean.InboxKeyFile, Routes: clean.Routes,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = cleanBuilt.inbox.Close() }()
	if err := startOwner(t.Context(), clean, cleanBuilt); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(ownerConflictPath(cfg)); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("conflict record survived a clean start: %v", err)
	}
}

func TestRecordOwnerConflictPassesOtherErrors(t *testing.T) {
	path := filepath.Join(t.TempDir(), "owner-conflict")
	other := errors.New("network down")
	if err := recordOwnerConflict(path, other); !errors.Is(err, other) {
		t.Fatalf("recordOwnerConflict() = %v", err)
	}
	if err := recordOwnerConflict(path, nil); err != nil {
		t.Fatalf("recordOwnerConflict(nil) = %v", err)
	}
	if _, err := os.Stat(path); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("a non-conflict error was recorded")
	}
	if err := recordOwnerConflict(filepath.Join(path, "missing", "record"), telegram.ErrAnotherOwner); !errors.Is(err, telegram.ErrAnotherOwner) {
		t.Fatalf("unwritable record = %v", err)
	}
}

func TestNotifyReady(t *testing.T) {
	t.Setenv("NOTIFY_SOCKET", "")
	if err := notifyReady(); err != nil {
		t.Fatal(err)
	}
	socket := filepath.Join(t.TempDir(), "notify")
	listener, err := net.ListenUnixgram("unixgram", &net.UnixAddr{Name: socket, Net: "unixgram"})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = listener.Close() }()
	t.Setenv("NOTIFY_SOCKET", socket)
	if err := notifyReady(); err != nil {
		t.Fatal(err)
	}
	buffer := make([]byte, 64)
	count, err := listener.Read(buffer)
	if err != nil || string(buffer[:count]) != "READY=1" {
		t.Fatalf("notification = %q, %v", buffer[:count], err)
	}
	t.Setenv("NOTIFY_SOCKET", filepath.Join(t.TempDir(), "missing"))
	if err := notifyReady(); err == nil {
		t.Fatal("unreachable notify socket was accepted")
	}
}

func TestDoctorReportsOwnerAndRoutes(t *testing.T) {
	cfg := ownerTestConfig(t, stubBotAPI(t, "", false))
	path := filepath.Join(t.TempDir(), "config.json")
	writeConfig(t, path, cfg)
	var output strings.Builder
	err := runDoctor(t.Context(), []string{"--config", path}, &output, &strings.Builder{})
	if err == nil || !strings.Contains(output.String(), "ok   bot: reachable, no webhook") ||
		!strings.Contains(output.String(), "ok   owner:") || !strings.Contains(output.String(), "FAIL route g:") {
		t.Fatalf("doctor = %v\n%s", err, output.String())
	}
	writeTestFile(t, ownerConflictPath(cfg), "2026-10-22T10:00:00Z\n")
	webhook := ownerTestConfig(t, stubBotAPI(t, "https://bots.example.test/hook", false))
	webhook.InboxPath = cfg.InboxPath
	writeConfig(t, path, webhook)
	output.Reset()
	_ = runDoctor(t.Context(), []string{"--config", path}, &output, &strings.Builder{})
	if !strings.Contains(output.String(), "FAIL bot: the bot delivers its updates to a webhook") ||
		!strings.Contains(output.String(), "FAIL owner: another process received this bot's updates at 2026-10-22T10:00:00Z") {
		t.Fatalf("doctor with another owner:\n%s", output.String())
	}
	output.Reset()
	if err := runDoctor(t.Context(), []string{"--config", filepath.Join(t.TempDir(), "missing.json")}, &output, &strings.Builder{}); err == nil ||
		!strings.Contains(output.String(), "FAIL config:") {
		t.Fatalf("doctor without config = %v\n%s", err, output.String())
	}
	if err := runDoctor(t.Context(), []string{"extra"}, &output, &strings.Builder{}); err == nil {
		t.Fatal("doctor accepted a positional argument")
	}
}

func writeConfig(t *testing.T, path string, cfg ingressConfig) {
	t.Helper()
	routes := make([]string, 0, len(cfg.Routes))
	for route, value := range cfg.Routes {
		routes = append(routes, `"`+route+`":{"operator_client_file":"`+value.OperatorClientFile+`"}`)
	}
	writeTestFile(t, path, `{"telegram_bot_token_file":"`+cfg.TelegramBotTokenFile+`","telegram_api_base":"`+cfg.TelegramAPIBase+
		`","telegram_chat_id":1,"inbox_path":"`+cfg.InboxPath+`","inbox_key_file":"`+cfg.InboxKeyFile+`","routes":{`+strings.Join(routes, ",")+`}}`)
}
