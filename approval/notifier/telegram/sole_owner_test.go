package telegram

import (
	"bytes"
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"

	"github.com/osolmaz/unyolo/approval/notifier"
)

func soleOwnerServer(t *testing.T, webhook string, updatesStatus int) (*Client, *[]string) {
	t.Helper()
	var methods []string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		method := r.URL.Path[strings.LastIndex(r.URL.Path, "/")+1:]
		methods = append(methods, method)
		w.Header().Set("Content-Type", "application/json")
		switch method {
		case "getWebhookInfo":
			_, _ = w.Write([]byte(`{"ok":true,"result":{"url":"` + webhook + `"}}`))
		case "getUpdates":
			w.WriteHeader(updatesStatus)
			if updatesStatus == http.StatusConflict {
				_, _ = w.Write([]byte(`{"ok":false,"error_code":409,"description":"Conflict: terminated by other getUpdates request"}`))
				return
			}
			_, _ = w.Write([]byte(`{"ok":true,"result":[]}`))
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	t.Cleanup(server.Close)
	client, err := New("test-token", 123, server.Client(), server.URL)
	if err != nil {
		t.Fatal(err)
	}
	return client, &methods
}

func TestProbeSoleOwner(t *testing.T) {
	client, methods := soleOwnerServer(t, "", http.StatusOK)
	if err := client.ProbeSoleOwner(t.Context(), 1); err != nil {
		t.Fatal(err)
	}
	if strings.Join(*methods, ",") != "getWebhookInfo,getUpdates" {
		t.Fatalf("methods = %v", *methods)
	}
	webhook, _ := soleOwnerServer(t, "https://bots.example.test/hook", http.StatusOK)
	if err := webhook.ProbeSoleOwner(t.Context(), 1); !errors.Is(err, ErrAnotherOwner) {
		t.Fatalf("webhook probe = %v", err)
	}
	poller, _ := soleOwnerServer(t, "", http.StatusConflict)
	if err := poller.ProbeSoleOwner(t.Context(), 1); !errors.Is(err, ErrAnotherOwner) {
		t.Fatalf("competing poller probe = %v", err)
	}
	broken, _ := soleOwnerServer(t, "", http.StatusOK)
	broken.baseURL = "http://127.0.0.1:1"
	if err := broken.ProbeSoleOwner(t.Context(), 1); err == nil || errors.Is(err, ErrAnotherOwner) {
		t.Fatalf("unreachable probe = %v", err)
	}
}

func TestPollDurableStopsWhenAnotherOwnerPolls(t *testing.T) {
	client, _ := soleOwnerServer(t, "", http.StatusConflict)
	inbox, err := OpenInbox(t.Context(), filepath.Join(t.TempDir(), "callbacks.db"), bytes.Repeat([]byte{5}, 32))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = inbox.Close() }()
	err = client.PollDurable(t.Context(), inbox, func(context.Context, notify.Decision) notify.DecisionResult { return notify.DecisionResult{} })
	if !errors.Is(err, ErrAnotherOwner) {
		t.Fatalf("PollDurable() = %v", err)
	}
}
