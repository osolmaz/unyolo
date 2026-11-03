package telegram

import (
	"bytes"
	"context"
	"errors"
	"io"
	"log/slog"
	"strings"
	"testing"
	"time"
)

func TestRetryLogLimitsRepeatedFailuresAndReportsRecovery(t *testing.T) {
	var output bytes.Buffer
	failures := newRetryLog(slog.New(slog.NewTextHandler(&output, nil)), "approval polling")
	now := time.Date(2026, 11, 3, 12, 0, 0, 0, time.UTC)
	failures.now = func() time.Time { return now }
	failures.failed(errors.New("connection reset"))
	now = now.Add(5 * time.Second)
	failures.failed(errors.New("connection reset"))
	now = now.Add(time.Minute)
	failures.failed(errors.New("request timed out"))
	failures.recovered()
	failures.recovered()
	lines := strings.Split(strings.TrimSpace(output.String()), "\n")
	if len(lines) != 3 {
		t.Fatalf("log lines = %q, want first failure, failure after a minute, and recovery", lines)
	}
	if !strings.Contains(lines[0], "connection reset") || !strings.Contains(lines[0], "failures=1") {
		t.Fatalf("first line = %q", lines[0])
	}
	if !strings.Contains(lines[1], "request timed out") || !strings.Contains(lines[1], "failures=3") {
		t.Fatalf("second line = %q", lines[1])
	}
	if !strings.Contains(lines[2], "telegram approval polling recovered") || !strings.Contains(lines[2], "failures=3") {
		t.Fatalf("recovery line = %q", lines[2])
	}
}

func TestOwnerLogsAFailedRouteButNotAnEndedStream(t *testing.T) {
	for name, test := range map[string]struct {
		watchErr error
		want     string
	}{
		"failed connection": {watchErr: errors.New("broker unavailable"), want: "telegram GitHub approval cards failed; retrying"},
		"ended stream":      {},
	} {
		t.Run(name, func(t *testing.T) {
			source := newFakeCardSource()
			source.watchErr = test.watchErr
			owner, _ := newTestOwner(t, openTestInbox(t), map[string]CardSource{RouteGitHub: source})
			var output bytes.Buffer
			owner.logger = slog.New(slog.NewTextHandler(&output, nil))
			ctx, cancel := context.WithTimeout(t.Context(), 50*time.Millisecond)
			defer cancel()
			owner.runRoute(ctx, RouteGitHub, source)
			lines := strings.Split(strings.TrimSpace(output.String()), "\n")
			switch {
			case test.want == "" && output.Len() != 0:
				t.Fatalf("log = %q, want no lines for a stream that ended", output.String())
			case test.want != "" && (len(lines) != 1 || !strings.Contains(lines[0], test.want) || !strings.Contains(lines[0], "broker unavailable")):
				t.Fatalf("log = %q, want one failure line", output.String())
			}
			if source.watchedAt == nil {
				t.Fatal("the owner never connected")
			}
		})
	}
}

func discardRetryLog() *retryLog {
	return newRetryLog(slog.New(slog.NewTextHandler(io.Discard, nil)), "test")
}
