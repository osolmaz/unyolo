package observability

import (
	"bytes"
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/osolmaz/unyolo/internal/storage/state"
)

func TestMetricsExposeOnlyClosedBoundedLabels(t *testing.T) {
	metrics, err := New("test-broker", nil)
	if err != nil {
		t.Fatal(err)
	}
	metrics.AdmissionAccepted()
	metrics.AdmissionRejected("caller-controlled-secret")
	metrics.OperationSubmitted("created")
	metrics.OperationExecuted("succeeded", 250*time.Millisecond)
	metrics.OperatorDecision("approve", "committed")
	metrics.NotificationDelivered("delivered")
	response := httptest.NewRecorder()
	metrics.Handler().ServeHTTP(response, httptest.NewRequest(http.MethodGet, "/metrics", nil))
	body := response.Body.String()
	for _, want := range []string{"unyolo_admission_requests_total", `broker="test-broker"`, `code="other"`,
		"unyolo_operation_execution_seconds", "unyolo_operator_decisions_total", "unyolo_notification_deliveries_total"} {
		if !strings.Contains(body, want) {
			t.Fatalf("metrics omitted %q:\n%s", want, body)
		}
	}
	if strings.Contains(body, "caller-controlled-secret") {
		t.Fatal("metrics exposed an unbounded caller-controlled label")
	}
}

type fakeStateSource struct {
	stats state.OperationalStats
	err   error
}

func (s fakeStateSource) OperationalStats(context.Context) (state.OperationalStats, error) {
	return s.stats, s.err
}

func TestMetricsCollectDurableStateWithoutUnboundedLabels(t *testing.T) {
	metrics, err := New("test-broker", fakeStateSource{stats: state.OperationalStats{
		PendingApprovals: 2, QueuedOperations: 3, ExecutingOperations: 4,
		PendingNotifications: 5, UnresolvedNotifications: 6,
	}})
	if err != nil {
		t.Fatal(err)
	}
	response := httptest.NewRecorder()
	metrics.Handler().ServeHTTP(response, httptest.NewRequest(http.MethodGet, "/metrics", nil))
	body := response.Body.String()
	for _, want := range []string{
		"unyolo_database_healthy", `unyolo_database_healthy{broker="test-broker"} 1`,
		`queue="approvals_pending"} 2`, `queue="operations_queued"} 3`,
		`queue="operations_executing"} 4`, `queue="notifications_pending"} 5`,
		`queue="notifications_unresolved"} 6`,
	} {
		if !strings.Contains(body, want) {
			t.Fatalf("metrics omitted %q:\n%s", want, body)
		}
	}
}

func TestMetricsSuppressQueueDepthWhenDatabaseProbeFails(t *testing.T) {
	metrics, err := New("test-broker", fakeStateSource{err: errors.New("secret database failure")})
	if err != nil {
		t.Fatal(err)
	}
	response := httptest.NewRecorder()
	metrics.Handler().ServeHTTP(response, httptest.NewRequest(http.MethodGet, "/metrics", nil))
	body := response.Body.String()
	if !strings.Contains(body, `unyolo_database_healthy{broker="test-broker"} 0`) {
		t.Fatalf("failed database health metric omitted:\n%s", body)
	}
	if strings.Contains(body, "unyolo_queue_depth") || strings.Contains(body, "secret database failure") {
		t.Fatalf("failed scrape exposed stale state or raw error:\n%s", body)
	}
}

func TestMetricsRequireBrokerName(t *testing.T) {
	if _, err := New(" ", nil); err == nil {
		t.Fatal("empty metrics broker accepted")
	}
}

func TestDiagnosticsShareBoundedMetricsAndStructuredRedaction(t *testing.T) {
	metrics, err := New("test-broker", nil)
	if err != nil {
		t.Fatal(err)
	}
	var logs bytes.Buffer
	diagnostics := NewDiagnostics("test-broker", metrics, &logs)
	diagnostics.WorkerConfigured(8)
	diagnostics.OperationStarted(strings.Repeat("x", 160), "critical", 8)
	diagnostics.OperationFinished(strings.Repeat("x", 160), "critical", "failed", "operation_upstream_rate_limited-secret", time.Second)
	diagnostics.NotificationAttempt("grant-1", "failed", "notification_unavailable-secret")
	diagnostics.Retry("grant-1", "notification")

	response := httptest.NewRecorder()
	metrics.Handler().ServeHTTP(response, httptest.NewRequest(http.MethodGet, "/metrics", nil))
	body := response.Body.String()
	for _, want := range []string{
		"unyolo_dependency_healthy", `dependency="provider"} 0`, `dependency="notification"} 0`,
		"unyolo_dependency_requests_total", `error_category="rate_limited"`, `error_category="unavailable"`,
		"unyolo_dependency_retries_total", "unyolo_worker_active", "unyolo_worker_limit",
	} {
		if !strings.Contains(body, want) {
			t.Fatalf("diagnostic metrics omitted %q:\n%s", want, body)
		}
	}
	if strings.Contains(body, "secret") || strings.Contains(logs.String(), "secret") || strings.Contains(logs.String(), strings.Repeat("x", 129)) {
		t.Fatalf("diagnostics exposed unbounded input: metrics=%s logs=%s", body, logs.String())
	}
	for _, want := range []string{`"msg":"broker.operation.started"`, `"msg":"broker.operation.finished"`, `"provider":"test-broker"`, `"operation_class":"critical"`, `"error_category":"rate_limited"`} {
		if !strings.Contains(logs.String(), want) {
			t.Fatalf("structured diagnostics omitted %q: %s", want, logs.String())
		}
	}
}

func TestErrorCategoryUsesOnlyClosedStableClasses(t *testing.T) {
	tests := map[string]string{
		"": "none", "rate_limited": "rate_limited", "unauthorized": "authentication", "forbidden": "authorization",
		"operation_canceled": "canceled", "upstream_conflict": "conflict", "response_invalid": "invalid_response",
		"operation_store_unavailable": "storage", "operation_timeout": "timeout", "upstream_result_unknown": "unavailable",
		"execution_rejected": "rejected", "caller-controlled-token": "other",
	}
	for input, want := range tests {
		if got := ErrorCategory(input); got != want {
			t.Errorf("ErrorCategory(%q) = %q, want %q", input, got, want)
		}
	}
	var diagnostics *Diagnostics
	diagnostics.OperationStarted("ignored", "low", 1)
	diagnostics.OperationFinished("ignored", "low", "failed", "unknown", 0)
	diagnostics.NotificationAttempt("ignored", "failed", "unknown")
	diagnostics.Retry("ignored", "provider")
}
