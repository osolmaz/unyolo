package observability

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/osolmaz/brokerkit/state"
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
	for _, want := range []string{"brokerkit_admission_requests_total", `broker="test-broker"`, `code="other"`,
		"brokerkit_operation_execution_seconds", "brokerkit_operator_decisions_total", "brokerkit_notification_deliveries_total"} {
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
		"brokerkit_database_healthy", `brokerkit_database_healthy{broker="test-broker"} 1`,
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
	if !strings.Contains(body, `brokerkit_database_healthy{broker="test-broker"} 0`) {
		t.Fatalf("failed database health metric omitted:\n%s", body)
	}
	if strings.Contains(body, "brokerkit_queue_depth") || strings.Contains(body, "secret database failure") {
		t.Fatalf("failed scrape exposed stale state or raw error:\n%s", body)
	}
}

func TestMetricsRequireBrokerName(t *testing.T) {
	if _, err := New(" ", nil); err == nil {
		t.Fatal("empty metrics broker accepted")
	}
}
