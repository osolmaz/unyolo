package observability

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestMetricsExposeOnlyClosedBoundedLabels(t *testing.T) {
	metrics, err := New("test-broker")
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

func TestMetricsRequireBrokerName(t *testing.T) {
	if _, err := New(" "); err == nil {
		t.Fatal("empty metrics broker accepted")
	}
}
