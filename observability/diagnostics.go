package observability

import (
	"context"
	"io"
	"log/slog"
	"os"
	"strings"
	"time"
)

// Diagnostics emits secret-safe structured runtime events and updates the
// matching bounded dependency and capacity metrics.
type Diagnostics struct {
	broker  string
	metrics *Metrics
	logger  *slog.Logger
}

// NewDiagnostics creates the shared runtime diagnostic boundary. A nil writer
// uses stderr; callers may pass io.Discard when diagnostics are intentionally disabled.
func NewDiagnostics(broker string, metrics *Metrics, writer io.Writer) *Diagnostics {
	if writer == nil {
		writer = os.Stderr
	}
	logger := slog.New(slog.NewJSONHandler(writer, &slog.HandlerOptions{Level: slog.LevelInfo}))
	return &Diagnostics{broker: strings.TrimSpace(broker), metrics: metrics, logger: logger}
}

// WorkerConfigured records the fixed execution capacity before work begins.
func (d *Diagnostics) WorkerConfigured(limit int) {
	if d == nil {
		return
	}
	d.metrics.workerLimit.Set(float64(max(0, limit)))
}

// OperationStarted records worker use without logging the operation or target.
func (d *Diagnostics) OperationStarted(correlationID, operationClass string, limit int) {
	if d == nil {
		return
	}
	d.metrics.operationStarted(limit)
	d.logger.InfoContext(context.Background(), "broker.operation.started", d.attributes(correlationID, operationClass)...)
}

// OperationFinished records one terminal execution or reconciliation outcome.
func (d *Diagnostics) OperationFinished(correlationID, operationClass, result, errorCode string, elapsed time.Duration) {
	if d == nil {
		return
	}
	category := ErrorCategory(errorCode)
	d.metrics.operationFinished(result, category)
	attributes := append(d.attributes(correlationID, operationClass),
		slog.String("result", closedValue(result, dependencyResults)), slog.String("error_category", category),
		slog.Int64("duration_ms", max(0, elapsed.Milliseconds())))
	d.logger.InfoContext(context.Background(), "broker.operation.finished", attributes...)
}

// NotificationAttempt records one approval-channel delivery outcome.
func (d *Diagnostics) NotificationAttempt(correlationID, result, errorCode string) {
	if d == nil {
		return
	}
	category := ErrorCategory(errorCode)
	d.metrics.notificationAttempt(result, category)
	d.logger.InfoContext(context.Background(), "broker.notification.delivery",
		slog.String("provider", d.broker), slog.String("correlation_id", boundedCorrelationID(correlationID)),
		slog.String("result", closedValue(result, dependencyResults)), slog.String("error_category", category))
}

// Retry records one durable dependency retry.
func (d *Diagnostics) Retry(correlationID, dependency string) {
	if d == nil {
		return
	}
	dependency = closedValue(dependency, dependencyNames)
	d.metrics.dependencyRetry(dependency)
	d.logger.InfoContext(context.Background(), "broker.dependency.retry",
		slog.String("provider", d.broker), slog.String("correlation_id", boundedCorrelationID(correlationID)),
		slog.String("dependency", dependency))
}

func (d *Diagnostics) attributes(correlationID, operationClass string) []any {
	return []any{slog.String("provider", d.broker), slog.String("correlation_id", boundedCorrelationID(correlationID)),
		slog.String("operation_class", closedValue(operationClass, operationClasses))}
}

// ErrorCategory maps only stable broker-owned codes to a closed diagnostic class.
func ErrorCategory(code string) string {
	code = strings.ToLower(strings.TrimSpace(code))
	if code == "" {
		return "none"
	}
	for _, rule := range errorCategoryRules {
		for _, marker := range rule.markers {
			if code == marker || strings.Contains(code, marker) {
				return rule.category
			}
		}
	}
	return "other"
}

var errorCategoryRules = []struct {
	category string
	markers  []string
}{
	{"rate_limited", []string{"rate_limit"}},
	{"authentication", []string{"authentication", "unauthorized"}},
	{"authorization", []string{"authorization", "forbidden"}},
	{"canceled", []string{"cancel"}},
	{"conflict", []string{"conflict"}},
	{"invalid_response", []string{"response_invalid"}},
	{"storage", []string{"store", "claim"}},
	{"timeout", []string{"timeout"}},
	{"unavailable", []string{"unavailable", "unknown", "reconciliation"}},
	{"rejected", []string{"reject", "invalid", "not_found"}},
}

var operationClasses = map[string]struct{}{"low": {}, "medium": {}, "high": {}, "critical": {}}

func boundedCorrelationID(value string) string {
	value = strings.ToValidUTF8(strings.TrimSpace(value), "")
	if len(value) > 128 {
		value = value[:128]
	}
	return value
}
