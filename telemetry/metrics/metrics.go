// Package observability owns BrokerKit's bounded operational metrics.
package observability

import (
	"context"
	"errors"
	"net/http"
	"strings"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"

	"github.com/osolmaz/brokerkit/internal/storage/state"
)

const stateCollectionTimeout = 2 * time.Second

// StateSource provides secret-free durable state counts at scrape time.
type StateSource interface {
	OperationalStats(context.Context) (state.OperationalStats, error)
}

// Metrics is one broker-local Prometheus registry. Labels are selected only
// from closed sets and never contain targets, reasons, paths, URLs, or clients.
type Metrics struct {
	registry      *prometheus.Registry
	admissions    *prometheus.CounterVec
	submissions   *prometheus.CounterVec
	executions    *prometheus.CounterVec
	executionTime *prometheus.HistogramVec
	decisions     *prometheus.CounterVec
	notifications *prometheus.CounterVec
	dependencies  *prometheus.GaugeVec
	upstream      *prometheus.CounterVec
	retries       *prometheus.CounterVec
	workerActive  prometheus.Gauge
	workerLimit   prometheus.Gauge
}

// New creates an isolated registry with one controlled broker label.
func New(broker string, source StateSource) (*Metrics, error) {
	broker = strings.TrimSpace(broker)
	if broker == "" {
		return nil, errors.New("metrics broker name is required")
	}
	labels := prometheus.Labels{"broker": broker}
	metrics := &Metrics{
		registry: prometheus.NewRegistry(),
		admissions: prometheus.NewCounterVec(prometheus.CounterOpts{Name: "brokerkit_admission_requests_total",
			Help: "Agent operation admission outcomes.", ConstLabels: labels}, []string{"result", "code"}),
		submissions: prometheus.NewCounterVec(prometheus.CounterOpts{Name: "brokerkit_operation_submissions_total",
			Help: "Agent operation submission outcomes.", ConstLabels: labels}, []string{"result"}),
		executions: prometheus.NewCounterVec(prometheus.CounterOpts{Name: "brokerkit_operation_executions_total",
			Help: "Provider operation execution outcomes.", ConstLabels: labels}, []string{"result"}),
		executionTime: prometheus.NewHistogramVec(prometheus.HistogramOpts{Name: "brokerkit_operation_execution_seconds",
			Help: "Provider execution and reconciliation latency.", ConstLabels: labels,
			Buckets: []float64{0.05, 0.1, 0.25, 0.5, 1, 2.5, 5, 10, 30, 60, 120}}, []string{"result"}),
		decisions: prometheus.NewCounterVec(prometheus.CounterOpts{Name: "brokerkit_operator_decisions_total",
			Help: "Operator decision outcomes.", ConstLabels: labels}, []string{"action", "result"}),
		notifications: prometheus.NewCounterVec(prometheus.CounterOpts{Name: "brokerkit_notification_deliveries_total",
			Help: "Approval notification delivery outcomes.", ConstLabels: labels}, []string{"result"}),
		dependencies: prometheus.NewGaugeVec(prometheus.GaugeOpts{Name: "brokerkit_dependency_healthy",
			Help: "Last observed health of a bounded runtime dependency.", ConstLabels: labels}, []string{"dependency"}),
		upstream: prometheus.NewCounterVec(prometheus.CounterOpts{Name: "brokerkit_dependency_requests_total",
			Help: "Provider and notification dependency outcomes.", ConstLabels: labels}, []string{"dependency", "result", "error_category"}),
		retries: prometheus.NewCounterVec(prometheus.CounterOpts{Name: "brokerkit_dependency_retries_total",
			Help: "Durable retry attempts by bounded dependency.", ConstLabels: labels}, []string{"dependency"}),
		workerActive: prometheus.NewGauge(prometheus.GaugeOpts{Name: "brokerkit_worker_active",
			Help: "Current provider operation workers in use.", ConstLabels: labels}),
		workerLimit: prometheus.NewGauge(prometheus.GaugeOpts{Name: "brokerkit_worker_limit",
			Help: "Configured provider operation worker capacity.", ConstLabels: labels}),
	}
	metrics.registry.MustRegister(metrics.admissions, metrics.submissions, metrics.executions,
		metrics.executionTime, metrics.decisions, metrics.notifications, metrics.dependencies,
		metrics.upstream, metrics.retries, metrics.workerActive, metrics.workerLimit)
	if source != nil {
		metrics.registry.MustRegister(newStateCollector(labels, source))
	}
	return metrics, nil
}

// Handler exposes this registry in Prometheus format.
func (m *Metrics) Handler() http.Handler {
	return promhttp.HandlerFor(m.registry, promhttp.HandlerOpts{ErrorHandling: promhttp.HTTPErrorOnError})
}

// AdmissionAccepted records accepted submission capacity.
func (m *Metrics) AdmissionAccepted() { m.admissions.WithLabelValues("accepted", "none").Inc() }

// AdmissionRejected records a refusal using a closed code set.
func (m *Metrics) AdmissionRejected(code string) {
	m.admissions.WithLabelValues("rejected", admissionCode(code)).Inc()
}

// OperationSubmitted records a durable submission outcome.
func (m *Metrics) OperationSubmitted(result string) {
	m.submissions.WithLabelValues(closedValue(result, submissionResults)).Inc()
}

// OperationExecuted records one provider execution attempt and reconciliation.
func (m *Metrics) OperationExecuted(result string, elapsed time.Duration) {
	result = closedValue(result, executionResults)
	m.executions.WithLabelValues(result).Inc()
	m.executionTime.WithLabelValues(result).Observe(max(0, elapsed.Seconds()))
}

// OperatorDecision records one revision- or token-bound decision.
func (m *Metrics) OperatorDecision(action, result string) {
	m.decisions.WithLabelValues(closedValue(action, decisionActions), closedValue(result, decisionResults)).Inc()
}

// NotificationDelivered records one approval delivery attempt.
func (m *Metrics) NotificationDelivered(result string) {
	m.notifications.WithLabelValues(closedValue(result, notificationResults)).Inc()
}

func (m *Metrics) operationStarted(limit int) {
	m.workerActive.Inc()
	m.workerLimit.Set(float64(max(0, limit)))
}

func (m *Metrics) operationFinished(result, category string) {
	m.workerActive.Dec()
	m.recordDependency("provider", result, category)
}

func (m *Metrics) notificationAttempt(result, category string) {
	m.recordDependency("notification", result, category)
}

func (m *Metrics) dependencyRetry(dependency string) {
	m.retries.WithLabelValues(closedValue(dependency, dependencyNames)).Inc()
}

func (m *Metrics) recordDependency(dependency, result, category string) {
	dependency = closedValue(dependency, dependencyNames)
	result = closedValue(result, dependencyResults)
	category = closedValue(category, errorCategories)
	m.upstream.WithLabelValues(dependency, result, category).Inc()
	switch result {
	case "succeeded", "reconciled", "delivered":
		m.dependencies.WithLabelValues(dependency).Set(1)
	case "failed", "ambiguous":
		m.dependencies.WithLabelValues(dependency).Set(0)
	}
}

var admissionCodes = map[string]struct{}{
	"submission_rate_limited": {}, "client_operation_limit": {}, "client_pending_limit": {},
	"global_operation_limit": {}, "global_execution_limit": {}, "store_unavailable": {}, "client_unconfigured": {},
}

var submissionResults = map[string]struct{}{"created": {}, "replayed": {}, "rejected": {}, "failed": {}}
var executionResults = map[string]struct{}{"succeeded": {}, "failed": {}, "reconciled": {}, "ambiguous": {}}
var decisionActions = map[string]struct{}{"approve": {}, "deny": {}}
var decisionResults = map[string]struct{}{"committed": {}, "replayed": {}, "rejected": {}}
var notificationResults = map[string]struct{}{"delivered": {}, "failed": {}, "claimed": {}, "already_recorded": {}}
var dependencyNames = map[string]struct{}{"provider": {}, "notification": {}, "privileged_helper": {}}
var dependencyResults = map[string]struct{}{
	"succeeded": {}, "failed": {}, "ambiguous": {}, "reconciled": {}, "delivered": {}, "claimed": {}, "already_recorded": {},
}
var errorCategories = map[string]struct{}{
	"none": {}, "authentication": {}, "authorization": {}, "canceled": {}, "conflict": {}, "invalid_response": {},
	"rate_limited": {}, "rejected": {}, "storage": {}, "timeout": {}, "unavailable": {}, "other": {},
}

func admissionCode(value string) string { return closedValue(value, admissionCodes) }

func closedValue(value string, allowed map[string]struct{}) string {
	if _, ok := allowed[value]; ok {
		return value
	}
	return "other"
}

type stateCollector struct {
	source  StateSource
	healthy *prometheus.Desc
	depth   *prometheus.Desc
}

func newStateCollector(labels prometheus.Labels, source StateSource) *stateCollector {
	return &stateCollector{
		source:  source,
		healthy: prometheus.NewDesc("brokerkit_database_healthy", "Whether the durable state database answered the bounded scrape probe.", nil, labels),
		depth:   prometheus.NewDesc("brokerkit_queue_depth", "Durable work depth by fixed queue class.", []string{"queue"}, labels),
	}
}

func (c *stateCollector) Describe(output chan<- *prometheus.Desc) {
	output <- c.healthy
	output <- c.depth
}

func (c *stateCollector) Collect(output chan<- prometheus.Metric) {
	ctx, cancel := context.WithTimeout(context.Background(), stateCollectionTimeout)
	defer cancel()
	stats, err := c.source.OperationalStats(ctx)
	if err != nil {
		output <- prometheus.MustNewConstMetric(c.healthy, prometheus.GaugeValue, 0)
		return
	}
	output <- prometheus.MustNewConstMetric(c.healthy, prometheus.GaugeValue, 1)
	for queue, value := range map[string]int64{
		"approvals_pending":        stats.PendingApprovals,
		"operations_queued":        stats.QueuedOperations,
		"operations_executing":     stats.ExecutingOperations,
		"notifications_pending":    stats.PendingNotifications,
		"notifications_unresolved": stats.UnresolvedNotifications,
	} {
		output <- prometheus.MustNewConstMetric(c.depth, prometheus.GaugeValue, float64(value), queue)
	}
}
