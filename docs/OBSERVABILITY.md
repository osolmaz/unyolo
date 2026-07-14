# Operational Observability

Every broker owns an isolated Prometheus registry created by BrokerKit's
`observability` package. Metrics are exposed at `GET /metrics` only on the
configured operator listener and require the same operator bearer credential as
Operator V1. The agent listener never serves metrics. A broker without an
operator listener has no metrics HTTP surface.

The current registry reports:

- admitted and rejected Agent V1 submissions, with stable rejection codes;
- created, replayed, rejected, and failed submissions;
- successful, failed, reconciled, and ambiguous provider executions;
- provider execution and reconciliation latency;
- committed, replayed, and rejected approve/deny decisions; and
- delivered, failed, claimed, and already-recorded approval notifications;
- durable pending-approval, queued-operation, executing-operation,
  pending-notification, and unresolved-notification depths; and
- a bounded durable-database health probe at scrape time.

When the database probe fails, `brokerkit_database_healthy` is `0` and queue
gauges are omitted. BrokerKit does not report unknown durable state as zero or
retain stale queue values between scrapes.

Each registry has one setup-controlled `broker` label. Other labels come from
closed BrokerKit enums. Client names, repository names, target users, reasons,
paths, commands, URLs, tokens, and upstream error strings are never metric
labels. Unknown values collapse to `other`, which keeps cardinality bounded and
prevents secrets from reaching the exposition output.

Liveness remains an unauthenticated, secret-free process probe on the agent
surface. Readiness verifies required durable and local privilege dependencies.
Operator health and readiness remain authenticated. Audit records security
evidence; metrics report aggregate operation, capacity, and dependency behavior
and are not an audit substitute.
