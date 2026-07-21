# Operational Observability

Every broker owns an isolated Prometheus registry created by BrokerKit's
`telemetry/metrics` package. Metrics are exposed at `GET /metrics` only on the
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
- last-observed provider and notification dependency health;
- provider and notification dependency outcomes by closed error category;
- durable notification retry attempts;
- active operation workers and configured worker capacity;
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

The same shared boundary writes JSON diagnostics to stderr for operation start
and completion, approval-notification delivery, and durable dependency retries.
Records contain only a stable event name, broker/provider, opaque bounded
correlation ID, catalog risk class, closed result, closed error category, and
bounded duration. They never contain the operation name, target, reason,
repository, user, path, command, URL, token, or raw error. Stable broker-owned
failure codes are reduced to `authentication`, `authorization`, `canceled`,
`conflict`, `invalid_response`, `rate_limited`, `rejected`, `storage`,
`timeout`, `unavailable`, or `other` before either logs or labels see them.

Dependency health is last-observed state, not a network probe performed during
a metrics scrape. A provider or notification failure marks that dependency
degraded; a later proven success restores it. Database health remains the
bounded scrape-time probe. Dependency outages are visible without changing
liveness or claiming that an unavailable external service corrupts local
readiness.

Liveness remains an unauthenticated, secret-free process probe on the agent
surface. Readiness verifies required durable and local privilege dependencies.
Operator health and readiness remain authenticated. Audit records security
evidence; metrics report aggregate operation, capacity, and dependency behavior
and are not an audit substitute.

Native Git discovery, upload-pack, receive-pack, and LFS requests continue to
emit the provider's existing policy and proxy audit records. The dedicated Git
listener identity response contains only the provider id. Credential-helper
input, output, and Basic credentials are never logged.

## Host bundle diagnostics

`brokerkit system status --json` and `brokerkit system doctor --json` provide a
closed host-level report. It contains bundle IDs, release build IDs, artifact
digest results, native service names, PIDs, executable paths, active state, and
recovery-required state. It never contains credentials, Telegram destinations,
decision authority, reasons, or provider payloads.

The host is unhealthy when an artifact digest changes, a required service is
inactive, a process executable differs from the immutable active release, a
Linux executable is marked deleted, or rollback did not complete. Exact Agent
and Operator digests are exposed by discovery and health responses so clients
can report contract drift without logging response bodies.

Telegram callback authority is observable only as aggregate queue lifecycle.
The durable inbox stores redacted terminal answers after deleting encrypted
authority. Operational logs may report callback receipt, retry, terminal state,
route, update ID, and bounded attempt count. They must not report callback data,
decision tokens, rendered messages, usernames, or chat IDs.
