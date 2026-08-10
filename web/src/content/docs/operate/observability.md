---
title: Metrics and logs
description: Monitor broker activity, dependencies, logs, and health checks.
---

Each broker has its own Prometheus registry. Metrics report activity and dependency health. Security
decisions belong in the [audit log](/docs/concepts/audit-logging), not in metrics.

## Metrics endpoint

`GET /metrics` is served only on the configured operator listener and requires the same operator
bearer credential as Operator V1. The agent listener never serves metrics, and a broker without an
operator listener has no metrics HTTP surface at all.

Putting metrics behind the operator credential is deliberate. Queue depths and rejection counts
describe what other clients are doing, which is information one agent should not be able to read
about another.

## Registry contents

The registry follows work through the broker. On the way in it counts Agent V1 submissions that
were admitted and rejected, with stable rejection codes, alongside the created, replayed, rejected,
and failed counts. Provider executions are then counted as successful, failed, reconciled, or
ambiguous, with latency recorded for both execution and reconciliation.

Approval activity is reported as committed, replayed, and rejected approve and deny decisions,
paired with notification counters for delivered, failed, claimed, and already-recorded deliveries
and their durable retry attempts.

The remaining series describe capacity and health. Active operation workers are reported against
configured worker capacity. Durable queue depths cover pending approvals, queued operations,
executing operations, pending notifications, and unresolved notifications. Provider and
notification dependencies report last-observed health and their outcomes by closed error category,
and a bounded durable-database probe runs at scrape time.

When the database probe fails, `unyolo_database_healthy` reports `0` and the queue gauges are
omitted. unYOLO does not report unknown durable state as zero and does not retain stale queue
values between scrapes, because a zero that means "I cannot tell" is worse than a missing series.

## Label cardinality

Each registry has one setup-controlled `broker` label. Every other label comes from a closed
unYOLO enum.

Client names, repository names, target users, reasons, paths, commands, URLs, tokens, and upstream
error strings are never metric labels. Unknown values collapse to `other`.

Two problems are solved by the same rule. Unbounded labels are the standard way to make Prometheus
fall over, and a repository name in a label is a secret-adjacent value that ends up in every
scrape, every remote write, and every dashboard.

## Structured diagnostics

The shared boundary writes JSON diagnostics to stderr for operation start and completion,
approval-notification delivery, and durable dependency retries.

Each record contains a stable event name, the broker or provider, an opaque bounded correlation ID,
the catalog risk class, a closed result, a closed error category, and a bounded duration. They
never contain the operation name, target, reason, repository, user, path, command, URL, token, or
raw error.

Broker-owned failure codes reduce to a closed set before either logs or labels see them:

```text
authentication  authorization  canceled   conflict
invalid_response  rate_limited  rejected   storage
timeout           unavailable   other
```

The correlation ID is how you tie a diagnostic record to an audit record when you need the detail
the diagnostic deliberately omits.

## Dependency health

Provider and notification dependency health is last-observed state rather than a probe performed
during a scrape. A failure marks that dependency degraded, and a later proven success restores it.
Database health remains the bounded scrape-time probe.

The reason for the distinction is that an unavailable external service should be visible without
changing liveness and without claiming that local readiness is broken. A rate-limited GitHub does
not mean the broker's durable state is unhealthy.

## Health probes

Liveness is an unauthenticated, secret-free process probe on the agent surface. Readiness verifies
required durable and local privilege dependencies. Operator health and readiness are authenticated.

A store corruption or an unsupported state shape makes readiness fail, and the listener must not
receive traffic in that condition.

## Git observability

Native Git discovery, upload-pack, receive-pack, and LFS requests emit the provider's normal policy
and proxy audit records. The dedicated Git listener's identity response contains only the provider
ID. Credential-helper input and output are never logged, and neither are Basic credentials.

## Host bundle diagnostics

`unyolo system status --json` and `unyolo system doctor --json` provide the host-level view:
bundle IDs, release build IDs, artifact digest results, native service names, PIDs, executable
paths, active state, and recovery-required state. Neither contains credentials, Telegram
destinations, decision authority, reasons, or provider payloads.

Exact Agent and Operator digests are exposed by discovery and health responses, so a client can
report contract drift without logging response bodies.

## Telegram callback observability

Callback authority is observable only as aggregate queue lifecycle. The durable inbox stores
redacted terminal answers after deleting the encrypted authority.

Operational logs may report callback receipt, retry, terminal state, route, update ID, and a
bounded attempt count. They must not report callback data, decision tokens, rendered messages,
usernames, or chat IDs.

## Alerting

Three signals are worth wiring up first. A `unyolo_database_healthy` of `0` means the broker
cannot serve, and readiness will already be failing. A steadily rising pending-approval depth
usually means an agent is requesting things nobody intends to approve, which is a policy problem
rather than a capacity one. A rising rejected-submission count with a stable rejection code points
at either a looping client or an admission limit that no longer matches the workload.
