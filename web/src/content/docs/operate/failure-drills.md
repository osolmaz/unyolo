---
title: Failure drills
description: The maintained qualification matrix pairing each failure class with its required invariant and automated coverage.
---

BrokerKit keeps deterministic failure drills beside the boundary they exercise. The matrix below is
the maintained qualification set. Provider suites add operation-specific cases without replacing
these shared drills.

Every drill asserts durable terminal state or rollback state rather than an HTTP status. Test
fixtures use bounded timeouts and synthetic local upstreams. Live provider tests complement the
matrix but are never the only evidence for a failure invariant.

## The matrix

| Failure class | Required invariant | Primary automated coverage |
| --- | --- | --- |
| SQLite corruption and incompatible restore | Startup and restore fail closed without replacing current state | `internal/storage/state/maintenance_test.go`, `internal/storage/state/grants_test.go` |
| Read-only or failed durable write | No decision or notification transition is reported as committed | `authorization/grants/grants_test.go`, `authorization/grants/notifications_test.go` |
| Backward or forward wall clock | Leases do not reopen authority and rate windows do not reset backward | `authorization/admission/admission_test.go`, `authorization/grants/notifications_test.go` |
| Telegram outage, retry, duplicate callback, cancellation | Offsets and encrypted authority survive restart, callbacks stay idempotent, polling stops | `approval/notifier/telegram/inbox_test.go`, `approval/notifier/telegram/telegram_test.go`, `authorization/grants/notifications_test.go` |
| Provider timeout or ambiguous completion | No automatic mutation retry; authority retained only for reconciliation | `operation/runtime/runtime_test.go`, provider recovery suites |
| Crash before or during execution | Committed plans recover; unprovable outcomes fail explicitly | `operation/runtime/runtime_test.go`, HF and GH restart suites |
| Listener or service activation failure | No transport fallback; previous managed configuration restored | `transport/endpoint`, `internal/host/service/install_linux_test.go`, `internal/host/service/install_darwin_test.go` |
| Interrupted credential or file replacement | Previous files and service definition restored before reactivation | `internal/host/service/install_linux_test.go`, `internal/host/service/install_darwin_test.go` |
| Submission overload | New work receives stable `429`; replay, cancellation, approval, and readiness stay available | `authorization/admission/admission_test.go`, `operation/runtime/runtime_test.go` |
| Shutdown with a live parent context | Owned workers stop before SQLite closes | GH, HF, and sudo server shutdown tests |
| Stale or deleted BrokerKit executable | Exact contract drift stops Telegram before polling; host doctor fails | `operator/client/client_test.go`, `approval/notifier/telegram/dispatcher_test.go`, `internal/host/bundle/bundle_test.go` |
| Partial multi-service upgrade | Providers start before consumers; any failure restores the previous release and state | `internal/host/bundle/bundle_test.go` |
| Host process exits during activation | The private transaction journal restores the prior release and activation record before another lifecycle command proceeds | `internal/host/bundle/bundle_test.go` |

## Notes on selected classes

Three of the entries deserve a note, because the invariant is less obvious than the failure.

**Ambiguous provider completion.** When a mutation times out, the safe-looking move is to retry. It
is the wrong one, because the first attempt may have succeeded and the retry would duplicate it.
The invariant is that authority is retained for reconciliation and the outcome is reported as
unprovable rather than retried. This is also why the client guidance is to reuse a stable request ID
when retrying and never to retry an ambiguous execution under a new one.

**Wall clock movement.** Grant expiry and rate windows are both time-derived. A backward clock step
must not reopen a lease that has expired and must not reset a rate window backward into allowing
more submissions than the limit.

**Deleted executable.** Replacing a binary on disk while its old process keeps running leaves a
service that reports active while executing code nobody can inspect. Linux marks the executable
path as `(deleted)`, and host doctor treats that as unhealthy. The Telegram ingress separately
compares each route's exact contract digest before every poll batch and exits on a mismatch rather
than consuming an update it cannot correctly route.

## Security verification

Beyond the matrix, required verification includes race tests, cursor and callback fuzzing, protocol
schema drift tests, provider activation and execution tests, restart tests, secret scanning,
dependency vulnerability scanning, and the adversarial fixtures in the Operator V1 conformance
suite.

Mutation testing stays checked in but is opt-in and non-blocking.

## CI coverage

The Go job runs `go mod tidy` with a clean-diff check, `go mod verify`, a `gofmt` check, the
architecture, generated-code, and SQL checks, the protocol test, `go vet`, the race-enabled test
suite, a coverage gate, `golangci-lint`, `govulncheck`, `gitleaks` with redaction, and the
Slophammer complexity and duplication gates. A separate macOS job runs the race-enabled suite on
Darwin.

CI never sends real Telegram messages and never mutates real external repositories. Telegram is
covered by a fake Bot API server or a fake notifier, and live provider tests are explicit manual or
staging checks.

## The shared test contract

Every broker is expected to test install script platform selection and checksum handling,
`setup systemd --dry-run`, `setup systemd --no-start` file rendering in temporary directories,
service unit content without starting real services, authentication accepting valid clients and
rejecting invalid ones, policy rejecting unknown operations, targets, attrs, and fields, deny
overriding active grants, generated grants matching only the approved client, operation, target,
attrs, duration, and use budget, and audit output containing no secrets.
