# Failure Drills

BrokerKit keeps deterministic failure drills beside the boundary they exercise.
The tests below are the maintained qualification matrix; provider suites add
operation-specific cases without replacing these shared drills.

| Failure class | Required invariant | Primary automated coverage |
| --- | --- | --- |
| SQLite corruption and incompatible restore | startup and restore fail closed without replacing current state | `internal/storage/state/maintenance_test.go`, `internal/storage/state/grants_test.go` |
| Read-only or failed durable write | no decision or notification transition is reported as committed | `authorization/grants/grants_test.go`, `authorization/grants/notifications_test.go` |
| Backward or forward wall clock | leases do not reopen authority and rate windows do not reset backward | `authorization/admission/admission_test.go`, `authorization/grants/notifications_test.go` |
| Telegram outage, retry, duplicate callback, and cancellation | offsets and encrypted authority survive restart, callbacks remain idempotent, and polling stops | `approval/notifier/telegram/inbox_test.go`, `approval/notifier/telegram/telegram_test.go`, `authorization/grants/notifications_test.go` |
| Provider timeout or ambiguous completion | no automatic mutation retry; authority is retained only for reconciliation | `operation/runtime/runtime_test.go`, provider recovery suites |
| Crash before or during execution | committed plans recover; unprovable outcomes fail explicitly | `operation/runtime/runtime_test.go`, HF and GH restart suites |
| Listener or service activation failure | no transport fallback; previous managed configuration is restored | `transport/endpoint`, `internal/host/service/install_linux_test.go`, `internal/host/service/install_darwin_test.go` |
| Interrupted credential or file replacement | previous files and service definition are restored before reactivation | `internal/host/service/install_linux_test.go`, `internal/host/service/install_darwin_test.go` |
| Submission overload | new work receives stable `429`; replay, cancellation, approval, and readiness remain available | `authorization/admission/admission_test.go`, `operation/runtime/runtime_test.go` |
| Shutdown with a live parent context | owned workers stop before SQLite closes | GH, HF, and sudo server shutdown tests |
| Stale or deleted BrokerKit executable | exact contract drift stops Telegram before polling and host doctor fails | `operator/client/client_test.go`, `approval/notifier/telegram/dispatcher_test.go`, `internal/host/bundle/bundle_test.go` |
| Partial multi-service upgrade | providers start before consumers and any failure restores the previous release and state | `internal/host/bundle/bundle_test.go` |
| Host process exits during activation | the private transaction journal restores the prior release and activation record before another lifecycle command proceeds | `internal/host/bundle/bundle_test.go` |

Every drill asserts durable terminal state or rollback state, not just an HTTP
status. Test fixtures use bounded timeouts and synthetic local upstreams. Live
provider tests complement this matrix but are not the only evidence for a
failure invariant.
