# Failure Drills

BrokerKit keeps deterministic failure drills beside the boundary they exercise.
The tests below are the maintained qualification matrix; provider suites add
operation-specific cases without replacing these shared drills.

| Failure class | Required invariant | Primary automated coverage |
| --- | --- | --- |
| SQLite corruption and incompatible restore | startup and restore fail closed without replacing current state | `state/maintenance_test.go`, `state/grants_test.go` |
| Read-only or failed durable write | no decision or notification transition is reported as committed | `grants/grants_test.go`, `grants/notifications_test.go` |
| Backward or forward wall clock | leases do not reopen authority and rate windows do not reset backward | `admission/admission_test.go`, `grants/notifications_test.go` |
| Telegram outage, retry, duplicate callback, and cancellation | callbacks remain idempotent, progress is durable, and polling stops | `notify/telegram/telegram_test.go`, `grants/notifications_test.go` |
| Provider timeout or ambiguous completion | no automatic mutation retry; authority is retained only for reconciliation | `operationruntime/runtime_test.go`, provider recovery suites |
| Crash before or during execution | committed plans recover; unprovable outcomes fail explicitly | `operationruntime/runtime_test.go`, HF and GH restart suites |
| Listener or service activation failure | no transport fallback; previous managed configuration is restored | `endpoint`, `service/install_linux_test.go`, `service/install_darwin_test.go` |
| Interrupted credential or file cutover | previous files and service definition are restored before reactivation | `service/install_linux_test.go`, `service/install_darwin_test.go` |
| Submission overload | new work receives stable `429`; replay, cancellation, approval, and readiness remain available | `admission/admission_test.go`, `operationruntime/runtime_test.go` |
| Shutdown with a live parent context | owned workers stop before SQLite closes | GH, HF, and sudo server shutdown tests |

Every drill asserts durable terminal state or rollback state, not just an HTTP
status. Test fixtures use bounded timeouts and synthetic local upstreams. Live
provider tests complement this matrix but are not the only evidence for a
failure invariant.
