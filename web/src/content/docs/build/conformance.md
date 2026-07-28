---
title: Conformance tests
description: What a broker must prove before it is trustworthy, and the shared suites that prove it.
---

A broker built on BrokerKit inherits the control plane but not a guarantee that it wired it up
correctly. The conformance suite exists to catch the difference. `broker/conformance` runs the
shared contract against your real HTTP handlers, and every broker invokes it from its own tests.

## Required proofs

Seven properties, taken from the shared contract:

- The broker registers only its own provider vocabulary.
- Valid requests go through BrokerKit decisions rather than around them.
- Malformed or unclassified requests fail closed before execution.
- Deny overrides active grants.
- Active grants match only the approved client, operation, target, attrs, duration, and use budget.
- Audit output contains no secrets, request bodies, Git pack contents, command output, approval
  tokens, or upstream credential metadata.
- Telegram callbacks cannot approve a different grant than the one displayed.

The second is the one that catches real mistakes. A provider handler that reaches its executor
without passing through the decision path will pass every unit test you wrote for it and fail this.

## The shared setup contract

Alongside the runtime behaviour, every broker is expected to test its installation surface:

- install script platform selection and checksum handling
- `setup systemd --dry-run`
- `setup systemd --no-start` file rendering in temporary directories
- service unit content, without starting real services
- client config rendering, without printing secrets
- authentication accepting valid clients and rejecting invalid ones
- policy rejecting unknown operations, targets, attrs, and fields
- deny overriding active grants
- generated grants matching only what was approved
- audit output containing no secrets

Telegram is covered by a fake Bot API server or a fake notifier. CI never sends real Telegram
messages and never mutates real external repositories, so live provider tests stay explicit manual
or staging checks.

## Test doubles

`operator/fake` runs the production handler and store behaviour inside consumer tests, so a trusted
host or plugin can be tested against real inbox semantics without a broker process. Checked-in wire
examples live under `operator/api/testdata`.

The framework injects a clock into the grant store, so expiry, lease, and rate-window behaviour is
testable without sleeping.

## Failure drills

Correct behaviour under normal load is the easy half. BrokerKit keeps deterministic drills beside
the boundary they exercise, and a new broker should expect to be held to the same list:

| Failure class | Required invariant |
| --- | --- |
| SQLite corruption or incompatible restore | Startup and restore fail closed without replacing current state. |
| Read-only or failed durable write | No decision or notification transition is reported as committed. |
| Backward or forward wall clock | Leases do not reopen authority and rate windows do not reset backward. |
| Provider timeout or ambiguous completion | No automatic mutation retry; authority retained only for reconciliation. |
| Crash before or during execution | Committed plans recover; unprovable outcomes fail explicitly. |
| Listener or service activation failure | No transport fallback; previous managed configuration restored. |
| Submission overload | New work receives a stable `429` while replay, cancellation, approval, and readiness stay available. |
| Shutdown with a live parent context | Owned workers stop before SQLite closes. |

Every drill asserts durable terminal state or rollback state rather than an HTTP status. Fixtures
use bounded timeouts and synthetic local upstreams. The full matrix, with the test file that covers
each row, is in [failure drills](/docs/operate/failure-drills).

## Security verification

Beyond functional tests, the required verification is race tests, cursor and callback fuzzing,
protocol schema drift tests, provider activation and execution tests, restart tests, secret
scanning, dependency vulnerability scanning, and the adversarial fixtures in the Operator V1
conformance suite.

Mutation targets stay broker-local and checked in, but they are disabled and non-blocking until an
explicit decision re-enables them.

## Quality and release tooling

`brokerkit-coverage` and `brokerkit-release` provide the common quality and release behaviour, so a
new broker gets the same coverage gate and release asset conventions as the shipped three.

The release shape is fixed: four platform archives plus `checksums.txt`, each archive containing
the binary, `README.md`, and `LICENSE`, and both `<broker> --version` and `<broker> version`
supported.

## CI in this repository

For reference, the CI job for the shipped brokers runs `go mod tidy` with a clean-diff check,
`go mod verify`, a `gofmt` check, architecture and generated-code and SQL checks, the protocol
test, `go vet`, the race-enabled suite, a coverage gate, `golangci-lint`, `govulncheck`, `gitleaks`
with redaction, and the Slophammer complexity and duplication gates. A separate macOS job runs the
race-enabled suite on Darwin.

The architecture check is the one specific to this framework: it fails a build where shared code
imports a provider, or where one provider imports another.
