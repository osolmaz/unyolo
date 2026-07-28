# unYOLO threat model

unYOLO is a control-plane library for brokers that keep an upstream
credential or privilege boundary away from an untrusted client. It does not
make a provider executor safe. Each broker remains responsible for parsing,
classifying, validating, and executing its own operations.

## Trust Boundaries

- Agent clients hold only a broker-client credential. They are not operators
  and never receive an upstream credential, decision token, or execution plan.
- Operators and trusted hosts use a separate operator credential on a separate
  listener or Unix socket. Reusing a client secret as an operator secret is
  rejected.
- The broker process owns policy, grants, immutable provider plans, activation
  validation, provider credentials, and audit export.
- Notification channels carry one-time decision tokens. They are transports,
  not long-term authority stores. The Telegram ingress may retain encrypted
  callback authority only until terminal delivery or expiry.
- The OpenClaw plugin is a trusted operator client. Its browser and outbound
  messages receive only the safe Operator V1 projection.
- Provider executors, especially the sudo helper, are separate processes and
  credential domains. unYOLO code does not execute provider operations.

## Protected Assets

- upstream provider credentials and privileged helper capabilities;
- broker-client and operator credentials;
- one-time decision tokens;
- canonical provider execution plans;
- grant, revision, use-budget, reservation, and idempotency state;
- notification delivery state and audit records.

## Required Controls

- Authenticate before returning operator resources or safe conflict state.
- Bind every approval to either an expected revision plus idempotency key or a
  single-use token. Activation validation and the state transition occur under
  the same grant-store lock.
- Treat provider plans as immutable, content-addressed records. Missing,
  malformed, or mismatched plans fail approval and execution closed.
- Bound request bodies, query sizes, pages, cursors, presentation text, event
  retention, grant duration, and use counts.
- Reject unknown command JSON fields, unsupported protocol versions, duplicate scalar
  query parameters, invalid transitions, widened approval constraints, and
  unsupported state shapes.
- Persist transitions, events, idempotency records, reservations, and
  notification claims atomically before acknowledging success.
- Persist a Telegram callback and its next update offset in one transaction
  before answering Telegram. Encrypt decision authority at rest and erase it
  after terminal reconciliation or expiry.
- Require exact generated Agent and Operator contract digests. A version label
  alone is not compatibility evidence.
- Execute persistent services only from a verified immutable host bundle.
  Stop callback consumers before switching releases and start them only after
  provider readiness succeeds.
- Keep native service definitions on the exact root-controlled `current`
  destination and verify every resulting process against the selected
  immutable release before committing activation.
- Keep Operator credentials outside signed runtime manifests. A manifest may
  contain only the absolute token-file path needed for authenticated local
  readiness.
- Keep execution reservations private. Public resources and events never
  expose decision-token verifiers, raw plans, credentials, provider bodies,
  command output, or reservation internals.
- Emit `Cache-Control: no-store`, safe closed error codes, and correlation IDs.
  External audit export failure does not roll back committed authority and is
  surfaced only through a safe diagnostic.
- Register broker sources statically. Browser input cannot select an endpoint,
  credential, proxy, header, or executable plan.
- Scope native Git credentials to the exact loopback listener origin. The Git
  listener exposes only authenticated identity, smart-HTTP, and provider-owned
  LFS routes; agent, operator, webhook, browser, and credential lifecycle
  routes return not found.
- Keep upstream LFS action URLs and headers inside the broker. Broker-local
  action capabilities are random, expiring, and bound to client, repository,
  path, method, and policy. Refuse unsupported Xet negotiation before returning
  any signed action.
- Treat user Git configuration as untrusted input. Installation rejects
  conflicting URL rewrites, owns exact values, never stores an upstream
  credential, and fails closed when the broker listener or helper is missing.

## Threats and failure behavior

| Threat | Required behavior |
| --- | --- |
| Client impersonates an operator | Separate secret sets and listeners reject it before handlers run. |
| Stale or replayed browser decision | Revision and idempotency checks return current safe state without repeating authority. |
| Replayed notification callback | The token is consumed only by the pending transition; later use fails. |
| Plan changed after request | Content digest and grant binding fail activation or execution. |
| Approval widens authority | Duration and use constraints can only stay equal or narrow. |
| Cursor swapping or filter changes | Filter-bound opaque cursors are rejected. |
| Store corruption or unsupported state | Readiness fails and the listener must not receive traffic. |
| Notification send has an ambiguous result | Durable unresolved state remains lease-bound and retry-safe. |
| Broker or host restarts after a lost response | Durable idempotency, events, cursors, and delivery records recover the committed result. |
| One broker is down or rate-limited | Its source becomes unhealthy without changing another broker's authority. |
| Presenter returns unsafe or invalid output | A bounded generic fallback is shown; actions and approval bounds still come from the grant. |
| Audit exporter fails after commit | The committed lifecycle stays authoritative and a safe diagnostic is emitted. |
| Provider error contains sensitive data | The public API maps it to a closed error code; detail remains only in provider-owned secret-safe audit data. |
| Git config routes around the broker | Install and doctor detect conflicting provider rewrites; broker-only mode never falls back to the provider. |
| Git listener is used as a broad agent API | The independent route gate rejects every non-Git path before provider routing. |
| Approval wait blocks all pushes to a repository | Release the provider lock during the wait, then reacquire and reclassify the exact transaction before forwarding. |
| LFS or Xet response exposes a signed provider action | Rewrite supported LFS actions to broker-local capabilities and fail unsupported transfers closed. |
| Old ingress calls a newer broker schema | Exact contract discovery fails before another Telegram update is consumed. |
| Binary is replaced while its old process keeps running | Host doctor detects the deleted or outside-release executable and fails readiness. |
| Host upgrade fails after stopping services | Restore the previous release, native services, and replaced state before restarting Telegram. |
| Host exits after switching the release pointer | Reconcile the private transaction journal before another lifecycle command; retain a verified committed candidate or restore the recorded prior release. |
| Telegram callback arrives while a broker is unavailable | Commit encrypted authority and offset, retry that route idempotently, and continue healthy routes. |

## Explicit Non-Protections

unYOLO does not protect a machine where the broker account, state files,
operator secret, provider credential, or privileged helper endpoint is already
compromised. It does not sandbox provider code, validate arbitrary shell
strings, proxy arbitrary provider APIs, or replace host hardening and secret
rotation.

## Security Verification

Required verification includes race tests, cursor and callback fuzzing,
protocol schema drift tests, provider activation and execution tests, restart
tests, secret scanning, dependency vulnerability scanning, and the adversarial
fixtures in the Operator V1 conformance suite. Mutation testing remains
checked in but is opt-in and non-blocking.
