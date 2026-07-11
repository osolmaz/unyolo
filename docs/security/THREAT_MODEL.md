# BrokerKit Threat Model

BrokerKit is a control-plane library for brokers that keep an upstream
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
  not authority stores.
- The OpenClaw plugin is a trusted operator client. Its browser and outbound
  messages receive only the safe Operator V1 projection.
- Provider executors, especially the sudo helper, are separate processes and
  credential domains. BrokerKit code does not execute provider operations.

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
- Keep execution reservations private. Public resources and events never
  expose decision-token verifiers, raw plans, credentials, provider bodies,
  command output, or reservation internals.
- Emit `Cache-Control: no-store`, safe closed error codes, and correlation IDs.
  External audit export failure does not roll back committed authority and is
  surfaced only through a safe diagnostic.
- Register broker sources statically. Browser input cannot select an endpoint,
  credential, proxy, header, or executable plan.

## Threats And Failure Behavior

| Threat | Required behavior |
| --- | --- |
| Client impersonates an operator | Separate secret sets and listeners reject it before handlers run. |
| Stale or replayed browser decision | Revision and idempotency checks return current safe state without repeating authority. |
| Replayed notification callback | The token is consumed only by the pending transition; later use fails. |
| Plan changed after request | Content digest and grant binding fail activation or execution. |
| Approval widens authority | Duration and use constraints can only stay equal or narrow. |
| Cursor swapping or filter changes | Filter-bound opaque cursors are rejected. |
| Store corruption or unsupported old state | Readiness fails and the listener must not receive traffic. No compatibility reader rewrites it. |
| Notification send has an ambiguous result | Durable unresolved state remains lease-bound and retry-safe. |
| Broker or host restarts after a lost response | Durable idempotency, events, cursors, and delivery records recover the committed result. |
| One broker is down or rate-limited | Its source becomes unhealthy without changing another broker's authority. |
| Presenter returns unsafe or invalid output | A bounded generic fallback is shown; actions and approval bounds still come from the grant. |
| Audit exporter fails after commit | The committed lifecycle stays authoritative and a safe diagnostic is emitted. |
| Provider error contains sensitive data | The public API maps it to a closed error code; detail remains only in provider-owned secret-safe audit data. |

## Explicit Non-Protections

BrokerKit does not protect a machine where the broker account, state files,
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
