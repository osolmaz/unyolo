---
title: Operator V1 API
description: API reference for listing and deciding operator requests.
---

Operator V1 (`unyolo.io/operator/v1`) is the protected API for listing and deciding requests. The
OpenAPI file is `protocol/openapi/operator-v1.yaml`. Generated Go code is under
`protocol/operatorwire/`, and `openclaw-unyolo/operator-v1` ships the TypeScript code.

Provider execution plans and credentials are deliberately absent from the contract.

## Routes

```text
GET  /api/operator/v1/requests
GET  /api/operator/v1/requests/{id}
GET  /api/operator/v1/events
POST /api/operator/v1/requests/{id}/approve
POST /api/operator/v1/requests/{id}/deny
POST /api/operator/v1/requests/{id}/revoke

GET  /metrics
```

Mount these only on an operator listener or a protected Unix socket. The agent listener must not
expose them. Authenticate with a bearer token from `/etc/<broker>/operator-secrets`.

Cancellation is absent by design. Only the authenticated requester may cancel its own pending
request, through the agent surface.

## Listing

Filters are `status`, `requester`, `operation`, `target_kind`, repeated `target.<field>`, `cursor`,
and `limit`.

Limits default to 50 and cannot exceed 100. Ordering is newest request first, then grant ID.
Cursors are opaque and bound to the filter that produced them, so swapping filters mid-pagination
is rejected rather than silently returning a different slice. Each request includes its grant
mode. `window` identifies reusable scoped authority, while `execution` identifies one exact
immutable action.

```sh
curl -sS --unix-socket /run/unyolo/huggingface/operator/broker.sock \
  -H "Authorization: Bearer $OPERATOR_TOKEN" \
  "http://localhost/api/operator/v1/requests?status=pending&limit=25"
```

## Decisions

```json
{
  "expected_revision": 3,
  "idempotency_key": "example-request",
  "constraints": {
    "duration_seconds": 300,
    "max_uses": 1
  }
}
```

Every decision requires a positive `expected_revision`. A stale decision returns
`409 revision_conflict` together with the current safe item.

Only approval accepts `constraints`, and they can only narrow. Duration and use count may stay
equal or shrink. No route accepts a replacement operation, target, attribute set, provider body, or
execution plan, so a decision always applies to the broker's canonical stored request.

## Lifecycle events

`GET /api/operator/v1/events` is an SSE stream. Durable cursors are sent as both the SSE `id` and
the event object's `cursor`. Reconnect with `Last-Event-ID` or the `cursor` query parameter.

Events contain only the grant ID, state, counters, revision, time, and cursor.

A cursor older than retained history returns `410 cursor_expired`. The consumer must refresh the
bounded list and restart from the newest returned lifecycle state before reconnecting.

## Presentation

Each item carries a bounded presentation model supplied by the broker's presenter: a title, a
summary, targets, risk, warnings, provider facts, and a plan hash. The shared layer validates it,
bounds its length, and makes defensive copies.

Presentation never becomes execution authority. Available actions and approval bounds come from the
grant. A presenter that returns unsafe or invalid output produces a bounded generic item rather
than hiding the request, so a broken presenter cannot make a pending approval invisible.

## UI payloads

The same document defines the aggregate payloads the packaged OpenClaw interface and delegated
hosts use. `UISnapshot` is the full authoritative view. `UISnapshotEvent` is a cursor-only
invalidation for bounded authenticated long polling. `UISummary` drives host badges without
exposing request details.

## Mounting the handler

```go
operators, err := operatorauth.New(operatorSecrets, operatorauth.Options{
    ClientSecrets: clientSecrets,
})
if err != nil {
    return err
}

inbox, err := operatorinbox.New(grantStore, providerPresenter)
if err != nil {
    return err
}

handler, err := operatorapi.New(operatorapi.Options{
    Inbox:     inbox,
    Authorize: operators.AuthenticateRequest,
    Broker:    "hf-broker",
    Audit:     auditWriter,
})
```

Passing `ClientSecrets` is what lets `operatorauth` reject an operator credential that a broker
client already uses. The audit recorder is required at construction time rather than optional.

## Packages

| Package | Responsibility |
| --- | --- |
| `authorization/grants` | Revisioned requests, bounded queries, decisions, lifecycle events, retention, durable cursors. |
| `approval/view` | Provider-neutral bounded presentation model, risk vocabulary, warnings, validation, safe fallback. |
| `operator/inbox` | Combines canonical grants with a broker-owned safe presenter. |
| `approval/notification` | Projects the validated presentation into a semantic notification envelope. |
| `operator/auth` | Authenticates operator credentials and rejects reuse by a broker client. |
| `operator/api` | The protected JSON and SSE routes. |
| `operator/client` | Small Go client for trusted host applications. |
| `operator/fake` | Runs production handler and store behaviour in consumer tests. |

Checked-in wire examples live under `operator/api/testdata`.

## Trusted host integration

```text
browser session
    → trusted web backend
    → operator/client using a server-held operator credential
    → broker operator API
    → canonical unYOLO grant store
```

The browser authenticates only to the trusted host. Operator credentials never enter browser
storage, HTML, JavaScript, logs, or API responses. A browser decision carries only the request ID,
expected revision, idempotency key, and bounded narrowing.

A host may aggregate several brokers, but each broker stays the source of truth for its own
requests. The host should persist only UI preferences and durable event cursors.

## Security properties

Every route authenticates before dispatch and returns `Cache-Control: no-store`.

Operator actions persist the approver, the previous and next state, revisions, and the event cursor
atomically in the durable lifecycle record. The required audit recorder receives the same outcome
as an external export; export failure is reported in the `X-Broker-Audit-Export` header and cannot
turn a committed decision into an apparent failure.

Notification transports such as Telegram are optional renderers over the same semantic presentation
and durable state machine. Persisted notification references bind the normalized presentation and
the exact rendered message with separate SHA-256 digests, and decision tokens are excluded.

## Metrics

`GET /metrics` serves the Prometheus registry on this listener and requires the same operator
credential. The agent listener never serves metrics, and a broker without an operator listener has
no metrics HTTP surface. See [metrics and logs](/docs/operate/observability).
