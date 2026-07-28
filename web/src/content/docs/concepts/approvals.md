---
title: Approvals
description: The operator inbox, decision safety, the presentation model, and how a waiting request resumes.
---

An operation marked `request` in policy does not run. It creates a durable approval record and
waits for a human. This page covers what an operator sees, how a decision is applied safely, and
what happens to the caller that is still waiting.

## The two sides

Agents and operators live in separate authority domains. The agent listener is client-scoped and
cannot make operator decisions or read another client's history. The operator inbox runs on its own
listener or Unix socket with its own credential, and a credential reused by a broker client is
rejected outright.

unYOLO provides the durable backend for the inbox. It does not render a web application. A
broker mounts the shared handler behind an operator-only transport, and a trusted host calls that
backend and presents the records in its own UI.

## Routes

```text
GET  /api/operator/v1/requests
GET  /api/operator/v1/requests/{id}
GET  /api/operator/v1/events
POST /api/operator/v1/requests/{id}/approve
POST /api/operator/v1/requests/{id}/deny
POST /api/operator/v1/requests/{id}/revoke
```

Operators approve or deny pending requests and may revoke active grants. Cancellation is not on
this list on purpose: only the authenticated requester may cancel its own pending request, and it
does so through the agent surface.

List filters are `status`, `requester`, `operation`, `target_kind`, repeated `target.<field>`,
`cursor`, and `limit`. Limits default to 50 and cannot exceed 100. Ordering is newest request
first, then grant ID, and cursors are opaque and bound to the filter that produced them.

## Making a decision safely

A decision body uses optimistic concurrency:

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

Every decision requires a positive expected revision. A stale decision returns `409
revision_conflict` along with the current safe item, so an operator acting on a screen that has
moved on gets told rather than silently overwriting.

Only approval accepts `constraints`, and they can only narrow. Duration and use count may stay
equal or shrink. No route accepts a replacement operation, target, attribute set, provider body, or
execution plan, so the decision applies to the broker's canonical stored request rather than to
anything the caller supplies.

## The presentation model

Operators need to understand what they are approving without the broker leaking the plan. That is
what the bounded presentation model is for. A provider presenter supplies a title, a summary,
targets, risk, warnings, provider-specific facts, and a plan hash. The shared layer validates all of
it, bounds its length, escapes it for whatever transport renders it, and owns the fixed controls.

Presentation never becomes execution authority. The actions available and the bounds an approval
may set come from the grant, not from the text. If a presenter returns unsafe or invalid output,
the inbox shows a bounded generic item rather than hiding the request, so a broken presenter cannot
make a pending approval invisible.

## Lifecycle events

`GET /api/operator/v1/events` is a Server-Sent Events stream carrying durable cursors as both the
SSE `id` and the event object's `cursor`. Reconnect with `Last-Event-ID` or the `cursor` query
parameter.

Events contain only the grant ID, state, counters, revision, time, and cursor. A cursor older than
retained history returns `410 cursor_expired`, and the consumer must refresh the bounded list and
restart from the newest returned state before reconnecting.

## Trusted host integration

A presentation host is not another grant authority. The chain runs:

```text
browser session
    → trusted web backend
    → operator/client using a server-held operator credential
    → broker operator API
    → canonical unYOLO grant store
```

The browser authenticates only to the trusted host. Operator credentials never enter browser
storage, HTML, JavaScript, logs, or API responses. A browser decision contains only the request ID,
the expected revision, an idempotency key, and bounded approval narrowing. The broker applies it to
its own stored request and plan.

A host may aggregate several brokers, but each broker stays the source of truth for its own
requests. The host should persist only UI preferences and durable event cursors. On disconnect or
restart it reconnects from the last cursor, and on `cursor_expired` it refreshes that broker's list
and starts from the newest state.

## The waiting caller

For discrete operations, submission returns immediately with a durable operation ID. The caller
polls or waits, and approval resumes the stored operation rather than requiring resubmission.
Retrying the same request ID cannot create a second execution.

For Git, the approval stays attached to the original HTTP request. One durable approval covers the
complete ordered receive-pack transaction. Approval resumes that same `git push`, and denial,
expiry, cancellation, or changed upstream state returns an ordinary Git failure without forwarding
a partial update.

The lock behaviour is worth knowing. A broker releases the provider lock while waiting for a
decision, then reacquires it and reclassifies the exact transaction before forwarding. Without
that, one pending approval would block every other push to the repository.

## Telegram as a view

Telegram is an optional notification view over the same durable grant store, not a second approval
state machine. A decision made through a Telegram button and a decision made through the inbox API
close the same request exactly once.

Provider code supplies only bounded operation, target, risk, warning, and plan facts. unYOLO
owns Telegram layout, escaping, emoji, the fixed Approve and Deny buttons, callback answers,
terminal wording, and message limits. Dynamic provider values are HTML-escaped and bounded without
splitting UTF-8, and they cannot supply markup, button labels, callback answers, or status prose.

When several brokers share a bot, one `unyolo-telegram` ingress owns inbound updates and routes
decisions to the owning broker's authenticated Operator V1 socket. See
[Telegram approvals](/docs/guides/telegram-approvals).

## Security properties

Every route authenticates before dispatch and returns `Cache-Control: no-store`. Operator actions
persist the approver, the previous and next state, revisions, and the event cursor atomically in
the durable lifecycle record.

The required audit recorder receives the same outcome as an external export. When an external
export fails, that is reported in the `X-Broker-Audit-Export` header and does not turn a committed
decision into an apparent failure. A committed decision stays committed.
