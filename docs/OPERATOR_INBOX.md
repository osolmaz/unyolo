# Operator Inbox

Brokerkit provides the durable backend contract for operator approval inboxes.
It is provider-neutral and does not render a web application. A broker mounts
the shared handler behind an operator-only transport; a trusted host calls that
backend and presents the resulting safe records in its own UI.

## Packages

- `grants` owns revisioned requests, bounded queries, decisions, lifecycle
  events, retention, and durable cursors.
- `operatorinbox` combines canonical grants with a broker-owned safe
  presenter. Presenter failure returns a generic item instead of hiding the
  request.
- `operatorauth` authenticates dedicated operator credentials and rejects any
  credential reused by a broker client.
- `operatorapi` exposes the protected JSON and SSE routes and requires an
  authorizer, broker name, and audit recorder at construction time.
- `operatorclient` is the small Go client used by trusted host applications.
- `operatorfake` runs the production handler and store behavior in consumer
  tests.

## Broker Mount

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

Mount this handler only on an operator listener or protected Unix socket. The
agent listener must not expose these routes. Operator credentials and broker
client credentials are separate authority domains.

## Routes

```text
GET  /api/grants
GET  /api/grants/{id}
GET  /api/grants/events
POST /api/grants/{id}/approve
POST /api/grants/{id}/deny
POST /api/grants/{id}/cancel
POST /api/grants/{id}/revoke
```

List filters are `status`, `client`, `operation`, `target_kind`, repeated
`target.<field>`, `cursor`, and `limit`. Limits default to 50 and cannot exceed
100. Ordering is newest request first, then grant ID. Cursors are opaque.

A decision body uses optimistic concurrency:

```json
{
  "expected_revision": 3,
  "expected_status": "pending",
  "reason": "Reviewed deployment plan",
  "duration_seconds": 300,
  "max_uses": 1
}
```

Only approval accepts duration and use-count narrowing. No route accepts a
replacement operation, target, attributes, provider body, or execution plan.
A stale decision returns `409 revision_conflict` with the current safe item.

The SSE route sends durable cursors as both `id` and the event object's
`cursor`. Reconnect with `Last-Event-ID` or the `cursor` query parameter. A
cursor older than retained history returns `410 cursor_expired`; the consumer
must refresh the list before reconnecting.

Checked-in wire examples are under `operatorapi/testdata`.

## Trusted Host Integration

A trusted presentation host is not another grant authority:

```text
browser session
    -> trusted web backend
    -> operatorclient using a server-held operator credential
    -> broker operator API
    -> canonical Brokerkit grant store
```

The browser authenticates only to the trusted host. Broker operator credentials
never enter browser storage, HTML, JavaScript, logs, or API responses. The host may
aggregate several brokers, but each broker remains the source of truth for its
own request. Browser decisions contain only the request ID, expected revision,
optional reason, and bounded approval narrowing. The broker applies that
decision to its canonical stored request and provider plan.

The host should persist only UI preferences and durable event cursors. On SSE
disconnect or process restart it reconnects from the last cursor. On
`cursor_expired` it refreshes the bounded list, replaces that broker's local
view, and starts from the newest returned lifecycle state.

## Security Properties

- Every route authenticates before dispatch and returns `Cache-Control:
  no-store`.
- Every decision requires a positive expected revision.
- Provider presenters can add wording, fields, risk, and a plan hash, but
  presentation never becomes execution authority.
- Events contain only grant ID, state, counters, revision, time, and cursor.
- Operator actions persist approver, reason, previous/next state, revisions,
  and event cursor atomically in the durable lifecycle record. The required
  audit recorder receives the same outcome as an external export; export
  failure is reported in `X-Broker-Audit-Export` but cannot turn a committed
  decision into an apparent failure.
- Notification transports such as Telegram are optional views over the same
  durable state machine.
