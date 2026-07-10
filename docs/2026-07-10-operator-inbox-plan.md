# Operator Inbox Plan

Date: 2026-07-10

Status: Brokerkit backend implemented; consuming-broker cutover pending

## Motivation

Broker-style services let an untrusted client request actions while a trusted
service holds the real credential or privilege boundary. Some actions can be
allowed automatically. Others need a human decision before they are executed.

Brokerkit already owns the generic grant lifecycle, durable notification
state, approval decisions, use budgets, reservations, and audit primitives.
What is missing is a reusable operator-inbox surface that applications can use
to build notification drawers, dashboards, CLIs, desktop prompts, or other
approval experiences without reimplementing grant queries and transitions in
every broker.

The operator inbox must remain independent of Hugging Face, GitHub, Unix
privilege execution, Telegram, and any specific frontend framework.

## Existing Baseline

This work extends the existing Brokerkit grant system. It must not introduce a
second request or approval state machine.

As of 2026-07-10:

- Brokerkit already owns durable grant states, decision tokens, notification
  claims and references, callback recovery, status delivery, reservations, use
  budgets, and expiry;
- `hf-broker` pull request
  [#19](https://github.com/osolmaz/hf-broker/pull/19) cuts Telegram transport
  and durable approval behavior over to Brokerkit commit `5d682c4`;
- `sudo-broker` pull request
  [#7](https://github.com/osolmaz/sudo-broker/pull/7) makes approval-message
  and execution-settlement state durable using Brokerkit;
- `hf-broker`, `gh-broker`, and `sudo-broker` already use the common
  `POST/GET /api/grants` shape for agent-facing grant creation and reads;
- `sudo-broker` already exposes HTTP approve, deny, and revoke routes, while
  `hf-broker` and `gh-broker` currently make those decisions through Telegram
  callbacks.

Implementation must land after, or be rebased onto, those durable-lifecycle
changes. It should extract and extend shared behavior, not replace it.

## Goal

Provide reusable Go primitives and HTTP handlers for:

- listing pending requests and historical decisions;
- reading one request and its safe operator-facing details;
- approving, denying, canceling, and revoking requests;
- streaming request lifecycle events;
- preserving idempotency, expiry, use budgets, reservations, and audit data;
- letting each consuming broker supply provider-specific display details and
  execute provider-specific actions.

A consuming broker should be able to mount the operator inbox on a protected
Unix socket or another trusted transport. A separate host application should
be able to call that surface through a thin client and render its own UI.

## Design Boundary

Brokerkit owns the generic control plane:

```text
request query
safe operator projection
decision command
grant transition
lifecycle event
audit metadata
```

The consuming broker owns:

```text
provider operation vocabulary
target classification
policy registration
provider-specific risk and display text
upstream credential
execution plan construction
provider action execution
transport exposure and operator authentication
```

Brokerkit must not become a daemon, generic credential proxy, hosted service,
or frontend application.

## Operator Inbox Model

Add a provider-neutral projection for displaying a request without exposing
the provider request body or credential-bearing data.

Suggested shape:

```go
type InboxItem struct {
    ID               string
    Client           string
    Operation        string
    Target           string
    Status           string
    RequestedAt      time.Time
    PendingExpiresAt time.Time
    ActiveExpiresAt  *time.Time
    RequestedMinutes int
    MaxUses          int
    UsedCount        int
    Risk             string
    Title            string
    Summary          string
    Reason           string
    Fields           []DisplayField
    PlanHash         string
    Audit            []AuditSummary
}
```

`Risk`, `Title`, `Summary`, `Fields`, and any plan presentation come from a
broker-owned presenter. Brokerkit validates and copies the projection, bounds
its size, and rejects unsafe field names or values according to a small generic
contract. It does not infer provider risk or wording.

The projection is not execution authority. Decisions always apply to the
durable grant and canonical provider plan already stored by the broker.

## Query API

Extend the durable grant store with bounded queries:

```go
List(Query) (Page, error)
Get(id string) (Grant, error)
```

`Query` should support:

- status group: pending, active, history, or all;
- client;
- operation;
- target;
- created-before cursor;
- bounded page size.

Ordering is deterministic: newest request first, then grant ID as a stable
tiebreaker. Pagination uses an opaque cursor generated from durable ordering
fields. Query output never contains decision tokens, notification tokens,
provider credentials, request bodies, or raw execution plans.

## Decision API

Expose typed commands over the existing grant store:

```go
Approve(ApproveCommand) (Grant, error)
Deny(DenyCommand) (Grant, error)
Cancel(CancelCommand) (Grant, error)
Revoke(RevokeCommand) (Grant, error)
```

Every command includes:

- request ID;
- authenticated approver identity supplied by the consuming broker;
- expected current status or revision;
- optional operator reason;
- only the bounded values already permitted by grant policy, such as approved
  duration and use count.

Commands must not accept a replacement operation, target, attrs, execution
plan, or provider request body. Stale and conflicting decisions return the
authoritative current state without reopening the request.

## Lifecycle Events

Add a durable event cursor over grant lifecycle changes. Events support live
notifications and reconnect without turning transient delivery into source of
truth.

Required event kinds:

```text
request.created
request.approved
request.denied
request.canceled
request.expired
grant.revoked
grant.reserved
grant.consumed
grant.released
execution.succeeded
execution.failed
execution.ambiguous
```

Each event contains only:

- monotonically ordered cursor;
- event kind;
- grant ID;
- safe status and count metadata;
- event timestamp.

Consumers fetch current details through the query API. Events do not duplicate
full request bodies or provider data.

The durable store must support:

```go
EventsAfter(cursor string, limit int) (EventPage, error)
```

An in-process notifier may wake blocked SSE handlers, but reconnect and missed
events always recover from durable state.

## Reusable HTTP Surface

Add a small stdlib `net/http` package, tentatively `operatorapi`, that brokers
can mount only after their own operator authentication and transport boundary.

Keep the established grant route vocabulary. On an operator-authenticated
listener or socket, expose:

```text
GET  /api/grants
GET  /api/grants/{id}
GET  /api/grants/events
POST /api/grants/{id}/approve
POST /api/grants/{id}/deny
POST /api/grants/{id}/cancel
POST /api/grants/{id}/revoke
```

The existing agent listener may continue to expose `POST /api/grants` and
client-scoped reads. It must not expose operator decisions or cross-client
history. A broker that deliberately uses one listener must authenticate
operator routes with a separate authority, as `sudo-broker` already does.

Requirements:

- `/api/grants/events` uses SSE with event IDs and reconnect support;
- list and history responses are paginated and bounded;
- mutating requests use strict JSON decoding and small body limits;
- response headers use `no-store`;
- errors expose stable safe codes and never include secrets or provider bodies;
- the package receives an authenticated approver identity through an explicit
  callback or request context set by the consuming broker;
- missing operator authentication fails closed before handlers run;
- handlers cannot be mounted on an agent listener accidentally without an
  explicit operator-authorizer dependency.

The routes do not include a protocol version. Consumers and brokers cut over
together when the contract changes.

## Client Support

Do not publish a separate multi-language SDK.

Provide:

- a small Go `operatorclient` for broker and Go-host integration tests;
- documented JSON and SSE examples;
- contract fixtures covering list, detail, events, and every decision;
- a fake operator server for consuming-application tests.

Non-Go applications should implement a thin internal client against the small
HTTP surface. The fixtures and conformance tests, not generated SDKs or
protocol negotiation, keep implementations aligned.

## Presentation Interface

Define a broker-supplied presenter interface:

```go
type Presenter interface {
    Present(context.Context, grants.Grant) (InboxPresentation, error)
}
```

The presenter may read broker-owned canonical plan metadata, but Brokerkit
receives only the safe projection. Presentation failure must not make a grant
disappear. The inbox returns the item with a generic title, status, and a safe
`presentation_unavailable` marker.

Brokerkit should provide bounds for:

- number of display fields;
- title, summary, reason, label, and value lengths;
- audit summary count;
- allowed risk labels;
- Unicode and control-character handling.

## Operator Authentication Boundary

Brokerkit authenticates named clients today, but the operator inbox needs a
separate authority domain. An agent client secret must never become an
operator credential.

Add reusable primitives for:

- operator identity records;
- constant-time operator-secret authentication where a broker uses secrets;
- explicit approver identity propagation;
- separation checks that reject reused client/operator secrets;
- audit-safe authentication failures.

The consuming broker decides whether the operator identity comes from a Unix
socket peer, OAuth-authenticated control plane, local CLI, passkey-backed
session, or another trusted source.

## Notification Transports

The operator inbox is the durable source of truth. Notification transports are
optional views over it.

- Telegram remains an optional Brokerkit adapter.
- A browser drawer can consume SSE.
- A CLI can list pending requests.
- A desktop app can poll or stream events.
- A broker may run with no push notifier at all.

Creating a request must not fail merely because no Telegram bot or other push
transport is configured. If policy permits a request, it remains pending and
discoverable in the inbox until decision or expiry.

## Audit

Every operator action emits the shared audit fields plus:

- approver identity;
- previous and next status;
- operator reason when present;
- expected and actual revision when a conflict occurs;
- event cursor;
- execution ambiguity marker when relevant.

Never audit:

- decision or approval tokens;
- broker client or operator secrets;
- upstream credentials;
- provider request bodies;
- raw execution plans;
- Git packs, command output, or raw upstream responses.

## Implementation Work

- extend `grants` with bounded queries and deterministic cursors;
- add durable lifecycle events and event cursors;
- add typed decision commands with approver and revision checks;
- add safe inbox projections and presenter bounds;
- add operator identity/auth primitives separate from agent auth;
- add `operatorapi` handlers and SSE recovery;
- add a small Go `operatorclient` and fake server;
- make notification delivery optional rather than request-creation gating;
- cut `hf-broker`, `gh-broker`, and `sudo-broker` over to the shared inbox
  query, decision, and event implementation without changing their provider
  classifiers or executors;
- delete broker-local duplicate HTTP decision/query logic in the same adoption
  change where the Brokerkit handler is used;
- update `ARCHITECTURE.md`, `OWNERSHIP.md`, and
  `UNIFIED_BROKER_CONTRACT.md` after implementation;
- keep provider-specific operations, plans, wording, and execution out of
  Brokerkit.

## Test Plan

### Grant And Query Tests

- deterministic pending, active, and history ordering;
- cursor pagination without duplicates or omissions;
- status, client, operation, and target filters;
- strict page-size bounds;
- decision tokens and unsafe metadata absent from all projections;
- stale revision and concurrent-decision behavior;
- approve, deny, cancel, revoke, expire, reserve, release, consume, and
  ambiguous-execution events;
- event recovery after restart;
- event compaction or retention does not corrupt current grant state.

### HTTP And SSE Tests

- operator authorization is mandatory;
- agent credentials cannot authenticate as operators;
- reused client/operator secrets are rejected at configuration time;
- strict methods, content types, JSON bodies, and size limits;
- list, detail, and history pagination;
- SSE initial replay, live delivery, reconnect, and last-event cursor;
- slow or disconnected subscribers do not block grant transitions;
- no-store and safe error headers;
- no secret or provider-body leakage.

### Client And Conformance Tests

- Go client covers every route and error code;
- fake server reproduces query, decision, and SSE behavior;
- checked-in fixtures round-trip through server and client;
- HF, GitHub, and Unix sample presenters pass the same list, detail, decision,
  and event fixtures;
- a consuming broker can mount the API on an operator-only Unix socket;
- a non-Go fixture consumer can implement the contract without provider
  knowledge.

### Quality Gates

```sh
go fmt ./...
go vet ./...
go test -race ./...
./scripts/check-go-coverage.sh
golangci-lint run
slophammer-go dry .
slophammer-go crap .
./scripts/check-mutation.sh
slophammer-go check .
```

## Acceptance Criteria

- Any broker can expose a durable approval inbox without Telegram.
- Any trusted host application can list, stream, approve, deny, and revoke
  requests through a small HTTP client.
- Agent and operator credentials are structurally separate.
- Provider-specific plans and wording remain in consuming brokers.
- Decisions apply only to canonical durable requests.
- Reconnect and restart preserve complete request history and pending state.
- No API, event, log, error, fixture, or test output contains protected
  credentials or decision tokens.
- Brokerkit remains a library rather than a daemon or provider framework.

## Non-Goals

- Do not implement a React component library or opinionated visual design.
- Do not implement Hugging Face, GitHub, or Unix provider behavior.
- Do not add a generic credential or HTTP reverse proxy.
- Do not require Telegram or another notification transport.
- Do not add protocol negotiation or compatibility layers.
- Do not turn Brokerkit into a standalone server.
