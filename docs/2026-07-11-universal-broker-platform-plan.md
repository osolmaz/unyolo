# Universal Broker Platform Plan

Date: 2026-07-11

Status: proposed

Owners: `brokerkit` for the common contract and reusable runtime; each broker
for its provider adapter; the trusted host for registration and UI aggregation

## Outcome

Brokerkit should become the small, versioned protocol and runtime foundation
for any service that lets an agent request authority and lets an operator
approve, narrow, deny, cancel, or revoke it. Hugging Face, GitHub, Unix, cloud,
database, deployment, finance, and future brokers should share one operator
contract without moving their credentials, request classification, execution
plans, or provider rules into Brokerkit.

The durable boundary is:

```text
agent-facing provider request
        -> provider broker classifies and validates it
        -> broker stores one canonical immutable request/plan
        -> Brokerkit owns the approval/grant lifecycle
        -> provider broker presents safe facts to the operator
        -> operator decides against the canonical revision
        -> provider broker executes its own stored plan
        -> Brokerkit records lifecycle and audit state
```

A trusted host may register many broker sources and aggregate their safe
operator views. Registration does not make the host an execution authority and
does not turn Brokerkit into a generic credential service or upstream proxy.

## Why This Is An Evolution

The current implementation already has the correct core:

- durable Brokerkit grants and lifecycle events;
- separate agent and operator credential domains;
- an operator-only handler;
- revision-checked decisions against canonical stored state;
- bounded provider-owned `Presentation` values with safe fallback;
- durable opaque SSE cursors;
- a trusted-host Go client and fake server;
- black-box control-plane conformance tests; and
- live adoption by `hf-broker` and `gh-broker`.

The plan must extend this state machine. It must not add a parallel request
store, a second approval path, a UI-owned plan, or broker-specific branches in
the common protocol.

## Product Principles

1. Brokerkit standardizes authority transitions, not provider operations.
2. A provider broker is the only owner of its credential and executable plan.
3. The operator sees a bounded safe projection, never the raw plan or request.
4. The decision command identifies a request revision; it cannot replace any
   operation, target, arguments, provider payload, or plan.
5. A trusted host registers broker instances explicitly. Broker responses do
   not get to choose their host-visible identity.
6. The common contract stays small. New provider behavior belongs behind an
   adapter until at least two independent consumers prove a shared need.
7. Every retry, conflict, partial failure, and reconnect has deterministic
   behavior.
8. Unknown input fails closed; unknown event kinds are skipped safely while
   advancing the event cursor.

## Non-Goals

This work does not create:

- a credential create, read, list, export, exchange, or introspection API;
- an arbitrary provider API proxy;
- a generic workflow engine;
- a generic form or component protocol;
- browser-held broker operator credentials;
- dynamic loading of untrusted in-process plugins;
- global transactions or ordering across brokers;
- one universal provider operation vocabulary;
- one universal provider execution-plan schema; or
- a replacement for provider-native policy and safety checks.

## Ownership Boundary

### Brokerkit owns

- the stable operator HTTP/JSON and SSE contract;
- common request/grant states and transitions;
- optimistic concurrency and decision idempotency;
- bounded pagination and durable cursor behavior;
- safe presentation types and validation;
- stable common error codes;
- agent/operator authentication separation primitives;
- the provider-neutral `Source` and `Presenter` interfaces;
- a static source registry and failure-isolating aggregation primitives;
- OpenAPI and JSON Schema source artifacts;
- Go client/server helpers and generated-client test fixtures;
- protocol and security conformance suites; and
- version, cutover, and release rules.

### Every provider broker owns

- upstream credentials and credential rotation;
- agent-facing routes and authentication policy;
- operation, target, and attribute vocabulary;
- provider request parsing and validation;
- provider-specific policy registration;
- canonical execution-plan creation, storage, hashing, and execution;
- upstream retries and ambiguity handling;
- provider-specific approval wording and safe facts;
- provider-specific audit fields and redaction;
- provider-native backstops; and
- the mapping from provider failures into common error categories.

### The trusted host owns

- its operator/browser authentication;
- the registry key, label, endpoint, and credential reference for each broker;
- broker reachability and TLS configuration;
- aggregation, filtering, sorting, and per-source health display;
- durable event cursors per registered source;
- browser-safe normalization; and
- UI state and accessibility.

The host must never accept a browser-provided broker endpoint, operator secret,
provider plan, operation, target, or extension payload for a decision.

## Minimal V1 Wire Example

The first stable contract should be intentionally small. A broker returns a
safe approval request like this:

```json
{
  "id": "01JZ8M41SC3QH12M7S4W8R2Q5N",
  "revision": 3,
  "requester": "bob",
  "operation": "git.push.append",
  "status": "pending",
  "requested_at": "2026-07-11T12:00:00Z",
  "pending_expires_at": "2026-07-11T12:10:00Z",
  "requested_duration_seconds": 300,
  "requested_max_uses": 1,
  "granted_max_uses": null,
  "used_count": 0,
  "request_reason": "Update model files",
  "presentation": {
    "risk": "high",
    "title": "Hugging Face repository write",
    "summary": "Approve one bounded update to the main branch.",
    "facts": [
      {"label": "Repository", "value": "osolmaz/model"},
      {"label": "Ref", "value": "refs/heads/main"},
      {"label": "Mode", "value": "append-only"}
    ]
  },
  "allowed_actions": ["approve", "deny", "cancel"],
  "approval_bounds": {
    "max_duration_seconds": 300,
    "max_uses": 1
  }
}
```

The broker source response does not contain a host registry id. The host binds
the response to the configured source and uses `(source_id, id)` as its
composite identity. This avoids letting a remote broker impersonate a different
registered source and lets the same broker implementation run more than once.

## V1 Resource Model

### Request fields

| Field | Required | Type | Rule |
| --- | --- | --- | --- |
| `id` | Yes | string | Broker-issued opaque id, 1-128 bytes. Never parse or sort it. |
| `revision` | Yes | integer | Positive decision revision. Increment only for status or authority-bound changes, never agent-driven use/reservation counters. |
| `requester` | Yes | string | Bounded safe actor label; never a credential. |
| `operation` | Yes | string | Broker-owned opaque classification. Hosts may display/filter it within a source but must not compare its semantics across sources. |
| `status` | Yes | enum | Common lifecycle state. |
| `requested_at` | Yes | timestamp | Immutable UTC RFC 3339 timestamp. |
| `pending_expires_at` | Yes for pending | timestamp | Deadline after which approval cannot activate the request. |
| `active_expires_at` | Active only | timestamp | Deadline after which active authority is unusable. |
| `requested_duration_seconds` | Yes | integer | Positive requested lifetime starting when approval commits. |
| `requested_max_uses` | Yes | integer | Positive requested committed-use limit. |
| `granted_max_uses` | After approval | integer | Effective approved use limit after narrowing. Immutable once approval commits. |
| `used_count` | Yes | integer | Permanently committed uses; excludes private reservations. |
| `request_reason` | No | string | Broker-sanitized request rationale. |
| `decided_at` | After decision | timestamp | Time the latest operator transition committed. |
| `decided_by` | After decision | string | Authenticated broker operator principal. |
| `decided_on_behalf_of` | No | string | Bounded audit-only human label asserted by a trusted host. |
| `decision_reason` | After decision | string | Bounded audit rationale. |
| `presentation` | Yes | object | Display-only provider projection. |
| `presentation_unavailable` | No | boolean | True only when generic fallback presentation replaced a failed provider presenter. |
| `allowed_actions` | Yes | enum array | Revision-specific actions currently offered; advisory until the broker atomically validates the command. Empty is valid. |
| `approval_bounds` | When approvable | object | Revision-specific maximums for common approval narrowing. |

Internal reservation counts stay private. They are an execution-settlement
mechanism, not a portable approval concept. The common `used_count` reports
only durable committed uses and advances independently of `revision`.

`requested_duration_seconds` and `requested_max_uses` are immutable. Approval
stores effective bounds separately: `active_expires_at` carries effective
duration, and `granted_max_uses` carries effective uses. The durable grant model
therefore stores original-request fields and never overwrites them during
narrowing. Cutover starts with fresh V1 state after all existing authority has
been revoked or allowed to expire; unverifiable retained records are not read.

Keeping usage counters out of `revision` is a security and liveness invariant.
An agent must not be able to starve emergency revocation by continuously
reserving or committing uses and racing the operator's expected revision.

### Common status vocabulary

```text
pending -> active | denied | canceled | expired
active  -> consumed | revoked | expired
denied, canceled, expired, consumed, revoked -> terminal
```

The implementation must retain the current Brokerkit semantics for ambiguous
execution and retained reservations. Those states fail closed internally. If
an operator-visible intervention is later required, it should be introduced as
a separately specified recovery action rather than leaking reservation flags
into V1.

### Safe presentation

```json
{
  "risk": "critical",
  "title": "Merge pull request",
  "summary": "Merge a reviewed branch into the protected default branch.",
  "facts": [
    {"label": "Repository", "value": "osolmaz/gh-broker"},
    {"label": "Pull request", "value": "#42"}
  ]
}
```

`risk` is `unknown`, `low`, `medium`, `high`, or `critical`. The specification
must define it as a conservative display and sorting hint based on privilege,
blast radius, reversibility, and destructive potential. It never changes
policy or enables an action. Unknown is the default.

`title`, `summary`, and facts are bounded inert text. V1 has no Markdown, HTML,
URL, image, button, form, code execution, or arbitrary component type. Facts
are ordered label/value pairs because the provider is best placed to explain
its own operation while the host remains provider-neutral.

Brokerkit validates byte bounds, UTF-8, control characters, list size, and
single-line fields. Invalid presentation falls back to generic wording and sets
`presentation_unavailable` rather than hiding the request.

The current public `plan_hash` should not become a V1 security primitive.
Revision-checked decisions already bind an operator action to canonical stored
state. Brokers may keep plan digests internally and in secret-safe audit data.
A public digest should be added only after a concrete cross-broker consumer and
canonicalization contract exist.

### Unknown fields and extensions

Unknown-field behavior is directional:

- Servers reject unknown fields in client input, including decision bodies,
  query parameters, and any future command resource. Input fails closed.
- Clients ignore unknown fields in authenticated response objects while
  preserving the known V1 fields. Trusted hosts drop unknown fields when they
  build the browser projection and never render or authorize from them.

This keeps commands reviewable without making every additive response field a
wire-major break. Conformance must test both rejection of unknown input and
tolerant parsing plus dropping of unknown output.

V1 should not include a generic `metadata`, `extra`, or provider extension bag
in browser-facing resources. Provider-specific operator facts go through the
bounded presentation. If a future trusted machine consumer proves a need for
provider data, add an optional reverse-DNS extension map in a later compatible
revision with these rules:

- Brokerkit never interprets it for policy, decisions, or execution.
- Generic hosts never render it and drop it at the browser boundary.
- The provider owns its independent schema, version, redaction, and bounds.
- The host allowlists each understood extension schema explicitly.
- Unknown extensions are dropped at the browser boundary.

## Discovery And Versioning

The configured operator endpoint exposes:

```http
GET /.well-known/brokerkit-operator
```

Minimal response:

```json
{
  "api_version": "brokerkit.io/operator/v1"
}
```

The host owns source identity and label, so discovery does not return them.
Broker-wide action/capability lists are intentionally omitted: V1 fixes the
event transport, and each request exposes its current allowed actions and
approval bounds. This removes duplicate sources of truth.

The API version identifies the wire contract, not a broker release or provider
API. V1 resources do not repeat it in every body because the route/media type
already selects the schema. An unsupported major version is a hard registration
failure. Additive behavior must be representable without changing the meaning
of existing required fields. A future breaking wire change requires another
coordinated whole-system cutover; one process does not serve two majors.

Provider adapters version independently of the common protocol. A new GitHub
operation or Hugging Face transfer mode does not require a Brokerkit protocol
version when it remains behind the provider classifier and safe presenter.

## Operator Routes

```text
GET  /.well-known/brokerkit-operator
GET  /healthz
GET  /readyz

GET  /api/operator/v1/requests
GET  /api/operator/v1/requests/{id}
GET  /api/operator/v1/events
POST /api/operator/v1/requests/{id}/approve
POST /api/operator/v1/requests/{id}/deny
POST /api/operator/v1/requests/{id}/cancel
POST /api/operator/v1/requests/{id}/revoke
```

These routes exist only on the protected operator listener or Unix socket.
They must never be mounted on the agent listener. Every response uses
`Cache-Control: no-store`, a JSON content type, request correlation, bounded
bodies, explicit timeouts, and secret-safe errors.

Discovery and every `/api/operator/v1/*` route require operator
authentication. `healthz` and `readyz` are unauthenticated so a local process
supervisor can probe them, but they return status only and no version, broker,
dependency, path, credential, or provider detail. Conformance must pin this
split so brokers do not diverge.

Only the versioned V1 operator routes are mounted after cutover. Existing
internal lifecycle/store packages may be reused, but no unversioned operator
handler, parser, route alias, or dual-write path remains reachable.

## Queries And Pagination

List filters remain bounded and common:

```text
status
requester
operation
target_kind
target.<provider-registered-field>
cursor
limit
```

Provider target filters are passed only to the broker that owns them; an
aggregating host must not assume the same field means the same thing elsewhere.

Response:

```json
{
  "requests": [],
  "next_cursor": "opaque",
  "event_cursor": "opaque-first-page-position"
}
```

Omitted `next_cursor` means the page is terminal. A separate `has_more` boolean
is unnecessary and risks contradictory state. The opaque pagination cursor
binds source, filter set, and ordering. It is not parsed, combined, compared,
or reused with different filters.

`event_cursor` appears only on the cursor-less first page and is captured under
the same store lock as that page. Later pages omit it. After completing live
pagination, the host starts or resumes the event stream from the first page's
cursor and treats every later event as an invalidation to reconcile or re-fetch.
This closes the list-then-watch race even when a first-page item changes while
later pages are being read. Using a cursor from the last page would miss that
change and is forbidden.

V1 does not promise a stable multi-page snapshot. Pages are live bounded
queries. The pagination cursor binds filters and ordering, while the first-page
event cursor supplies the recovery boundary for concurrent mutations.

Ordering is `requested_at` descending, then `id` as a deterministic broker-side
tiebreaker. `cursor_expired` tells the host to restart the bounded query.

## Decisions

Approval request:

```json
{
  "expected_revision": 3,
  "idempotency_key": "01JZ8M7G1WPEY7NQ8B6J3D2A4V",
  "decision_reason": "Reviewed the immutable broker plan",
  "on_behalf_of": "onur",
  "constraints": {
    "duration_seconds": 300,
    "max_uses": 1
  }
}
```

`deny`, `cancel`, and `revoke` use the same body without `constraints`.

Rules:

- `expected_revision` is required and compared atomically.
- `expected_status` is omitted because revision plus route transition rules is
  the single concurrency authority.
- `idempotency_key` is required for safe recovery from lost responses.
- A key is scoped to authenticated operator, request id, and action.
- The server strictly decodes then normalizes the logical command. JSON key
  order and insignificant whitespace do not matter; optional-field presence,
  strings, numbers, and constraint values do. The idempotency record stores a
  hash of that normalized command.
- Reuse with the same normalized command returns the original committed result
  and marks the response as an idempotency replay. That representation may be
  stale because the grant can expire, be consumed, or be revoked afterward; it
  acknowledges the original commit, and the host must fetch current state.
- Reuse with different content returns `idempotency_conflict`.
- Failed, rejected, or conflicting attempts write no idempotency record and are
  revalidated normally on retry.
- The broker retains decision idempotency records for at least the longer of
  request retention or 24 hours after the terminal decision.
- `decision_reason` is bounded UTF-8 text and is persisted as audit-sensitive
  data.
- `on_behalf_of` is an optional bounded audit-only human label asserted by the
  trusted host. It never participates in authentication or authorization. The
  broker records both the authenticated operator principal and this assertion;
  `decided_by` remains the authenticated principal and the safe response may
  expose a separate `decided_on_behalf_of` field.
- Approval constraints may only narrow the current `approval_bounds`.
- No decision route accepts operation, target, attrs, provider input, plan,
  presentation, requester, or expiry timestamps.
- Revision/token validation, activation validation, transition, durable
  lifecycle event, and idempotency record commit in one store transaction and
  one durable write. Idempotency records live in the same durable unit as the
  grants, so a crash cannot commit a transition without its replay record.
- External audit export occurs after that commit and is best effort. Export
  failure produces the existing safe diagnostic but cannot roll back or make a
  committed decision appear uncommitted.

## Durable Events

```json
{
  "cursor": "opaque",
  "kind": "request.approved",
  "request_id": "01JZ8M41SC3QH12M7S4W8R2Q5N",
  "revision": 4,
  "status": "active",
  "occurred_at": "2026-07-11T12:01:00Z",
  "used_count": 0
}
```

V1 wire event kinds are explicitly:

```text
request.created
request.approved
request.denied
request.canceled
request.expired
request.consumed
request.revoked
request.updated
```

`request.updated` reports a committed-use-count change without advancing the
decision revision. Reservation and execution-settlement kinds such as
`grant.reserved`, `grant.released`, and `execution.ambiguous` remain internal;
they are not part of the V1 wire vocabulary. The event is an
invalidation/reconciliation signal, not a full materialized request. The host
applies `max(current, event.used_count)` for monotonic counters and fetches the
current item when presentation, status, bounds, or allowed actions may have
changed.

Events are ordered only within one broker and delivered at least once. The SSE
`id` equals `cursor`; the JSON object repeats it for non-SSE fixtures. The host
stores a cursor per registered source and resumes with `Last-Event-ID`.
Duplicate cursors are ignored. Revisions older than the host's current item are
ignored. Unknown event kinds are logged safely, the cursor is advanced, and
the referenced request is refreshed when possible. `410 cursor_expired`
requires a bounded list refresh before reconnect.

The SSE stream sends a comment heartbeat at least every 15 seconds while idle
so proxies and hosts can distinguish quiet from dead connections. It may send a
bounded `retry:` hint. V1 omits the SSE `event:` field; `kind` already exists in
JSON, and clients listen to ordinary message dispatch. Heartbeats carry no ids
or data and do not advance the durable cursor.

There is no cross-broker global cursor, order, or exactly-once claim. A hub may
fan events into one UI stream, but its envelope supplies the local source id.

## Error Contract

```json
{
  "error": {
    "code": "revision_conflict",
    "message": "The request changed; refresh before deciding.",
    "correlation_id": "01JZ8MBM2TT9V6R2Q0FGQH8M4Y",
    "current": {}
  }
}
```

Stable common codes:

```text
invalid_request
unauthorized
forbidden
not_found
revision_conflict
invalid_transition
constraint_exceeded
idempotency_conflict
cursor_expired
rate_limited
temporarily_unavailable
internal_error
```

Every internal failure maps once into the closed V1 error vocabulary.
`invalid_cursor`, `invalid_query`, and malformed commands map to
`invalid_request`; an exceeded approval bound maps to `constraint_exceeded`;
an invalid state transition maps to `invalid_transition`. A committed decision
returns success even if post-commit audit export fails; export failure is
surfaced only through the safe diagnostic and metrics.

`current` is allowed only for a revision conflict after operator authentication
and contains only the safe request resource. Provider upstream failures map to
one common code and remain detailed only in provider-owned secret-safe audit
fields. Messages never contain upstream bodies, headers, credentials, raw
plans, stack traces, or filesystem paths. `Retry-After` is used for bounded
rate limiting and temporary unavailability. Retry behavior is defined by HTTP
status plus the stable error code; V1 does not add a `retryable` boolean that
could contradict those semantics.

## Provider Interfaces

The in-process Brokerkit interfaces should separate lifecycle from provider
behavior:

```go
type Presenter interface {
    Present(context.Context, grants.Grant) (Presentation, error)
}

type ActivationValidator interface {
    ValidateActivation(context.Context, grants.Grant, ApprovalConstraints) error
}
```

`Presenter` remains display-only. `ActivationValidator` is optional and
provider-owned; it lets a broker fail closed before activation if its stored
canonical plan is missing, corrupt, inconsistent, or incompatible with the
approved narrowing. It returns no plan and exposes no credentials.

The validator must not be attached only to an HTTP handler. Brokerkit should
introduce one `DecisionService` used by operator HTTP decisions, Telegram and
other approval-channel callbacks, CLI decisions, tests, and future transports.
It supports two explicit bindings:

- Revision-bound commands carry `expected_revision` and `idempotency_key` and
  are used by the operator API and trusted host.
- Token-bound commands carry Brokerkit's one-time decision token and are used
  by Telegram or equivalent approval channels. They do not pretend to carry a
  revision or separate idempotency key. The single-use token is their replay
  protection and is sound only because pending decision-relevant content is
  immutable; reclassification creates a new request and token.

Both bindings call the same activation validator for approval and commit
through the same transition/event/audit path. The approval-channel `Decider`
must be implemented over `DecisionService`, not installed beside it. Provider
execution performs a fresh provider-owned validation because upstream state may
change after approval.

Low-level store transition methods remain implementation mechanics. First-party
brokers and transports must not call them directly once `DecisionService`
exists. Conformance must prove every supported decision transport converges on
the same `DecisionService` and activation validator. Revision-bound transports
additionally use the durable idempotency record; token-bound transports rely on
atomic single-use token consumption.

For aggregation, define a provider-neutral client interface:

```go
type Source interface {
    Discover(context.Context) (Descriptor, error)
    List(context.Context, Query) (Page, error)
    Get(context.Context, string) (Request, error)
    Decide(context.Context, string, Action, Decision) (Request, error)
    Watch(context.Context, string) (EventStream, error)
    Health(context.Context) error
}
```

The production HTTP client implements `Source`. `operatorfake` implements the
same behavior for consumer tests. Provider brokers do not implement a separate
HF or GitHub source interface; they mount Brokerkit's V1 handler with their
presenter and canonical store.

## Agent Boundary

V1 deliberately standardizes the operator side, not one universal agent HTTP
API. Git smart HTTP, typed inference, pull-request JSON, bucket operations, and
Unix execution have materially different transport, streaming, body, and
failure semantics. Each broker authenticates, parses, validates, and classifies
its agent-facing request before creating a canonical `grants.Request`.

Brokerkit may keep provider-neutral internal request/grant types and policy
interfaces. It must not expose an agent endpoint that accepts arbitrary
operation, target, attrs, provider payload, or plan merely to make all brokers
look alike. A future agent SDK can standardize discovery and status polling
after concrete cross-provider use cases exist, without weakening the
provider-owned request boundary.

## Static Registration And Aggregation

A trusted host registry entry contains:

```yaml
id: hf-primary
label: Hugging Face
endpoint: http://127.0.0.1:8081
operatorCredentialRef: env:MLCLAW_HF_BROKER_OPERATOR_SECRET
enabled: true
```

This is host configuration, not a broker wire resource. The concrete config
schema belongs to the host repository, but Brokerkit should publish the rules:

- ids are unique and immutable within one host installation;
- endpoints are operator-configured, never browser-supplied;
- credentials are references resolved server-side and never serializable to a
  browser response;
- production remote endpoints require authenticated TLS, mTLS, or a protected
  private network with operator authentication;
- redirects are disabled by default;
- DNS resolution and connection targets are constrained against SSRF;
- one source failure cannot block, reorder, or erase other sources; and
- removing a source preserves its cursor only as inactive host state.

The registry is explicit and static for V1. Do not load arbitrary shared
libraries, execute plugin manifests, or discover brokers from the network.

The aggregation layer assigns every response a host-local `source_id` after
successful authentication to its configured source. It uses bounded parallel
fetches, per-source deadlines, retry budgets, jittered reconnects, circuit
breaking, and backpressure. Results include per-source freshness and health;
partial failure returns healthy results plus explicit source errors rather than
an empty global inbox.

## Browser Boundary

The trusted host may return this normalized envelope to its browser:

```json
{
  "source_id": "hf-primary",
  "request": {"id": "01JZ...", "revision": 3}
}
```

The browser sends only:

```json
{
  "source_id": "hf-primary",
  "request_id": "01JZ...",
  "expected_revision": 3,
  "idempotency_key": "01JZ...",
  "decision_reason": "Reviewed",
  "constraints": {"duration_seconds": 300, "max_uses": 1}
}
```

The host resolves the registered source and server-held operator credential.
It derives `on_behalf_of` server-side from its authenticated browser session and
injects that audit-only label into the broker command. It discards any
browser-supplied attribution and all other extra browser fields. It never
accepts a browser endpoint, header, credential reference, operation, target,
plan, extension, or provider payload.

## Canonical Schema Artifacts

Brokerkit should own:

```text
spec/operator/v1/openapi.yaml
spec/operator/v1/schema/discovery.json
spec/operator/v1/schema/request.json
spec/operator/v1/schema/page.json
spec/operator/v1/schema/decision.json
spec/operator/v1/schema/event.json
spec/operator/v1/schema/error.json
operatorapi/testdata/v1/
```

The OpenAPI document is the route source of truth. JSON Schemas use closed
objects, explicit integer bounds, exact enums, RFC 3339 UTC strings, maximum
UTF-8 byte rules documented where JSON Schema cannot enforce them, and realistic
valid/invalid examples. Go types and any TypeScript client are generated or
checked against these artifacts; hand-written runtime validation remains
authoritative for security limits.

## Conformance Suite

`conformance.RunOperatorV1` should run against every real broker handler and
prove:

- discovery and version rejection;
- operator auth on discovery and every operator API route, plus status-only
  unauthenticated health/readiness;
- rejection of agent credentials on operator routes;
- absence of operator routes on the agent listener;
- no-store headers and strict content types;
- unknown input rejection plus tolerant/drop-only unknown response handling;
- all field/list/body/UTF-8 bounds;
- generic presentation fallback;
- each valid and invalid state transition;
- atomic revision conflict behavior;
- decision idempotency replay and mismatch conflict;
- atomic transition/event/idempotency persistence with no torn crash window;
- revision-bound and token-bound commands converging on the same decision
  service and activation validator;
- approval can narrow but never widen duration or uses;
- decisions cannot replace provider state;
- stable pagination and filter-bound opaque cursors;
- omission of `next_cursor` on terminal V1 pages;
- first-page event-cursor recovery across multi-page concurrent mutation;
- SSE reconnect, duplication, retention, and cursor expiry;
- unknown event-kind recovery;
- audit correlation without secret leakage;
- upstream/provider errors mapped to stable safe errors;
- request cancellation and active grant revocation;
- terminal records remain immutable except retention metadata; and
- process restart preserves decisions, idempotency, events, and cursors.
- revocation succeeds while an agent continuously reserves and commits uses;
- presenter fallback cannot change actions or approval bounds; and
- a fresh cutover state cannot load any unsupported record shape.

Adversarial fixtures should attempt HTML/script injection, control characters,
oversized facts, secret-shaped values, credential reuse, stale decisions,
duplicate actions, cursor swapping, filter changes, malformed timestamps,
fractional integers, unsupported versions, and SSRF through registration input.
The integration suite should also run SSE through an idle-terminating or
buffering proxy to prove heartbeat and reconnect behavior, and force event-log
truncation during a burst to prove cursor-expiry refresh.

## Observability And Audit

Common metrics should include request totals by source/action/result, decision
latency, revision conflicts, idempotency replays/conflicts, source health,
query latency, SSE reconnects, cursor expiry, presenter fallback, event lag,
circuit state, and dropped/unknown events. Labels must be bounded and must not
include request ids, reasons, targets, credentials, or arbitrary provider data.

Every decision audit record correlates authenticated operator, host source id
where available, broker request id, prior/current revision and status, action,
constraints, idempotency outcome, timestamp, and export result. The broker's
committed lifecycle remains authoritative if an external audit export fails;
the response exposes a safe diagnostic header without pretending the decision
failed.

Distributed tracing may carry a generated correlation id across host and
broker. It must not carry authorization headers, upstream request bodies, raw
plans, or provider credentials.

## Failure And Recovery Semantics

- Authentication failure is terminal and does not retry automatically.
- Revision and transition conflicts require refresh, not blind retry.
- Rate limiting honors `Retry-After` within a host retry budget.
- Network loss after a decision uses the same idempotency key until a result is
  recovered.
- Presenter failure does not hide the request or enable extra actions.
- A broker that cannot validate its canonical plan fails closed before
  activation/execution.
- SSE loss falls back to cursor resume, then bounded refresh on expiry.
- One unhealthy broker remains visible as stale/unavailable while others work.
- The hub never synthesizes approval success from cached state.
- There is no distributed transaction across brokers because one decision targets
  exactly one source and one request.

## Implementation Order For The Single Cutover

The following work is completed in dependency order on one implementation
branch. None of the intermediate commits is a supported deployment:

1. approve the ownership boundary, V1 resource, revision semantics, host source
   identity, attribution, and canonical plan ownership in ADRs;
2. add canonical OpenAPI, closed JSON Schemas, examples, error mappings, Go wire
   types, protocol discovery, and generation/fixture drift checks;
3. implement fresh V1 durable request fields, same-store decision idempotency,
   and one `DecisionService` containing provider activation validation;
4. mount only V1 routes, implement filter-bound list cursors, atomic first-page
   `event_cursor`, SSE, readiness, the Go source client, and fake;
5. add `RunOperatorV1`, fuzzing, race/restart/coverage/leak tests,
   threat model, and partial-source failure tests;
6. implement and test HF, GH, and sudo canonical plan binding/presentation on
   the same contract;
7. implement the independent OpenClaw plugin described by the companion plan
   using only the pinned released public plugin API;
8. start from fresh state, run the complete broker/plugin/browser/channel/live
   matrix, and build all release artifacts from the same green commit; and
9. replace the old deployment atomically with the complete V1 system and
   archive the source repositories.

The implementation is releasable only when every item and acceptance criterion
passes. There is no dual-route, dual-state, or mixed-source operating window.

## Release And Version Policy

- Freeze schema fixtures before the first V1 release candidate.
- Use semantic versioning for Brokerkit releases independently of wire
  `api_version`.
- Treat a required field, changed enum meaning, changed transition, changed
  error mapping, or changed idempotency/cursor behavior as a wire major change.
- Treat new event kinds as additive only because clients advance unknown kinds
  safely while refreshing the referenced request.
- Serve one operator wire major. A breaking change is another coordinated
  cutover, not a second concurrently served route family.
- Publish an artifact matrix that identifies the single BrokerKit API and
  minimum OpenClaw host version supported by each complete release.

## Monorepo Work Breakdown

The components below are logical ownership boundaries inside the focused
BrokerKit monorepo. The history-preserving repository consolidation, target
layout, release model, and cutover procedure are defined in
`docs/2026-07-11-monorepo-consolidation-plan.md`.

### Brokerkit

- ADRs and V1 specification artifacts;
- versioned handler/client/fake;
- decision idempotency storage;
- request projection and safe presentation rules;
- cursor binding and event behavior;
- conformance, fuzzing, threat model, and release documentation;
- optional reference registry/aggregation primitives; and
- cutover validation and release instrumentation.

### hf-broker

- Brokerkit upgrade and V1 mount;
- HF canonical plan validation and internal digest/audit binding;
- HF presenter, risk, and safe facts;
- HF error mapping, conformance, and live smoke; and
- no movement of token, Hub, Router, Git/LFS/Xet, mirror, or bucket logic.

### gh-broker

- Brokerkit upgrade and V1 mount;
- GitHub canonical plan validation and internal digest/audit binding;
- GitHub presenter, risk, and safe facts;
- GitHub error/rate-limit mapping, conformance, and live smoke; and
- no movement of App, installation, Git, REST/GraphQL, PR, webhook, ruleset, or
  branch-protection logic.

### sudo-broker

- new implementation on the V1 contract with no alternate control plane;
- exact structured plans for declared commands, bounded environment, cwd, and
  runtime;
- separate least-privileged process and host-specific execution backends;
- sudo-specific presentation, audit, conformance, and adversarial tests; and
- no arbitrary shell-string execution or privilege inherited by other
  monorepo artifacts.

### OpenClaw plugin

- explicit broker registration and operator SecretRefs;
- per-source list/watch cursors, health, reconciliation, and safe projection;
- compact Gateway Approvals tab registered through the public plugin API;
- authenticated `/brokerkit` commands and generic public outbound adapters;
- plugin-owned SQLite containing only cursors, opaque handles, generic routing
  coordinates, and delivery bookkeeping;
- broker authority retained across plugin restarts and lost responses; and
- no provider executor, upstream credential, or channel-specific transport
  implementation.

## Acceptance Criteria

The platform is ready when:

- a new provider broker can adopt the common operator protocol without adding
  provider code to Brokerkit;
- a trusted host can register HF and GH with the same `Source` interface;
- the common UI uses no HF/GH operation switch;
- each broker still owns and validates a different canonical execution plan;
- every decision is revision-bound or single-use-token-bound, replay-safe,
  bounded, activation-validated, and audit-correlated;
- no browser or common API receives an upstream credential or executable plan;
- one broker can fail, restart, rate-limit, or expire its cursor without taking
  down other brokers;
- schema, conformance, security, race, restart, and provider tests pass;
- the coordinated fresh-state cutover is documented and exercised; and
- adding provider-specific behavior changes only that broker unless a proven
  common concept is deliberately promoted into a future protocol version.

## Decisions To Keep Explicit

The recommended V1 decisions are:

- host-assigned source identity, not broker-asserted identity;
- one canonical Brokerkit lifecycle, not a hub-owned lifecycle;
- versioned routes with one discovery discriminator;
- no generic provider extension payload in browser-facing V1;
- bounded plain-text presentation facts, not schema-driven arbitrary UI;
- defined but non-authoritative risk classification;
- revision as the canonical plan-binding precondition;
- required decision idempotency for lost-response recovery;
- private execution reservations;
- per-source durable cursors and no global ordering; and
- explicit static registration before any dynamic discovery or plugin loading.

These choices make the platform general by keeping the stable core small, not
by making every provider detail generic.

## Deliberately Deferred

V1 defers multi-party/quorum approval, provider-typed narrowing such as money
or resource caps, narrowing an already active grant, renewal/extension, and an
operator recovery action for ambiguous retained execution. The closed V1 state
and action vocabulary means quorum approval may require a wire major version;
record that honestly rather than implying it is an additive field.

Until a recovery action exists, a provider presenter should surface a bounded
`Needs attention` fact when internal ambiguous settlement makes apparently
active authority unusable. Per-client pending-request quotas remain
broker-owned but belong in the V1 security checklist to prevent cheap operator
inbox flooding.
