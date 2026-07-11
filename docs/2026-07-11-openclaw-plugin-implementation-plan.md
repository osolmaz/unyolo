# OpenClaw BrokerKit Plugin Implementation Plan

Date: 2026-07-11

Status: proposed; implementation-ready after the host seams in
`docs/2026-07-11-openclaw-host-seams-plan.md` are released

Plugin id: `brokerkit`

Npm package: `openclaw-brokerkit`

Monorepo path: `plugins/openclaw`

## What The Operator Configures

The smallest valid OpenClaw configuration registers one BrokerKit source with
one server-resolved operator credential:

```json5
{
  plugins: {
    entries: {
      brokerkit: {
        enabled: true,
        config: {
          brokers: [
            {
              id: "hf-primary",
              label: "Hugging Face",
              endpoint: "http://127.0.0.1:8081",
              operatorCredential: {
                source: "env",
                provider: "default",
                id: "HF_BROKER_OPERATOR_SECRET"
              }
            }
          ]
        }
      }
    }
  }
}
```

The Gateway popover works with only this configuration. To mirror approval
requests into OpenClaw channels, the operator separately uses OpenClaw's
existing delivery configuration:

```json5
{
  approvals: {
    plugin: {
      enabled: true,
      mode: "targets",
      targets: [
        { channel: "discord", to: "123456789012345678" },
        { channel: "telegram", to: "123456789" }
      ]
    }
  }
}
```

The plugin does not define Discord, Telegram, Slack, Matrix, WhatsApp, Signal,
iMessage, or future channel configuration. OpenClaw owns channel rendering,
routing, approver authorization, buttons/reactions/commands, and resolution
updates.

## Outcome

Build one independent OpenClaw plugin that:

- registers any number of conforming BrokerKit operator sources from static
  OpenClaw configuration;
- resolves each source's operator credential through OpenClaw SecretRefs;
- consumes BrokerKit Operator V1 list and SSE APIs;
- keeps a bounded in-memory safe projection plus durable per-source cursors and
  approval-mirror records;
- renders a compact Approvals popover tied to the Gateway Settings button;
- submits revision-bound approve, deny, cancel, and revoke decisions;
- mirrors pending requests through OpenClaw's existing approval/channel system;
- reconciles restart, timeout, expiry, stale revision, lost response, and one
  unavailable source without inventing authority; and
- contains no Hugging Face, GitHub, sudo, MLClaw, or channel-specific branch.

BrokerKit brokers remain the only durable authority. OpenClaw is an operator UI
and decision-delivery host.

## Hard Boundaries

The plugin must never:

- receive or expose an upstream Hugging Face token, GitHub credential, sudo
  privilege, provider request body, or canonical execution plan;
- accept a broker endpoint, operator credential, provider payload, operation,
  target, `on_behalf_of`, or request revision from an untrusted location other
  than the fields explicitly allowed in a decision command;
- persist resolved operator credentials;
- turn an OpenClaw timeout, restart, channel failure, or plugin disable into a
  broker deny/revoke;
- offer `allow-always` for a broker request;
- execute provider operations itself;
- use OpenClaw private imports, raw state tables, raw approval managers, or
  Gateway RPC loopback calls;
- implement a second durable request/grant lifecycle; or
- silently run against an OpenClaw host missing required public SDK seams.

## Required Contracts

### BrokerKit Operator V1

Every configured endpoint must provide:

```text
GET  /.well-known/brokerkit-operator
GET  /api/operator/v1/requests
GET  /api/operator/v1/requests/{id}
GET  /api/operator/v1/events
POST /api/operator/v1/requests/{id}/approve
POST /api/operator/v1/requests/{id}/deny
POST /api/operator/v1/requests/{id}/cancel
POST /api/operator/v1/requests/{id}/revoke
```

Discovery must return exactly the supported API discriminator:

```json
{ "api_version": "brokerkit.io/operator/v1" }
```

The source id and label come only from OpenClaw configuration. A remote broker
cannot assert or replace them. The composite request identity is
`(sourceId, brokerRequestId)`.

The request projection used by this plugin contains the common fields defined
in `docs/2026-07-11-universal-broker-platform-plan.md`: opaque id, positive
decision revision, requester, operation, status, request/expiry timestamps,
requested/granted bounds, used count, safe presentation, allowed actions, and
approval bounds. Unknown response fields are ignored after required fields are
validated. Unknown command fields are rejected.

### OpenClaw host

The minimum host must publicly support:

- background plugin services;
- scoped plugin Gateway methods;
- manifest-declared SecretRef inputs;
- manifest-gated shared keyed state for this installed plugin;
- background approval requests with pre-resolution settlement;
- settings descriptors rendered in the compact footer popover; and
- the credential-free plugin iframe bridge.

The exact minimum OpenClaw and plugin API versions are pinned only after the
host seams land. Registration must hard-fail with one actionable diagnostic on
an older host. There is no alternate implementation for older hosts.

## Package Layout

```text
plugins/openclaw/
  package.json
  openclaw.plugin.json
  tsconfig.json
  vite.config.ts
  index.ts

  src/
    config.ts
    constants.ts
    errors.ts
    plugin.ts

    brokerkit/
      generated/
        operator-v1.ts
        operator-v1.schema.ts
      client.ts
      error-map.ts
      sse.ts
      types.ts
      validate.ts

    registry/
      source-registry.ts
      source-runtime.ts
      source-state.ts

    reconcile/
      coordinator.ts
      list-refresh.ts
      event-loop.ts
      mirror-controller.ts
      decision-settler.ts
      backoff.ts

    state/
      keys.ts
      cursor-store.ts
      mirror-store.ts
      models.ts

    gateway/
      methods.ts
      snapshot.ts
      decision.ts
      actor.ts

    http/
      ui-route.ts
      security-headers.ts

    test/
      fake-clock.ts
      fake-openclaw.ts
      fake-source.ts
      fixtures.ts

  ui/
    index.html
    src/
      main.tsx
      app.tsx
      bridge.ts
      api.ts
      model.ts
      state.ts
      styles.css
      components/
        approval-card.tsx
        approval-detail.tsx
        broker-health.tsx
        decision-dialog.tsx
        empty-state.tsx
        error-state.tsx
        loading-state.tsx
        source-filter.tsx
    test/
    components.json

  test/
    config.test.ts
    client.test.ts
    sse.test.ts
    reconciliation.test.ts
    settlement.test.ts
    restart.test.ts
    gateway-methods.test.ts
    ui-route.test.ts
    manifest.test.ts
    integration.test.ts
```

Use TypeScript with strict mode. The service/runtime code stays dependency-light
and uses the platform `fetch`, streams, `AbortController`, Web Crypto, and
OpenClaw SDK types. The iframe UI may use React, Vite, Tailwind, and shadcn/Radix
source components because its bundle and DOM are isolated from OpenClaw's Lit
Control UI. It must not load CDN resources at runtime.

Do not create a separately published TypeScript SDK until there is an
independent consumer. Generated wire types remain internal to the plugin
package.

## Plugin Manifest

`openclaw.plugin.json` starts with this shape, updated to the final released
host contract names:

```json
{
  "id": "brokerkit",
  "name": "BrokerKit",
  "description": "Review and deliver approval requests from configured BrokerKit brokers.",
  "activation": { "onStartup": true },
  "configSchema": {
    "type": "object",
    "additionalProperties": false,
    "required": ["brokers"],
    "properties": {
      "brokers": {
        "type": "array",
        "minItems": 1,
        "maxItems": 32,
        "items": {
          "type": "object",
          "additionalProperties": false,
          "required": ["id", "label", "endpoint", "operatorCredential"],
          "properties": {
            "id": {
              "type": "string",
              "pattern": "^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$"
            },
            "label": { "type": "string", "minLength": 1, "maxLength": 64 },
            "endpoint": { "type": "string", "minLength": 1, "maxLength": 2048 },
            "operatorCredential": {
              "type": "object",
              "additionalProperties": false,
              "required": ["source", "provider", "id"],
              "properties": {
                "source": { "enum": ["env", "file", "exec"] },
                "provider": { "type": "string", "minLength": 1 },
                "id": { "type": "string", "minLength": 1 }
              }
            },
            "enabled": { "type": "boolean", "default": true }
          }
        }
      }
    }
  },
  "contracts": {
    "pluginStateNamespaces": {
      "brokerkit.cursors.v1": { "maxEntries": 32 },
      "brokerkit.mirrors.v1": { "maxEntries": 10000 }
    }
  },
  "configContracts": {
    "secretInputs": {
      "paths": [
        {
          "path": "brokers.*.operatorCredential",
          "expected": "string"
        }
      ]
    }
  }
}
```

The final SecretRef schema must reuse the exact OpenClaw manifest-supported
SecretInput schema rather than maintaining a divergent copy if the manifest
format exposes one.

`package.json` is private at the monorepo root but publishable in this
directory. It declares ESM, the built plugin entry, packaged UI assets, an
optional OpenClaw peer dependency, exact `openclaw.extensions`, install
metadata, `minHostVersion`, plugin API range, and npm/ClawHub release
metadata. The exact package name is `openclaw-brokerkit`; it returned npm
registry 404 on 2026-07-11. Claim it during the coordinated release and fail
the release rather than silently renaming it if npm no longer accepts it.

## Configuration Rules

### `brokers`

`brokers` is required and contains 1-32 source objects. Source order affects UI
tie-breaking only; it does not create authority or cross-source ordering.

Duplicate ids are invalid. Endpoint duplication is allowed because one
operator listener may expose separate configured identities, but the source id
must still be unique.

### `id`

The id is a stable local key, 1-63 characters, lowercase ASCII letters,
digits, and interior hyphens. It must not change when the label changes. A
changed id is a new source with a new cursor and mirror namespace.

Valid: `hf-primary`, `github-work`, `sudo-laptop`

Invalid: `HF`, `-github`, `github_1`, an endpoint URL

### `label`

The label is bounded display text. Normalize Unicode to NFC, trim surrounding
whitespace, reject control/bidi override characters and empty results, and
escape it in every HTML/message surface. It is not an identifier.

### `endpoint`

The endpoint is an absolute base URL parsed once at startup. It must:

- use HTTPS, or HTTP only with `localhost`, an IPv4 loopback address, or an IPv6
  loopback address;
- contain no username, password, query, or fragment;
- use a normalized path prefix with no dot-segment escape;
- disable HTTP redirects for every operator request;
- never come from the browser, broker response, event, or request body; and
- remain fixed in the immutable source runtime until config reload restarts it.

V1 does not add custom CA, client certificate, proxy, or arbitrary header
fields. Operators needing those features terminate them in trusted local
infrastructure or install trust in the host OS.

### `operatorCredential`

The source config value must be a structured SecretRef. Plaintext config is
rejected. OpenClaw resolves it only in the server runtime snapshot. The plugin
receives a non-empty resolved string for the Authorization header and never
stores, hashes, returns, interpolates into errors, or logs it.

An unresolved SecretRef makes only that source unavailable. Other sources and
the Gateway remain usable.

### `enabled`

Omitted means true. A false source is displayed as disabled, makes no network
request, owns no live approval mirror, and retains its cursor so re-enabling can
resume. Disabling a source cancels OpenClaw mirrors without denying broker
requests.

## Runtime Object Model

`BrokerkitPlugin` owns one immutable `SourceRegistry`, one reconciliation
coordinator, two keyed state namespaces, a current safe snapshot, and Gateway
method handlers.

Each `SourceRuntime` owns:

- normalized local id/label/endpoint;
- an in-memory resolved credential inaccessible to UI types;
- one bounded HTTP client;
- one event-loop AbortController;
- one serialized refresh queue;
- current safe request map keyed by opaque broker id;
- in-memory health/backoff state; and
- live OpenClaw approval handles keyed by request revision.

No provider subclass or provider-type discriminator exists. A new broker is
added through config after it passes Operator V1 conformance.

## Broker HTTP Client

The client uses these fixed defaults:

- discovery/connect timeout: 5 seconds;
- ordinary request timeout: 10 seconds;
- decision timeout: 15 seconds;
- response headers/body limits from the Operator V1 schema;
- no redirects;
- `Accept: application/json` for JSON and `text/event-stream` for events;
- `Authorization: Bearer <resolved operator credential>`;
- generated safe correlation id;
- no automatic decision retry except with the same idempotency key; and
- bounded exponential reconnect delay with full jitter from 1 to 30 seconds.

Authentication failure is terminal until configuration reload. Unsupported
discovery version is terminal. Rate limiting honors a bounded `Retry-After`.
Network and 5xx failures retry only reads/events. Decisions recover through the
same idempotency key and a current-request fetch.

The JSON decoder validates required V1 fields and limits before returning safe
types. It drops unknown response fields. Error parsing exposes only the closed
BrokerKit error code, safe message, correlation id, and optional current safe
request. Raw bodies and headers never enter UI/log errors.

## Durable Plugin State

The broker remains authoritative; durable plugin state is only delivery and
resume metadata.

### Cursor namespace

Namespace: `brokerkit.cursors.v1`

Key: source id

Value:

```ts
type CursorRecord = {
  cursor: string;
};
```

The cursor is opaque, at most the BrokerKit wire limit, and never parsed or
compared. The keyed-store entry already records creation time, so the value
does not duplicate a timestamp. Persist it only after the corresponding event has been accepted as an
invalidation and queued/applied for reconciliation. A cursor-expired response
deletes it only after a successful bounded refresh captures the replacement
first-page `event_cursor`.

### Mirror namespace

Namespace: `brokerkit.mirrors.v1`

Key:
`v1:<base64url(sourceId)>:<base64url(brokerRequestId)>`

The decoded components must fit the configured 63-byte source id and V1
128-byte request id limits. Keys never include display text.

Value:

```ts
type MirrorState = "offered" | "settling" | "stale" | "retryable_error";

type MirrorRecord = {
  revision: number;
  approvalId: string;
  state: MirrorState;
  decision?: "approve" | "deny";
  idempotencyKey?: string;
  updatedAtMs: number;
  errorCode?: string;
};
```

Conditional fields are valid only as follows:

- `decision` and `idempotencyKey` are required in `settling` and may be
  retained in `retryable_error`;
- they are absent in `offered` and `stale`;
- `errorCode` is present only for `retryable_error`;
- `approvalId` identifies an OpenClaw delivery mirror, never broker authority.

At startup all stored `offered` and `settling` records are treated as stale
until broker refresh proves the request still pending and a live OpenClaw
handle is re-established. Terminal or missing broker requests delete their
mirror records. Records older than 24 hours whose broker request is no longer
pending are pruned. No provider content, request snapshot, operator credential,
decision reason, or human attribution is stored here.

The schema has no separate version field because the namespace and key are
versioned. A future incompatible state shape uses a new namespace and performs
an explicit all-or-nothing cutover; V1 code never guesses an unknown shape.

## Startup And Reconciliation Algorithm

Startup is deterministic:

1. parse and strictly validate the source-form configuration;
2. resolve SecretRefs through the active OpenClaw runtime snapshot;
3. normalize endpoints and build immutable source runtimes;
4. open exactly the two declared keyed-state namespaces;
5. load cursor/mirror records and validate their closed shapes;
6. mark stored mirrors stale in memory without changing broker state;
7. run discovery for all enabled sources with bounded concurrency four;
8. for each healthy source, fetch the cursor-less first page, save its
   `event_cursor`, finish bounded live pagination, and materialize the safe
   request map;
9. reconcile stored mirrors against current broker requests;
10. start one SSE loop per healthy source from its committed cursor; and
11. become ready and serve the current snapshot to scoped Gateway callers.

One source failure does not abort startup after config/schema validation. The
source appears unavailable with a safe code. A corrupt plugin state entry is
quarantined/deleted only according to a documented closed rule and triggers a
full refresh; it never blocks broker decisions or grants authority.

### Event handling

For each SSE message:

1. enforce framing, line, event, and JSON limits;
2. ignore a duplicate cursor;
3. advance unknown event kinds safely and refresh the referenced request when
   possible;
4. ignore an older decision revision while applying monotonic
   `max(used_count)`;
5. fetch the current request when status, presentation, actions, or bounds may
   have changed;
6. update the safe in-memory map and mirror state;
7. persist the cursor after reconciliation work is accepted; and
8. expose the updated immutable snapshot to the next Gateway poll.

The event stream heartbeat deadline is 20 seconds, allowing the required
15-second broker heartbeat plus scheduling tolerance. Missing heartbeat,
invalid framing, body overflow, or connection loss aborts and reconnects with
backoff. `410 cursor_expired` performs a full list refresh before reconnect.

### Refresh serialization

Each source has one serialized refresh queue. Multiple events for the same
request coalesce to the newest known revision/counter. A full refresh supersedes
queued item refreshes. A source never has two concurrent decisions for the same
request revision.

## Approval Mirror Algorithm

A broker request is mirror-eligible when:

- status is `pending`;
- current time is before `pending_expires_at`;
- allowed actions include `approve` or `deny`; and
- the current `(request id, revision)` has no live approval handle.

The plugin builds bounded prompt text only from source label and safe BrokerKit
presentation:

- title: presentation title, truncated within the OpenClaw limit;
- description: source label, presentation summary, and at most the highest
  priority safe facts within the description limit;
- severity: `critical` for BrokerKit high risk, `warning` for medium, `info`
  for low;
- decisions: `allow-once` when approve is allowed, `deny` when deny is allowed;
- expiry: the earlier of broker pending expiry and OpenClaw maximum lifetime;
  and
- stable key: a hash-safe encoding of source id, request id, and revision.

Provider facts remain plain text. The plugin does not interpret repositories,
branches, models, buckets, pull requests, commands, money, or provider
extensions.

An OpenClaw mirror expires once for a request revision. The plugin does not
automatically spam a replacement for the same revision after ordinary timeout.
The Gateway panel offers **Send to channels again**, which calls
`brokerkit.resend`; a new broker revision is independently eligible.

When the broker request becomes active, denied, canceled, expired, consumed,
revoked, missing, or a different revision, cancel the live OpenClaw handle and
delete/replace the mirror record. Cancellation never submits a broker action.

## Channel Decision Settlement

OpenClaw calls the mirror's settlement callback before resolving its approval.

Map decisions:

| OpenClaw decision | Broker action |
| --- | --- |
| `allow-once` | `approve` |
| `deny` | `deny` |

The plugin derives a BrokerKit idempotency key from the OpenClaw settlement
`attemptId`, source id, request id, revision, and action. It persists the
settling mirror before the network call. It derives `on_behalf_of` from
OpenClaw's authenticated `resolvedBy` value, bounds/normalizes it, and never
accepts that field from browser or broker data.

Settlement outcomes:

- successful commit or same-command broker replay -> `committed`;
- revision conflict, terminal/missing request, action no longer allowed, or
  expired request -> refresh and return `superseded`;
- network loss -> retry the same broker command/idempotency key once through
  recovery; if still unknown, fetch current state;
- current state proves the requested transition committed -> `committed`;
- current state proves it did not commit and the error is transient ->
  `retryable`;
- authentication/version/configuration failure -> source unavailable and
  `superseded`, because retrying the operator button cannot repair it; and
- unclassifiable result -> fail closed as `retryable`, retain correlation, and
  never claim authority.

The BrokerKit activation validator remains inside the broker's one decision
service. Neither OpenClaw nor this plugin bypasses or recreates it.

## Gateway Methods

Register exactly three plugin-owned methods, all scoped to
`operator.approvals`.

### `brokerkit.snapshot`

Request: closed empty object.

Response:

```ts
type BrokerkitSnapshot = {
  sources: Array<{
    id: string;
    label: string;
    state: "ready" | "degraded" | "unavailable" | "disabled";
    errorCode?: string;
  }>;
  requests: Array<{
    sourceId: string;
    request: BrokerkitOperatorV1Request;
    mirror?: {
      state: MirrorState;
      errorCode?: string;
    };
  }>;
};
```

Return only safe in-memory projections. Sort pending first, then
`requested_at` descending, then configured source order, then broker id.

### `brokerkit.decide`

Request:

```ts
type BrokerkitDecisionCommand = {
  sourceId: string;
  requestId: string;
  expectedRevision: number;
  action: "approve" | "deny" | "cancel" | "revoke";
  idempotencyKey: string;
  reason?: string;
  constraints?: {
    durationSeconds?: number;
    maxUses?: number;
  };
};
```

Rules:

- reject unknown fields and non-canonical numbers;
- source/request/revision/action must match the current safe cache and current
  broker fetch before submission;
- action must appear in `allowed_actions`;
- constraints are valid only for approve and may only narrow advertised bounds;
- idempotency key is a UI-generated UUID/ULID, 16-128 safe characters, reused
  for a retry of the identical command;
- reason is optional bounded UTF-8, maps to BrokerKit `decision_reason`, and is
  never added automatically;
- actor attribution comes from authenticated Gateway context, never params;
- endpoint and credential come only from the registry; and
- response maps to this closed safe result:

```ts
type BrokerkitDecisionResult =
  | {
      ok: true;
      request: BrokerkitOperatorV1Request;
    }
  | {
      ok: false;
      code:
        | "invalid_request"
        | "source_unavailable"
        | "request_changed"
        | "action_unavailable"
        | "broker_rejected"
        | "temporary_failure";
      request?: BrokerkitOperatorV1Request;
    };
```

`request` is the resulting authoritative safe projection on success and the
latest safe projection when an error such as `request_changed` can provide it.
The UI maps closed codes to local copy; broker error messages are not forwarded.

### `brokerkit.resend`

Request:

```ts
{
  sourceId: string;
  requestId: string;
  expectedRevision: number;
}
```

The request must still be pending and mirror-eligible. Cancel any stale local
handle, create a fresh delivery attempt, persist it, and return its safe state.
It does not change broker authority.

## Gateway UI

The plugin registers:

```ts
api.session.controls.registerControlUiDescriptor({
  surface: "settings",
  placement: "footer-popover",
  id: "approvals",
  label: "Approvals",
  description: "Review authority requested by connected brokers.",
  icon: "shield-check",
  path: "/plugins/brokerkit/ui/",
  requiredScopes: ["operator.approvals"],
  bridge: {
    gatewayMethods: [
      "brokerkit.snapshot",
      "brokerkit.decide",
      "brokerkit.resend"
    ]
  }
});
```

The panel is deliberately compact:

```text
┌ Approvals ─────────────────────────── × ┐
│ HF ready · GitHub ready · sudo down    │
│ [All 3] [HF 1] [GitHub 2]             │
│                                        │
│ High · Hugging Face repository write   │
│ osolmaz/model · refs/heads/main         │
│ Requested by bob · expires in 4m       │
│                         [Deny] [Review] │
│                                        │
│ GitHub pull request merge              │
│ org/repo · #42                          │
│                         [Deny] [Review] │
└────────────────────────────────────────┘
```

Selecting Review opens detail inside the same popover, not a side panel. It
shows all bounded presentation facts, request reason, requested bounds, use
count, expiry, source, and only currently allowed actions. Approve opens a
confirmation/narrowing dialog when bounds exist. Deny/revoke require a concise
confirmation. Cancel appears only when the broker advertises it.

The UI never invents provider forms. Provider-specific wording is already in
the broker's bounded presentation. HTML is escaped; links are not created from
fact text in V1.

Accessibility requirements:

- keyboard operation and visible focus for every action;
- focus trap and restoration to Settings gear;
- Escape/back behavior that never submits;
- `aria-live` only for concise state changes;
- risk not encoded by color alone;
- minimum target sizes and responsive bottom sheet on narrow screens;
- reduced-motion support; and
- deterministic loading, empty, unavailable, conflict, and retry states.

The React bundle talks only through the OpenClaw iframe bridge. While visible,
it polls `brokerkit.snapshot` every two seconds and immediately after a command;
polling stops when hidden or closed. CSP has `connect-src 'none'`; the browser
never receives broker endpoints, operator credentials, or Gateway credentials.

## Static UI Route

Register a prefix route at `/plugins/brokerkit/ui/` with plugin-managed auth
that serves only immutable packaged UI assets. It must:

- normalize/decode once and reject traversal, encoded separators, dot segments,
  NUL, and unknown assets;
- map a closed asset manifest rather than arbitrary filesystem paths;
- set exact content types, `X-Content-Type-Options: nosniff`, no-store for HTML,
  immutable caching for hashed assets, frame policy compatible only with the
  Gateway host, and the restrictive tested CSP;
- contain no request data, config, endpoints, credentials, source labels, or
  inline environment values; and
- return bounded generic errors.

The route is safe to fetch without Gateway bearer auth because it serves only
the inert shell. All data and actions pass through the authenticated parent
bridge and scoped Gateway methods.

## Health, Errors, And Observability

Source states:

- `ready`: discovery, list, and event loop healthy;
- `degraded`: last safe snapshot remains visible but events/retries are lagging;
- `unavailable`: no usable current snapshot due to auth, version, config, or
  repeated connectivity failure;
- `disabled`: explicitly disabled in config.

Use closed safe error codes such as `auth_failed`, `unsupported_version`,
`invalid_response`, `timeout`, `rate_limited`, `cursor_expired`,
`state_unavailable`, and `network_error`. Logs include source id, operation,
safe code, duration, retry count, and correlation id. They exclude endpoint
userinfo (forbidden), Authorization, SecretRef ids where avoidable, response
bodies, reasons, facts, targets, and broker ids unless debug policy explicitly
permits bounded opaque ids.

Metrics use bounded labels only:

- source health and reconnect count;
- list/event/decision latency and result category;
- cursor expiry and refresh count;
- pending/mirrored/settling counts;
- stale/superseded/retryable settlements; and
- UI snapshot/decision method results.

No metric label contains request id, requester, operation, target, reason,
presentation, endpoint, credential, or arbitrary provider value.

## Config Reload And Shutdown

Register restart reload behavior for changes under
`plugins.entries.brokerkit.config`. A restart is preferred over hot mutation in
V1 so resolved credentials, endpoints, event loops, and source identities are
replaced atomically.

On stop:

1. stop accepting new Gateway decisions;
2. abort event/list work;
3. cancel live OpenClaw mirrors with `plugin-stop` without broker action;
4. wait a bounded five seconds for active broker settlements;
5. persist accepted cursors/mirror state already committed; and
6. discard credentials and in-memory snapshots.

A settlement that has reached the broker uses its idempotency key for recovery
after restart. Shutdown never rewrites a broker decision.

## Testing

### Pure unit tests

- strict config and SecretRef source/runtime validation;
- source id/label/endpoint normalization and SSRF/redirect rejection;
- state key encoding/decoding and closed record validation;
- Operator V1 JSON/error/SSE parsers with hostile limits;
- risk/presentation mapping and prompt truncation;
- decision constraints and idempotency derivation;
- retry/backoff with fake clock; and
- log/error redaction.

### Property and fuzz tests

- arbitrary JSON, Unicode, control/bidi characters, timestamps, integers,
  cursors, SSE lines, event ordering, composite keys, and URL encodings;
- unknown fields and event kinds;
- duplicate/out-of-order events and monotonically increasing used count;
- request ids at byte limits; and
- no generated UI/message/log output contains seeded secret canaries.

### State/restart tests

- initial list-then-watch race closure;
- crash before/after cursor persistence;
- crash before settlement, during unknown broker response, and after broker
  commit;
- stale stored mirror revalidation;
- broker request terminal while plugin is offline;
- OpenClaw approval timeout without broker mutation;
- resend without duplicate authority;
- cursor expiry/full refresh; and
- corrupt keyed-state entry fail-closed refresh.

### Multi-source tests

- HF and GH fake sources with different presentations but one UI path;
- one auth failure, one rate limit, and one healthy source;
- same broker request id under different source ids;
- independent cursors and ordering;
- source disable/re-enable; and
- no provider conditional in plugin source outside test fixture names.

### OpenClaw integration tests

- manifest discovery, config UI, SecretRef audit/resolution, and restart policy;
- installed-plugin keyed state contract;
- background approval settlement through ordinary Gateway UI;
- Discord/Telegram or channel fakes using existing forwarder contracts;
- authenticated actor attribution and unauthorized decision rejection;
- compact Settings popover and iframe bridge;
- token/endpoint absence from frame messages and browser network log;
- browser tests in Chromium, Firefox, and WebKit; and
- disable/uninstall/restart while a request is pending.

### Live broker smoke tests

Use disposable, least-authority test accounts/resources. Verify one HF request,
one GH request, and later one sudo command plan through the same plugin. No test
uses production credentials. Provider tests prove provider behavior in broker
directories; plugin tests prove only the common contract.

## Implementation Order For The Single Cutover

These are dependency-ordered commits in one implementation branch and one
coordinated cutover, not separately supported releases:

1. land/release the provider-neutral OpenClaw host seams;
2. add plugin package/build/manifest/config validation;
3. generate Operator V1 TypeScript types and fixture tests;
4. implement strict BrokerKit client and SSE parser;
5. implement keyed cursor/mirror stores and source registry;
6. implement list/watch/reconciliation and multi-source snapshot;
7. implement background channel mirrors and pre-resolution settlement;
8. implement scoped Gateway snapshot/decision/resend methods;
9. implement static UI route, bridge client, and React/shadcn popover UI;
10. complete restart, adversarial, browser, channel, and live conformance tests;
11. pin the released OpenClaw host version, verify package name, and build
    reproducible npm/ClawHub artifacts; and
12. enable the plugin only when all brokers and the monorepo cutover are ready.

No commit in the sequence is a supported deployment. The first supported
state is the complete cutover commit/release with all required checks green.

## Clean Cutover Rules

- No MLClaw overlay code is imported or retained as a fallback.
- No unversioned BrokerKit operator route is called.
- No pre-V1 request, cursor, decision, or state shape is parsed.
- No old OpenClaw tab/side-panel UI remains in the production package.
- No plaintext broker credential config is accepted.
- No mixed old/new broker source is registered.
- No aliases, config converters, dual writes, or route probes are
  added.
- Existing pending/active authority is revoked or expires before cutover; the
  plugin starts from a fresh V1 list/cursor snapshot.
- Failure before release aborts the cutover. Failure after release disables the
  complete new plugin/broker set; it does not activate alternate code.

## Acceptance Criteria

The plugin is complete when another agent can run the documented commands and
prove all of the following without making an architectural decision:

- config and manifest schemas are closed and validated;
- credentials remain SecretRefs/server-only;
- all configured V1 brokers appear through one provider-neutral registry;
- per-source list/watch cursors survive restart;
- pending requests render in the compact Settings popover;
- direct UI decisions are revision-bound, scoped, idempotent, and actor-derived;
- channel decisions use OpenClaw's existing transport/authorization and settle
  at the broker before resolution;
- timeout/restart/channel/source failure never synthesizes broker authority;
- HF, GH, and sudo-specific behavior remains exclusively in those brokers;
- no private OpenClaw import or channel implementation exists in the plugin;
- no browser/frame/log/state/metric leaks credentials or plans;
- all unit, race/concurrency, fuzz, restart, integration, browser, conformance,
  package, provenance, and live smoke gates pass; and
- only the complete V1 monorepo/plugin system is supported after cutover.
