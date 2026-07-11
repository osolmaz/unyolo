# OpenClaw BrokerKit Plugin Implementation Plan

Date: 2026-07-11

Status: approved, self-contained implementation plan

Plugin id: `brokerkit`

Npm package: `openclaw-brokerkit`

Monorepo path: `plugins/openclaw`

## Outcome

Build one independently packaged OpenClaw plugin that connects the Gateway to
any number of BrokerKit Operator V1 sources. It must use only OpenClaw's
existing public plugin API and must require no OpenClaw source change, private
import, patched build, or upstream contribution.

The plugin provides:

- a packaged Approvals tab in the Gateway Control UI;
- authenticated, revision-bound approve, deny, cancel, and revoke actions;
- broker request notifications and decisions in configured OpenClaw channels;
- source health, event reconciliation, bounded retry, and restart recovery;
- plugin-owned durable cursor, handle, subscription, and delivery state; and
- one provider-neutral implementation with no Hugging Face, GitHub, sudo,
  MLClaw, Discord, Telegram, or other provider/channel branch.

Each broker remains the sole authority for requests, decisions, grants,
execution plans, and audit. OpenClaw is a presentation and delivery host.

## Existing OpenClaw API Baseline

The implementation targets the public plugin APIs audited at OpenClaw commit
`fe261b0f59aa1582e8e4a7dc8e372eb82c8eb0cd`:

- `api.registerService` for the background source reconciler;
- `api.registerHttpRoute` for packaged UI assets and the UI API;
- `api.registerCommand` for channel-neutral operator commands;
- `api.session.controls.registerControlUiDescriptor` with `surface: "tab"`;
- `api.runtime.channel.outbound.loadAdapter(channel)` for generic outbound
  text delivery; and
- the standard command context authorization fields and required scopes.

Before implementation, pin a released OpenClaw package containing these APIs
and compile/test against that exact package. If a public signature has changed,
adapt the plugin to the released API without editing OpenClaw.

The current public API does not render third-party `surface: "settings"`
descriptors, expose the internal approval manager to background plugins, grant
external plugins access to OpenClaw's trusted keyed store, or provide an
authenticated parent-to-iframe RPC channel. Therefore:

- the UI is an Approvals tab, not a Settings-button popup;
- channel decisions use authenticated plugin commands, not OpenClaw's internal
  approval objects or native approval buttons;
- durable state is plugin-owned SQLite under the supplied state directory; and
- the iframe authenticates to plugin HTTP routes with a restart-scoped random
  capability carried in the descriptor URL fragment.

These are deliberate product boundaries. An implementation must not alter
OpenClaw to recreate the earlier popup concept.

## Operator Configuration

The smallest valid configuration is:

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

Configuration schema:

```ts
type BrokerKitPluginConfig = {
  brokers: Array<{
    id: string;
    label: string;
    endpoint: string;
    operatorCredential: SecretRef;
    requestTimeoutMs?: number;
  }>;
  pollIntervalMs?: number;
  notificationConcurrency?: number;
};
```

Rules:

- `brokers` is non-empty and source ids are unique stable slugs.
- `label` is local presentation text; a broker cannot replace it.
- `endpoint` is an absolute `http:` or `https:` URL without credentials,
  query, fragment, or path outside an explicitly allowed base path.
- non-loopback plaintext HTTP is rejected.
- `operatorCredential` is a structured OpenClaw `SecretRef`; literal secret
  strings are rejected.
- resolved credentials exist only in server memory and are never serialized,
  logged, returned to the browser, or inserted into an error.
- unknown config fields are rejected.
- source additions, removals, and credential changes take effect after a
  normal plugin/Gateway restart.

Channel destinations are not duplicated in plugin configuration. An
authorized operator subscribes the current OpenClaw conversation with
`/brokerkit subscribe`; the plugin records the generic routing coordinates
already resolved by OpenClaw.

## Hard Security Boundaries

The plugin must never:

- receive or expose an upstream provider credential, provider request body, or
  canonical executable plan;
- accept broker endpoints, source ids, credentials, operations, targets,
  requester identity, or request revisions from browser- or channel-provided
  data except the opaque handle and expected revision required for a decision;
- persist a resolved operator credential, broker request snapshot, safe
  presentation body, or execution plan;
- turn an OpenClaw timeout, restart, disable, delivery error, or unsubscribe
  action into a broker decision;
- offer permanent approval or execute a provider operation itself;
- import OpenClaw internals or access OpenClaw-owned database tables;
- store Gateway bearer credentials in the UI; or
- treat a notification delivery as evidence that a request was approved.

All broker decision calls are revision-bound and idempotent. The broker's
response is authoritative when local state disagrees.

## BrokerKit Operator V1 Contract

Every configured source provides:

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

Discovery must return:

```json
{ "api_version": "brokerkit.io/operator/v1" }
```

The plugin validates required response fields, bounds response sizes, ignores
unknown response fields, and rejects unknown decision input fields. Composite
identity is `(sourceId, brokerRequestId)`. The safe request projection is the
Operator V1 projection defined in the universal platform plan; no provider
payload is inferred from display text.

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
      generated/operator-v1.ts
      generated/operator-v1.schema.ts
      client.ts
      error-map.ts
      sse.ts
      validate.ts
    registry/
      source-registry.ts
      source-runtime.ts
    reconcile/
      coordinator.ts
      event-loop.ts
      list-refresh.ts
      notification-worker.ts
      backoff.ts
    state/
      database.ts
      schema.ts
      cursor-store.ts
      handle-store.ts
      subscription-store.ts
      delivery-store.ts
    channel/
      commands.ts
      authorization.ts
      notifier.ts
      rendering.ts
    http/
      router.ts
      auth.ts
      ui-api.ts
      ui-assets.ts
      security-headers.ts
    test/
      fake-clock.ts
      fake-openclaw.ts
      fake-source.ts
  ui/
    index.html
    src/
      main.tsx
      app.tsx
      api.ts
      model.ts
      styles.css
      components/
        approval-card.tsx
        approval-detail.tsx
        broker-health.tsx
        decision-dialog.tsx
        empty-state.tsx
        source-filter.tsx
    test/
    components.json
  test/
    config.test.ts
    client.test.ts
    sse.test.ts
    state.test.ts
    reconciliation.test.ts
    commands.test.ts
    notifications.test.ts
    ui-auth.test.ts
    manifest.test.ts
    integration.test.ts
```

Use strict TypeScript. Runtime code uses platform `fetch`, streams,
`AbortController`, Web Crypto, and `node:sqlite`. The isolated UI may use
React, Vite, Tailwind, and shadcn/Radix source components. It loads no runtime
CDN asset and introduces no React dependency into OpenClaw itself.

## Plugin Manifest And Registration

Use only fields accepted by the released OpenClaw manifest schema. Do not
invent declarations for state, approvals, settings surfaces, or iframe RPC.
The manifest declares plugin id, name, version, config schema, UI metadata,
the package entry point, and this existing secret-input contract:

```json
{
  "configContracts": {
    "secretInputs": {
      "bundledDefaultEnabled": false,
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

OpenClaw resolves those references into the active server configuration
snapshot before plugin activation. Runtime parsing accepts the resolved string
at that boundary while setup/static validation requires the persisted value to
be a structured SecretRef. Test both views without ever logging the resolved
value.

Registration is conceptually:

```ts
export default function register(api: OpenClawPluginApi): void {
  const runtime = createBrokerKitRuntime(api);

  api.registerService({
    id: "brokerkit-reconciler",
    start: () => runtime.start(),
    stop: () => runtime.stop()
  });

  api.registerHttpRoute({
    path: "/plugins/brokerkit",
    handler: runtime.httpHandler,
    auth: "plugin"
  });

  api.registerCommand(createBrokerKitCommand(runtime));

  api.session.controls.registerControlUiDescriptor({
    surface: "tab",
    id: "approvals",
    label: "Approvals",
    description: "Review BrokerKit requests",
    icon: "shield-check",
    group: "control",
    order: 60,
    path: `/plugins/brokerkit/ui/#${runtime.uiCapability}`,
    requiredScopes: ["operator.approvals"]
  });
}
```

Adjust exact registration object shapes to the pinned released SDK types. The
behavior and security properties above are fixed.

## Plugin-Owned SQLite State

Store the database at:

```text
<service-context-stateDir>/plugins/brokerkit/state.sqlite
```

Create parent directories with mode `0700`, request mode `0600` for the file,
enable WAL, set a finite busy timeout, use foreign keys, and wrap state changes
in transactions. Refuse symlinks and unsafe ownership/permissions where the
platform exposes the required checks.

The database contains only restart coordination metadata:

```text
source_cursor(
  source_id TEXT PRIMARY KEY,
  cursor TEXT NOT NULL
)

request_handle(
  handle TEXT PRIMARY KEY,
  source_id TEXT NOT NULL,
  request_id TEXT NOT NULL,
  revision INTEGER NOT NULL CHECK (revision > 0),
  expires_at_ms INTEGER NOT NULL,
  UNIQUE(source_id, request_id, revision)
)

channel_subscription(
  id TEXT PRIMARY KEY, -- deterministic hash of normalized routing tuple
  channel TEXT NOT NULL,
  target TEXT NOT NULL,
  account_id TEXT,
  thread_id TEXT,
  UNIQUE(channel, target, account_id, thread_id)
)

notification_delivery(
  subscription_id TEXT NOT NULL REFERENCES channel_subscription(id)
    ON DELETE CASCADE,
  handle TEXT NOT NULL REFERENCES request_handle(handle) ON DELETE CASCADE,
  state TEXT NOT NULL CHECK (state IN ('pending', 'sent', 'error')),
  attempts INTEGER NOT NULL DEFAULT 0 CHECK (attempts >= 0),
  next_attempt_at_ms INTEGER NOT NULL,
  PRIMARY KEY(subscription_id, handle)
)
```

Use cryptographically random, URL-safe request handles with at least 128 bits
of entropy. Derive a subscription id from a domain-separated hash of the
normalized `(channel, target, accountId, threadId)` tuple; it is not an
independent identity. Persist the delivery attempt count and next-attempt time
so restart cannot reset bounded retry policy. Handles are safe opaque
references for chat and UI; they reveal no broker id. Delete terminal/expired
handles and delivery rows after a bounded
retention interval; terminal reconciliation deletes the handle instead of
persisting a second lifecycle state. Delete cursor rows for removed source ids
after startup validation. Never store request presentation, credentials,
decisions, operator identities, delivery error text, or broker response bodies.

Create only the schema required by this release. Schema creation is atomic and
versioned through `PRAGMA user_version`; an unrecognized version fails closed
with an actionable diagnostic.

## Source Runtime And Reconciliation

At service start:

1. validate all configuration before opening the database or network clients;
2. resolve operator SecretRefs server-side;
3. discover every broker and require Operator V1;
4. load each source cursor and reconcile the bounded pending request list;
5. allocate durable handles for pending `(source, request, revision)` tuples;
6. enqueue missing subscription deliveries transactionally; and
7. start one supervised SSE loop per healthy source.

SSE processing persists the cursor only after the event projection and any
delivery work commit. On cursor rejection, perform a bounded list reconcile and
resume from the broker-provided position. On disconnect, retry with capped
exponential backoff and jitter. A failing source becomes visibly unhealthy but
does not block other sources.

Periodic list reconciliation repairs missed events, marks handles terminal
when the broker says the request is terminal, and prunes expired data. It never
manufactures a decision. Memory is bounded by configured source count, pending
request limits, response byte limits, and delivery concurrency.

For every browser or command decision:

1. authenticate and authorize the operator;
2. resolve the opaque handle from local state;
3. refetch the request from the configured source;
4. require the stored and submitted expected revision to match the broker;
5. require the action to be currently allowed;
6. submit the BrokerKit decision with a deterministic idempotency key derived
   from source, request, revision, action, and authenticated actor;
7. return the broker result without translating uncertainty into success; and
8. reconcile the handle and notification state from broker truth.

## Gateway Approvals Tab

The `surface: "tab"` descriptor is visible only to Gateway clients with
`operator.approvals`. The iframe contains a compact centered approval surface,
not a permanent side panel. It shows:

- source health and last successful synchronization;
- pending cards grouped/filterable by source;
- safe operation, target, requester, expiry, use bounds, and broker-provided
  presentation;
- revision-aware approve/deny dialogs and revoke/cancel when allowed;
- explicit stale, expired, unavailable, loading, and empty states; and
- a manual refresh action.

The browser never receives operator credentials or a Gateway bearer token.
At plugin start, generate a random 256-bit UI capability and place it only in
the descriptor path fragment. URL fragments are not sent in HTTP requests.
The static shell reads the fragment into memory, removes it from the displayed
URL when browser behavior allows, and sends it as a bearer capability to the
plugin UI API. It is never written to storage, logs, DOM text, analytics, or
error reports and rotates on restart.

The UI HTTP API:

- accepts only the exact plugin route prefix;
- validates the capability in constant time before returning request data or
  accepting an action;
- accepts `Origin: null` only because the sandboxed plugin iframe has an opaque
  origin, and only with a valid bearer capability;
- uses no cookies and rejects query-string credentials;
- sends `Cache-Control: no-store`, restrictive CSP, frame policy compatible
  only with the Gateway host, `X-Content-Type-Options: nosniff`, and a strict
  referrer policy;
- limits bodies, methods, content types, and request rates; and
- returns generic errors without endpoints, secrets, headers, or broker bodies.

The public static shell is inert without the capability. Test the complete
fragment, sandbox, CORS, and header behavior in Chromium, Firefox, and WebKit.

UI endpoints are intentionally small:

```text
GET  /plugins/brokerkit/ui/
GET  /plugins/brokerkit/ui/assets/{content-hash}
GET  /plugins/brokerkit/api/v1/snapshot
GET  /plugins/brokerkit/api/v1/requests/{handle}
POST /plugins/brokerkit/api/v1/requests/{handle}/approve
POST /plugins/brokerkit/api/v1/requests/{handle}/deny
POST /plugins/brokerkit/api/v1/requests/{handle}/cancel
POST /plugins/brokerkit/api/v1/requests/{handle}/revoke
```

Decision bodies contain only `expectedRevision` and Operator V1 action bounds
allowed for that action. Unknown fields fail validation.

## Channel-Neutral Notifications And Decisions

Register one `/brokerkit` command with `requireAuth: true` and
`requiredScopes: ["operator.approvals"]`. Supported subcommands are:

```text
/brokerkit subscribe
/brokerkit unsubscribe
/brokerkit pending
/brokerkit show <handle>
/brokerkit approve <handle>
/brokerkit deny <handle>
/brokerkit revoke <handle>
/brokerkit cancel <handle>
```

For decision commands, require OpenClaw's generic authorized-sender result and
the registered `operator.approvals` scope policy. External plugins cannot
request disclosure of OpenClaw's private owner-status marker, so the plugin
must not depend on it. Record the channel-scoped `senderId` as the
server-attributed actor identifier used for the broker audit call and reject a
decision when it is absent. Never trust an actor name supplied in command
arguments.

`subscribe` captures only generic command context routing fields: `channel`,
`to` (persisted as `target`), optional `accountId`, and optional message
`threadId`. It does not inspect
Discord-, Telegram-, Slack-, or other channel-shaped payloads. If the current
adapter cannot supply a stable destination, return an actionable error and do
not create a row.

For each subscription, load the adapter with
`api.runtime.channel.outbound.loadAdapter(channel)` and call its generic
`sendText` operation using the stored destination fields. Notifications contain
safe projection text, expiry, source label, opaque handle, and exact decision
commands. No provider plan, credential, raw request body, or operator secret is
rendered. Channels without `sendText` are reported as unsupported; the plugin
does not add an adapter.

Delivery is at-least-once and deduplicated by `(subscription, handle)`.
Transient errors retry with bounded backoff. A permanent delivery error is
visible in health output and never changes the broker request. Commands always
refetch broker truth, so duplicated chat delivery or command retry is safe.

## Error Semantics

Use stable plugin error codes for UI and commands:

```text
source_unavailable
source_protocol_error
request_not_found
request_terminal
revision_stale
action_not_allowed
not_authorized
subscription_unsupported
delivery_failed
invalid_input
internal_error
```

Map BrokerKit structured errors deliberately. Preserve retryability without
exposing raw upstream details. A lost decision response remains uncertain until
the plugin refetches the request with the same idempotency context.

## Testing And Quality Gates

Tests must cover:

- strict config validation and SecretRef-only credentials;
- discovery, list, detail, SSE parsing, bounds, cancellation, and timeouts;
- SQLite permissions, transactions, uniqueness, pruning, restart recovery, and
  rejection of an unknown schema version;
- event/list races, disconnects, cursor rejection, stale revisions, expiry,
  duplicate events, lost responses, and one unhealthy source;
- every command's authentication, scope policy, parsing, actor attribution, and
  generic routing capture;
- outbound delivery through at least two fake channel adapters without a
  channel-specific implementation branch;
- UI capability entropy, rotation, constant-time validation, fragment handling,
  `Origin: null` behavior, CSP, no-store, rate/body limits, and redaction;
- approve, deny, cancel, and revoke end to end against the BrokerKit fake;
- browser accessibility, keyboard operation, narrow viewport, and all status
  states in Chromium, Firefox, and WebKit;
- package contents, manifest schema, deterministic UI build, and no runtime CDN
  dependency; and
- integration against the pinned released OpenClaw package using only its
  public exports.

Required plugin commands:

```sh
npm ci
npm run format:check
npm run lint
npm run typecheck
npm test
npm run test:browser
npm run build
npm pack --dry-run
```

Add secret scanning and generated Operator V1 schema drift checks to the root
monorepo workflow. Logs and test snapshots must use canary secrets to prove
redaction.

## Implementation Order

Complete this work as one coordinated cutover:

1. pin the released OpenClaw SDK baseline and add a compile-only public API
   contract test;
2. scaffold the package, strict config parser, manifest, and build tooling;
3. generate Operator V1 types and implement the bounded client/SSE parser;
4. implement plugin-owned SQLite and its stores;
5. implement source discovery, list reconciliation, SSE supervision, and
   durable handles;
6. implement authenticated commands, subscriptions, generic outbound delivery,
   and restart recovery;
7. implement the UI capability, static routes, HTTP API, and security headers;
8. implement the React/shadcn Approvals tab;
9. run unit, integration, browser, channel, security, packaging, and monorepo
   gates from fresh state; and
10. publish/install the plugin with broker endpoints still isolated, validate
    end to end, then expose the complete system together.

No step authorizes OpenClaw source edits. If an expected public API is absent in
the pinned release, redesign the plugin within available public APIs or stop
and update this plan; do not patch the host.

## Definition Of Done

The plugin is complete when:

- it installs on an unmodified released OpenClaw package;
- disabling/removing it leaves OpenClaw code and state untouched outside the
  plugin-owned directory;
- multiple BrokerKit sources reconcile independently;
- the packaged Approvals tab renders and decides requests securely;
- authorized channel conversations can subscribe and decide through generic
  commands on adapters that support text delivery;
- no provider- or channel-specific branch exists;
- no provider credential, executable plan, or resolved operator secret crosses
  the broker boundary or appears in state/logs/UI/chat;
- restart, expiry, stale revision, duplicate delivery, and lost-response tests
  preserve broker authority; and
- all plugin and root monorepo gates pass from a clean checkout.
