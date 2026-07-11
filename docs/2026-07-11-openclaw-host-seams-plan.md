# OpenClaw Host Seams Plan

Date: 2026-07-11

Status: proposed prerequisite for the independent BrokerKit plugin

Reviewed OpenClaw baseline:
`openclaw/openclaw@fe261b0f59aa1582e8e4a7dc8e372eb82c8eb0cd`

## Outcome

Add three small, provider-neutral OpenClaw capabilities that let an independent
workflow plugin persist bounded state, offer background approval requests, and
render a compact settings contribution without importing OpenClaw internals or
duplicating channel code.

The additions are not BrokerKit APIs. They must be useful to deployment,
budget, credential, workspace, and other approval-oriented plugins.

The required seams are:

1. manifest-gated keyed state for explicitly enabled installed plugins;
2. a background approval source with pre-resolution settlement; and
3. a generic settings-popover host with a credential-free iframe bridge.

The BrokerKit plugin must not ship against copied internal modules while these
seams are unavailable. It may implement its pure broker client, state machine,
and UI against fakes in parallel, but production integration waits for a
released OpenClaw version containing the public contracts.

## Current Baseline And Gaps

The reviewed OpenClaw revision already provides:

- `api.registerService(...)` for long-lived plugin work;
- `api.registerGatewayMethod(...)` with operator scopes;
- `api.registerHttpRoute(...)` with explicit Gateway or plugin auth;
- `api.session.controls.registerControlUiDescriptor(...)` with
  `session`, `tool`, `run`, `settings`, and `tab` descriptor surfaces;
- `plugins.uiDescriptors` and `plugins.sessionAction` Gateway methods;
- `surface: "tab"` projection into `controlUiTabs` and sandboxed iframe tabs;
- `plugin.approval.*`, shared approval UI, `/approve`, approver authorization,
  and native/fallback channel forwarding;
- `api.runtime.state.openKeyedStore(...)`, backed by the shared OpenClaw SQLite
  database with JSON validation, namespace limits, a 64-KiB value cap, and a
  50,000-entry per-plugin fuse; and
- SecretRefs plus manifest `configContracts.secretInputs` wildcard paths.

Three gaps remain:

- the keyed store rejects non-bundled, non-official installed plugins;
- background services have no public in-process API for creating a plugin
  approval and settling it against an external authority before resolution;
- settings descriptors are returned by `plugins.uiDescriptors`, but the
  Control UI does not render them and the descriptor wire schema cannot carry
  an external panel path/bridge allowlist.

These facts must be rechecked against the exact OpenClaw revision selected for
implementation. If upstream already supplies an equivalent public contract,
adopt it and record the mapping rather than adding a duplicate.

## Seam 1: Manifest-Gated Plugin State

### Manifest shape

Extend `openclaw.plugin.json#contracts` with
`pluginStateNamespaces`:

```json
{
  "contracts": {
    "pluginStateNamespaces": {
      "brokerkit.cursors.v1": { "maxEntries": 32 },
      "brokerkit.mirrors.v1": { "maxEntries": 10000 }
    }
  }
}
```

Field rules:

| Field | Required | Rule |
| --- | --- | --- |
| map key | Yes | Existing safe namespace syntax, at most 128 bytes. |
| `maxEntries` | Yes | Integer from 1 through 50,000. |

Unknown fields are rejected. Duplicate JSON keys are rejected by the manifest
loader's normal policy. The sum of declared maxima must not exceed the global
per-plugin fuse.

### Runtime behavior

For bundled and trusted official plugins, preserve existing behavior. For an
installed plugin, `openKeyedStore` and `openSyncKeyedStore` are available only
when all of these are true:

- the plugin is explicitly enabled;
- its manifest declares the requested namespace;
- the runtime `maxEntries` exactly matches the declaration; and
- the existing store validation and global fuse pass.

`defaultTtlMs` remains runtime-owned because it affects each entry rather than
namespace capacity. A plugin may not open undeclared namespaces, raise a
declared capacity, select another plugin id, or access raw OpenClaw tables.

This gate is resource governance and API hygiene, not a sandbox: installed
native plugin code already executes with Gateway process privileges. The
namespaced API is still safer and more maintainable than encouraging private
SQLite or JSON sidecars.

### OpenClaw files for plugin state

- `src/plugins/manifest-types.ts`
- manifest parsing/validation under `src/plugins/manifest-*`
- `src/plugins/registry.ts`
- `src/plugin-state/plugin-state-store.runtime.test.ts`
- `docs/plugins/manifest.md`
- `docs/plugins/sdk-runtime.md`

### Plugin-state acceptance tests

- enabled installed plugin opens exactly a declared namespace;
- disabled plugin is rejected;
- undeclared namespace is rejected;
- mismatched or excessive `maxEntries` is rejected;
- one plugin cannot read another plugin's namespace;
- duplicate module instances share the same namespaced state;
- disabling/uninstalling does not silently delete durable state;
- explicit reset/uninstall cleanup follows existing OpenClaw state policy;
- corrupt/oversized/non-JSON values still fail through existing store errors;
- bundled/trusted official behavior does not regress.

## Seam 2: Background Approval Source

### Why ordinary plugin approvals are insufficient

`before_tool_call.requireApproval` and Gateway
`plugin.approval.request` assume an in-flight call. A BrokerKit watcher discovers
requests independently of an OpenClaw tool call. Calling Gateway RPC from an
in-process service or importing the approval manager would couple the plugin to
private implementation details.

The external broker must also remain authoritative. OpenClaw may capture an
operator decision, but it must not announce a final resolution before the
plugin has revision-checked and committed that decision at the broker.

### Proposed public API

Add this provider-neutral runtime surface:

```ts
type RuntimeApprovalDecision = "allow-once" | "deny";

type RuntimeApprovalSettlement =
  | {
      status: "committed";
      summary?: string;
    }
  | {
      status: "superseded";
      code: string;
      summary: string;
    }
  | {
      status: "retryable";
      code: string;
      summary: string;
      retryAfterMs?: number;
    };

type RuntimeApprovalRequest = {
  key: string;
  title: string;
  description: string;
  severity: "info" | "warning" | "critical";
  allowedDecisions: readonly RuntimeApprovalDecision[];
  expiresAtMs: number;
  settle: (context: {
    decision: RuntimeApprovalDecision;
    resolvedBy?: string;
    attemptId: string;
    signal: AbortSignal;
  }) => Promise<RuntimeApprovalSettlement>;
};

type RuntimeApprovalHandle = {
  id: string;
  key: string;
  expiresAtMs: number;
  cancel: (reason: "source-resolved" | "source-replaced" | "plugin-stop") =>
    Promise<boolean>;
};

api.runtime.approvals.request(
  request: RuntimeApprovalRequest,
): Promise<RuntimeApprovalHandle>;
```

Contract rules:

- `key` is plugin-scoped, 1-256 bytes, stable for one external request
  revision, and never displayed as authority.
- Repeating `request` with the same key and same normalized prompt returns the
  live handle and replaces the in-process `settle` callback.
- Repeating the key with different prompt/expiry/decisions fails closed.
- V1 permits only `allow-once` and `deny`; `allow-always` is invalid for an
  external authority mirror.
- `title` and `description` use existing plugin-approval limits.
- `expiresAtMs` is clamped to the earlier of the source expiry and OpenClaw's
  maximum approval lifetime. Expiry never calls `settle`.
- The core serializes settlement attempts for a handle and supplies a stable
  `attemptId` to retries of the same candidate decision.
- `settle` runs before the approval manager marks the request resolved or
  forwards a resolution to channels.
- `committed` resolves and forwards the selected decision.
- `superseded` removes the prompt as no longer actionable and exposes the safe
  summary; it does not offer a retry against stale data.
- `retryable` keeps the prompt pending, releases the settlement lease, and
  returns the safe failure to the resolving surface. A retry reuses
  `attemptId` for the same candidate.
- Cancellation removes a pending mirror only. It does not synthesize a deny.
- Plugin stop aborts active callbacks. A late callback result from a retired
  runtime cannot resolve a new handle.
- `resolvedBy` comes from OpenClaw's authenticated approval path and is safe,
  bounded attribution. It is never accepted from the plugin's browser UI.
- Prompt text, summaries, logs, and events retain existing secret-safe limits.

### Delivery semantics

The runtime API must feed the existing plugin approval manager and forwarder.
Discord, Matrix, Slack, Telegram, reaction fallbacks, `/approve`, same-chat
authorization, and configured `approvals.plugin.targets` remain owned by
OpenClaw and its channel plugins.

An OpenClaw timeout, route outage, restart, plugin disable, or cancellation
must never deny or revoke the external request. It only ends that delivery
attempt. The source plugin decides whether and when to offer a replacement.

### OpenClaw files for background approvals

- `src/plugins/runtime/types-core.ts`
- `src/plugins/runtime/index.ts`
- `src/plugins/registry.ts` for plugin attribution/lifecycle binding
- `src/infra/plugin-approvals.ts`
- `src/gateway/exec-approval-manager.ts`
- `src/gateway/server-methods/approval-shared.ts`
- `src/infra/plugin-approval-forwarder.ts`
- focused new runtime adapter and tests under `src/plugin-sdk/`
- `docs/plugins/plugin-permission-requests.md`
- `docs/plugins/sdk-runtime.md`

Do not expose the raw approval manager, Gateway request handlers, broadcaster,
forwarder, or channel runtime through the SDK.

### Background-approval acceptance tests

- background service creates an approval without a tool call or Gateway client;
- duplicate stable key deduplicates within one Gateway process;
- different normalized content under the same key is rejected;
- only offered decisions resolve;
- settle commits before resolved broadcast/forwarding;
- retryable settlement leaves the prompt actionable and reuses attempt id;
- superseded settlement removes the prompt without implying broker denial;
- timeout/cancel/stop never invokes settle and never creates a deny;
- abort during settlement cannot resolve a replacement handle;
- configured channel routing and authorization match ordinary plugin approvals;
- no approval surface available produces a safe delivery failure without
  mutating the external source;
- request and settlement errors redact plugin-thrown sensitive values.

## Seam 3: Settings Popover And Plugin UI Bridge

### Descriptor

Extend the existing settings descriptor rather than inventing a BrokerKit UI
slot:

```ts
api.session.controls.registerControlUiDescriptor({
  surface: "settings",
  placement: "footer-popover",
  id: "approvals",
  label: "Approvals",
  description: "Review authority requested by connected brokers.",
  path: "/plugins/brokerkit/ui/",
  icon: "shield-check",
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

`placement` for `surface: "settings"` V1 accepts only
`footer-popover`. `path` must be an absolute Gateway-local path beginning with
the registering plugin's `/plugins/<plugin-id>/` prefix. Bridge method names
must be registered by the same plugin; event names must use the plugin id
prefix. Unknown descriptor fields remain invalid.

The Gateway filters descriptors by `requiredScopes` before returning them from
`plugins.uiDescriptors`. `plugins.sessionAction` and Gateway methods retain
server-side checks; UI filtering is not authorization.

### Control UI interaction

When there are no visible settings contributions, the Settings gear preserves
its current direct navigation behavior.

When one or more visible contributions exist:

1. activating the gear opens a small anchored menu;
2. the first item, **Open settings**, performs existing config navigation;
3. each plugin contribution appears as a labeled item;
4. selecting one replaces the menu body with a bounded panel anchored to the
   same gear, with Back and Close controls;
5. desktop width is 360-440 px and height is capped at the viewport; mobile
   uses a bottom sheet, not a permanent side panel;
6. Escape closes, focus is trapped/restored, outside click closes, and all
   actions are keyboard and screen-reader accessible; and
7. disabling the plugin or losing required scope closes its open panel.

This is a host surface for any plugin. Core code must not contain `brokerkit`,
Hugging Face, GitHub, or sudo identifiers.

### Credential-free iframe bridge

The plugin serves a static UI shell from a plugin-auth route. The shell embeds
no data, credential, Gateway token, broker endpoint, or server-rendered
request. It uses a sandboxed iframe with scripts but without same-origin,
top-navigation, popups, forms, downloads, or storage privileges.

The parent creates a `MessageChannel`, binds one port to the exact iframe
window, and sends a versioned ready message. The child can request only the
descriptor's allowlisted Gateway methods. The parent calls its
already-authenticated `GatewayBrowserClient`; no bearer token enters the frame.

Minimal bridge messages:

```ts
type HostReady = {
  type: "openclaw.plugin-ui.ready";
  version: 1;
  pluginId: string;
  descriptorId: string;
};

type ChildRequest = {
  type: "openclaw.plugin-ui.request";
  id: string;
  method: string;
  params: unknown;
};

type HostResponse = {
  type: "openclaw.plugin-ui.response";
  id: string;
  ok: boolean;
  result?: unknown;
  error?: { code: string; message: string };
};

```

The bridge rejects malformed messages, duplicate in-flight ids, messages over
64 KiB, more than 16 concurrent requests, non-allowlisted methods, and
messages after panel close or descriptor removal. Errors are safe projections,
not raw thrown objects.

The static response sets a restrictive CSP: no network connections, frames,
objects, workers, navigation, or form submission. Only packaged scripts,
styles, images, and fonts required by the panel are allowed. The implementation
must test the final CSP and sandbox behavior in Chromium, Firefox, and WebKit.

### OpenClaw files for settings UI

- `src/plugins/host-hooks.ts`
- `packages/gateway-protocol/src/schema/plugins.ts`
- `src/gateway/server-methods/plugin-host-hooks.ts`
- `ui/src/components/app-sidebar.ts`
- a generic settings-contribution popover component/controller
- a generic plugin iframe bridge component/controller
- `docs/plugins/sdk-overview.md`
- `docs/plugins/building-plugins.md`

### Settings-UI acceptance tests

- no descriptors preserves direct Settings navigation;
- one/multiple descriptors render deterministically;
- required-scope filtering occurs on the Gateway and UI;
- external plugin content appears in the anchored popover, not a full sidebar;
- no token, password, SecretRef, or endpoint is sent to the iframe;
- bridge accepts only the owning plugin's allowlisted methods;
- iframe cannot navigate the parent or make direct broker/Gateway requests;
- focus, Escape, outside click, mobile layout, and descriptor removal work;
- malformed/oversized/flooded bridge traffic fails safely;
- existing plugin tabs and settings/config navigation do not regress.

## Minimum Host Version

Each seam is additive to the Plugin SDK but must ship with an exact minimum
OpenClaw version. The BrokerKit plugin declares that version in
`package.json#openclaw.install.minHostVersion` and
`package.json#openclaw.compat.pluginApi`.

Do not use version detection based on private fields. Registration performs
explicit capability checks and fails with one actionable message when any
required seam is absent. The plugin has no tab or reduced-function alternate
on an older host.

## Implementation Slices

Implement and review in this order:

1. manifest-gated installed-plugin state access and tests;
2. background approval runtime types plus in-memory fake;
3. approval manager/forwarder settlement integration and lifecycle tests;
4. descriptor protocol additions and Gateway scope filtering;
5. generic Settings popover with static fixture content;
6. credential-free iframe bridge and browser security tests;
7. SDK documentation, minimum-version metadata, and example plugin;
8. release/beta validation before the BrokerKit plugin raises its minimum host
   version.

OpenClaw work must follow its contribution rules, use the main author account,
and be committed in coherent working slices on the pull-request branch. Do not
open or commit OpenClaw work as `dutifulbob`.

## Completion Gate

The host prerequisite is complete when an external test plugin can:

- open only two manifest-declared keyed-state namespaces;
- discover a background request and offer it through ordinary OpenClaw
  approval UI/channels;
- settle a decision in a fake external authority before OpenClaw broadcasts
  resolution;
- render its packaged UI in the compact Settings popover;
- call its scoped Gateway methods without receiving a Gateway token; and
- survive disable, restart, timeout, stale revision, and one unavailable
  channel without inventing external authority.
