# Browser Session Transport Implementation Plan

Date: 2026-07-14

Status: implemented and verified

Completed: 2026-07-17. The packaged OpenClaw UI now keeps decisions inside
the Gateway popover, retains read-only sessions as non-actionable viewers, and
contains no launcher protocol or parent-navigation path.

## Required Decision UX

The OpenClaw Gateway approvals popover is the canonical review and decision
surface. Operators inspect requests, approve, deny, and revoke directly inside
that popover. BrokerKit must not replace those controls with a **Review
securely** launcher, navigate the Gateway tab away from the current screen, or
require a second top-level approval page.

The trusted backend keeps broker operator credentials and policy authority. It
issues the sandboxed popover a short-lived, audience-bound delegated session
with `access: "decide"`. The iframe holds that session only in memory and uses
it only through the fixed delegated API. This preserves the credential
boundary without moving the operator out of the Gateway UI.

An `access: "read"` session is allowed only for a deliberately non-actionable
viewer. It shows no decision controls and offers no navigation-based authority
upgrade. The OpenClaw Gateway approvals popover is not such a viewer and must
receive `access: "decide"`.

## Contract At A Glance

BrokerKit browser UI clients authenticate every protected UI API request with
one dedicated HTTP field:

```http
GET /trusted-host/api/brokerkit/snapshot HTTP/1.1
Origin: null
BrokerKit-Session: eyJ2ZXJzaW9uIjoxLCJhdWRpZW5jZSI6Ii4uLiJ9.signature
Accept: application/json
```

`BrokerKit-Session` contains the raw opaque browser session or direct UI
capability. It does not use the `Bearer` scheme. A browser UI request never
sends that credential through `Authorization`, a cookie, a query parameter,
local storage, or session storage.

Server-to-server BrokerKit Operator V1 clients continue to authenticate their
operator API requests with `Authorization: Bearer <operator-credential>`.

This is an in-place replacement of the pre-release
`brokerkit.io/delegated-web/v1` transport rule. Version 1 is the only supported
format. Do not add a legacy fallback, dual-send both headers, accept the old
header, add a second format version, or introduce migration code.

## Objective

Make every BrokerKit browser UI mode portable behind hosting layers that
reserve the standard `Authorization` field for their own access control. The
final contract must work in direct and delegated-web mode behind Hugging Face
signed Space links, reverse proxies, Cloudflare Access, enterprise SSO
gateways, and ordinary same-origin hosts without host-specific UI code.

The change must also make transient delegated-web failures recover cleanly in
the UI. A recovered event or snapshot connection must not leave a stale
`Approvals are unavailable` banner visible.

The change must preserve direct decisions inside the mounted OpenClaw Gateway
popover. Security comes from the trusted backend's short-lived delegated
session and server-side authorization, not from leaving the Gateway UI.

## Confirmed Failure

The production reproduction used a signed Hugging Face Space chat URL. The
outer OpenClaw page, BrokerKit iframe document, and packaged JavaScript loaded,
but each request to the delegated snapshot endpoint returned `404` before it
reached MLClaw. The browser resource record was:

```text
/mlclaw/api/brokerkit/snapshot  404
```

The BrokerKit UI currently sends its short-lived delegated token as
`Authorization: Bearer <token>`. Hugging Face owns that field at the Space
edge, interprets the delegated value as a Hugging Face credential, and rejects
it. The trusted application therefore cannot repair or remap the request
because it never receives it.

This is a transport collision, not an Operator V1 failure, a missing approval,
an OpenClaw route failure, or an HF Broker health failure.

## Ownership And Boundaries

BrokerKit owns:

- the browser session transport used by direct and delegated-web modes;
- the fixed session field name and value syntax;
- direct-versus-delegated client behavior;
- token renewal behavior;
- safe UI recovery behavior;
- the browser and protocol conformance suites; and
- maintained delegated-web documentation.

A trusted host such as MLClaw owns:

- authenticating the human before serving token-bearing HTML;
- issuing, validating, renewing, and scoping delegated sessions;
- its exact same-origin API base path;
- CORS and CSP enforcement at its HTTP boundary;
- translating safe delegated calls to BrokerKit Operator V1; and
- integration tests against its hosting platform.

OpenClaw owns only the plugin registration and surrounding Gateway surface.
Individual brokers remain authoritative for requests and decisions. No
OpenClaw core, HF Broker, GH Broker, Sudo Broker, provider policy, or Operator
V1 route change is required.

The OpenClaw Gateway host must request and renew `access: "decide"` for its
authenticated operator popover. It must keep the iframe mounted and must not
navigate the parent tab in response to BrokerKit UI actions.

## Delegated-Web V1 Transport Contract

### Session field

The HTTP field name is `BrokerKit-Session`. Field-name comparison is
case-insensitive as required by HTTP, but documentation and generated examples
use this spelling.

The value is the exact opaque token from the current
`brokerkit.io/delegated-web/v1` session object:

```text
BrokerKit-Session: <session.token>
```

Rules:

- send exactly one field value;
- send the raw token with no authentication-scheme prefix;
- reject an empty, repeated, combined, malformed, or oversized value;
- keep the existing maximum token size of 4096 bytes;
- accept opaque tokens as visible ASCII except comma and whitespace;
- never log, trace, persist, reflect, or include the value in an error;
- never copy it to an upstream BrokerKit operator request; and
- treat it only as a trusted-host delegated session, never as an operator or
  provider credential.

The session payload remains audience-bound, access-scoped, short-lived, and
nonce-bearing. This cutover changes its HTTP transport, not its authority.

### Requests using the field

Every delegated-web request below uses `BrokerKit-Session`:

| Method | Relative path                | Purpose                                 |
| ------ | ---------------------------- | --------------------------------------- |
| `POST` | `/session`                   | Renew a direct-renewal session.         |
| `GET`  | `/snapshot`                  | Fetch the complete safe inbox snapshot. |
| `GET`  | `/events`                    | Wait for the next revision cursor.      |
| `GET`  | `/requests/{handle}`         | Refresh one safe request.               |
| `POST` | `/requests/{handle}/approve` | Approve within broker bounds.           |
| `POST` | `/requests/{handle}/deny`    | Deny a pending request.                 |
| `POST` | `/requests/{handle}/revoke`  | Revoke an active grant.                 |

The existing normalized same-origin `basePath` rule remains unchanged. Request
bodies, response envelopes, handles, revisions, and event cursors remain the
existing version 1 shapes.

### Initial session and renewal

The protected host may still inject the closed session object through the
one-time `brokerkit-delegated-session` meta element or return it through the
nonce-bound parent bridge. The UI removes the meta element immediately and
holds the token only in memory.

For the OpenClaw Gateway approvals popover, the injected or bridged session has
`access: "decide"`. The trusted backend validates that access on every detail
and decision request. The browser never receives an Operator V1 credential.

For `renewal_transport: "direct"`, the UI sends the current token in
`BrokerKit-Session` to `POST <basePath>/session`. The request uses
`credentials: "omit"`, `cache: "no-store"`, and no `Authorization` field.

For `renewal_transport: "parent"`, the existing strict postMessage bridge
remains unchanged. The returned replacement token is then used in
`BrokerKit-Session` for protected API calls.

### CORS expectations for trusted hosts

The packaged UI runs in a scripts-only sandbox with an opaque origin. A
conforming host therefore:

- accepts only the expected opaque `Origin: null` delegated requests;
- returns `Access-Control-Allow-Origin: null`;
- allows `BrokerKit-Session` and `Content-Type` in preflight responses;
- allows only the methods required by its fixed delegated routes;
- uses `Vary: Origin` and `Cache-Control: no-store`;
- does not require or allow browser cookies on delegated API calls; and
- does not return `Access-Control-Allow-Credentials: true`, because the UI
  deliberately uses `credentials: "omit"`.

The token is the delegated API credential. The host's ordinary browser
session remains responsible only for the protected HTML response that issues
the initial token.

### Browser and Operator V1 isolation

Direct mode's browser capability also uses `BrokerKit-Session` when calling
`/plugins/brokerkit/api/v1`. A direct-mode UI can sit behind the same class of
identity-aware proxy, so retaining standard `Authorization` there would leave
the platform-level collision unresolved.

Only the server-side Operator V1 client retains standard bearer
authentication. Keep browser sessions and operator credentials in separate
typed clients. Do not create one mutable header map that can send an operator
credential to a browser route or a browser session to a broker listener.

## BrokerKit Implementation

### UI client

Update `plugins/openclaw/ui/src/api.ts` so that:

- direct and delegated-web browser requests set only `BrokerKit-Session`;
- no browser request sets `Authorization`;
- direct session renewal follows the delegated-web field rule;
- caller-provided request headers cannot replace or duplicate the credential
  field;
- the credential is applied after normalizing safe non-authentication headers;
  and
- fetch continues to omit credentials and disable caching.

Remove the delegated top-level launcher protocol, launcher-only meta marker,
and parent-tab navigation request. A read-only delegated session remains
read-only in place. A decision-capable session renders Approve, Deny, and
Revoke directly in the popover.

Use one small browser credential helper shared by both UI modes. Keep the
field name as one exported constant used by implementation and tests. Do not
make the field name deployment-configurable and do not accept arbitrary
credential field names from bootstrap data.

Update `plugins/openclaw/src/http.ts` so the direct browser API reads only
`BrokerKit-Session`. Its capability validation, access checks, safe handles,
and response schemas remain unchanged. This is a browser API transport change,
not a change to the server-side Operator V1 client in
`plugins/openclaw/src/client.ts`.

### Protocol documentation

Replace the bearer wording in `plugins/openclaw/README.md` with the complete
version 1 rule. Include:

- one minimal request example;
- the exact field semantics;
- direct and parent renewal behavior;
- the CORS obligations of a trusted host;
- the reason standard `Authorization` is reserved; and
- a warning that delegated tokens must not appear in URLs, storage, logs, or
  operator requests.

The delegated-web contract is an OpenClaw plugin/host interface, not an
Operator V1 broker wire route. Keep it documented with the plugin and do not
add this browser token to `protocol/openapi/operator-v1.yaml`.

### UI recovery

Update `plugins/openclaw/ui/src/use-broker-snapshot.ts` so a successful
snapshot or event wait clears a prior transient availability error. Preserve
the last valid snapshot while retrying. Authorization expiry, invalid
responses, cursor expiry, and source failures retain their existing safe public
messages.

Recovery must not depend on a full iframe reload. Opening the popover,
receiving an invalidation message, returning browser focus, receiving an event,
or completing a successful retry must converge on the current snapshot without
flicker or stale error state.

## Verification

### Unit tests

Extend `plugins/openclaw/ui/src/api.test.ts` to prove:

- every direct and delegated browser route sends `BrokerKit-Session` with the
  raw token or capability;
- no browser route sends `Authorization`;
- the server-side Operator V1 client still sends its bearer operator
  credential and never sends `BrokerKit-Session`;
- direct renewal uses the new field;
- parent renewal remains nonce-bound and data-minimal;
- caller headers cannot override or duplicate either credential field;
- missing, expired, malformed, and oversized sessions fail safely; and
- error parsing never exposes response bodies or credentials.

Add focused hook tests for a failed event followed by an unchanged successful
event, a failed snapshot followed by a successful invalidation refresh, and a
cursor-expiry recovery. Each case must clear the availability banner while
retaining valid inbox content.

### Browser tests

Extend `plugins/openclaw/test/browser/approvals.spec.ts` across the supported
Chromium, Firefox, and WebKit desktop/mobile projects. The delegated host
fixture must simulate an identity-aware edge that:

- reserves `Authorization` and returns `404` when any browser request uses it;
- forwards `BrokerKit-Session` unchanged to the trusted test backend;
- requires the opaque sandbox origin and successful preflight;
- serves a decision-capable sandboxed OpenClaw Gateway popover;
- renews a session without cookies; and
- streams a newly created request into the already-mounted UI.

The test passes only when the request renders, the operator decides it without
leaving the parent Gateway URL, and the permitted decision reaches the fake
Operator V1 backend. Assert that **Review securely** and **Open approvals** do
not render. Add a negative assertion that the delegated token is absent from
captured URLs, cookies, storage, logs, DOM after bootstrap consumption, and
host-owned `Authorization` observations.

### Package and quality checks

Run at minimum:

```sh
pnpm --filter openclaw-brokerkit check
pnpm --filter openclaw-brokerkit test
pnpm --filter openclaw-brokerkit test:browser
pnpm --filter openclaw-brokerkit build
pnpm --filter openclaw-brokerkit test:package
go fmt ./...
go vet ./...
go test ./...
golangci-lint run
slophammer-go check .
```

Generated and packaged `dist/ui` assets must match source before the commit is
considered complete.

## Coordinated Replacement

Land BrokerKit and its MLClaw consumer as one coordinated pre-release change:

1. implement and verify the BrokerKit client contract;
2. implement the trusted-host adapter so the OpenClaw Gateway popover receives
   a short-lived `access: "decide"` session;
3. advance MLClaw's immutable BrokerKit revision to the reviewed commit;
4. build and publish the candidate MLClaw runtime image;
5. deploy the candidate to `osolmaz/mlclaw-test`; and
6. verify both an ordinary authenticated Space URL and a Hugging Face signed
   chat URL in a fresh browser context.

Do not publish BrokerKit or MLClaw while one side still implements the replaced
bearer transport. There is no mixed-version compatibility window.

## Acceptance Criteria

- No BrokerKit browser UI mode uses the standard `Authorization` field.
- `BrokerKit-Session` is fixed, documented, tested, and used by every direct
  and delegated browser request.
- Server-to-server Operator V1 retains its existing bearer authentication.
- A proxy that reserves `Authorization` cannot interfere with either browser
  UI mode.
- The sandboxed UI sends no cookies and passes strict CORS preflight.
- Tokens remain memory-only, short-lived, scoped, redacted, and absent from
  URLs and persistent browser state.
- A recovered connection clears `Approvals are unavailable` without reloading
  the iframe.
- Approve, Deny, and Revoke work inside the OpenClaw Gateway popover.
- Decision controls do not navigate, replace, or reload the parent Gateway
  page.
- No **Review securely** or **Open approvals** launcher exists in the Gateway
  flow.
- Chromium, Firefox, and WebKit pass delegated browser coverage at desktop and
  mobile sizes.
- The packaged plugin passes install and minimum-OpenClaw verification.
- The companion MLClaw plan is complete and the exact signed-link reproduction
  renders the pending approval end to end.

## Companion Plan

The trusted-host implementation, runtime pin, deployment, and live validation
are specified in
`osolmaz/mlclaw:docs/2026-07-14-brokerkit-session-transport-plan.md`.
