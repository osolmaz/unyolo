# OpenClaw BrokerKit

`openclaw-brokerkit` is an OpenClaw plugin that adds a provider-neutral
Approvals tab and `/brokerkit` commands to OpenClaw. It connects to one or
more BrokerKit Operator V1 sources; the brokers remain authoritative and
retain all provider credentials and executable plans.

The minimum supported host is `openclaw@2026.7.1-beta.5`, the first published
SDK used by this package that includes public tab descriptors.

## Install

Install an exact release from
[npm](https://www.npmjs.com/package/openclaw-brokerkit) through OpenClaw:

```sh
openclaw plugins install npm:openclaw-brokerkit@<version>
```

For a local monorepo checkout, build and link the package explicitly:

```sh
pnpm --filter openclaw-brokerkit build
openclaw plugins install --link ./plugins/openclaw
```

## Choose a trust mode

- `direct` trusts the OpenClaw process with operator SecretRefs and enables
  the tab, background reconciliation, `/brokerkit` commands, and channel
  delivery.
- `delegated-web` packages only the tab UI and delegates authenticated
  browser requests to a same-origin trusted backend. It gives OpenClaw no
  broker credential and registers no command or background source service.

## Direct mode configuration

```json5
{
  plugins: {
    entries: {
      brokerkit: {
        enabled: true,
        config: {
          mode: "direct",
          brokers: [
            {
              id: "hf-primary",
              label: "Hugging Face",
              endpoint: "https://hf-broker.example.com",
              operatorCredential: {
                source: "env",
                provider: "default",
                id: "HF_BROKER_OPERATOR_SECRET",
              },
            },
          ],
        },
      },
    },
  },
}
```

Literal operator credentials are rejected; `operatorCredential.source` is
`env`, `file`, or `exec`. Non-loopback endpoints require HTTPS. Each
`endpoint` is the broker's Operator V1 listener, not its agent listener. The
plugin stores only cursors, opaque handles, generic channel destinations, and
delivery bookkeeping under the OpenClaw service state directory.

## Commands

```text
/brokerkit subscribe
/brokerkit unsubscribe
/brokerkit pending
/brokerkit show <handle>
/brokerkit approve <handle>
/brokerkit deny <handle>
/brokerkit revoke <handle>
```

Commands are registered only in direct mode. They require an authorized
sender and the `operator.approvals` scope. Requesters cancel their own
pending requests through the authenticated broker client API, not through
this operator surface. Subscriptions use OpenClaw's generic outbound adapter,
so this package contains no Telegram, Discord, Slack, or other
channel-specific implementation.

## Delegated web mode

For a deployment that treats OpenClaw as untrusted:

```json5
{
  plugins: {
    entries: {
      brokerkit: {
        enabled: true,
        config: {
          mode: "delegated-web",
          delegatedWeb: {
            basePath: "/trusted-host/api/brokerkit",
          },
        },
      },
    },
  },
}
```

The trusted backend implements `brokerkit.io/delegated-web/v1`, authenticates
the human operator, and issues an in-memory decision token lasting no more
than five minutes. The base path must be a normalized same-origin absolute
path. The OpenClaw gateway must set `gateway.controlUi.embedSandbox` to
`scripts` so the approval tab can run while retaining its opaque sandbox
origin; do not use `trusted`.

When OpenClaw is outside the credential trust boundary, the trusted backend
must serve the packaged `dist/ui` files at the registered UI path itself. A
framed popover may receive a server-enforced `read` or `decide` session: a
`read` session shows requests without action controls, and a `decide` session
lets the operator act directly in the frame. Hosts that use framed decisions
accept that the surrounding application controls the iframe's placement and
can attempt UI redressing; use the navigation-only launcher below when that
threat must remain out of scope.

### Session injection

The host injects the short-lived delegated session into the sandboxed
response:

```html
<meta name="brokerkit-delegated-session" content="BASE64URL_SESSION_JSON" />
```

Token-bearing HTML responses must enforce `sandbox allow-scripts` in their
CSP, and immutable UI assets must be loadable by the opaque document (serve
them without a same-origin CORP restriction or set
`Cross-Origin-Resource-Policy: cross-origin`).

The content is a base64url-encoded `brokerkit.io/delegated-web/v1` session
object; the UI removes the element as soon as it reads it. Version 1 uses
this closed payload:

```json
{
  "api_version": "brokerkit.io/delegated-web/v1",
  "token": "opaque-short-lived-browser-session",
  "expires_at": "<no more than five minutes from issue time, RFC3339>",
  "access": "read",
  "renewal_transport": "direct"
}
```

`access` is `read` or `decide`; the host enforces it on every endpoint.
`renewal_transport` is `direct` (the UI posts the current session to
`<basePath>/session`) or `parent` (the nonce-bound bridge below returns the
replacement session in memory). The host preserves the token's access when it
returns a replacement session.

### Browser session transport

Every direct and delegated-web browser API call carries its raw session in
one fixed HTTP field:

```http
GET /trusted-host/api/brokerkit/snapshot HTTP/1.1
Origin: null
BrokerKit-Session: eyJ2ZXJzaW9uIjoxLCJhdWRpZW5jZSI6Ii4uLiJ9.signature
Accept: application/json
```

`BrokerKit-Session` has no authentication-scheme prefix. A host must reject
empty, repeated, combined, malformed, or oversized values; tokens are 32 to
4096 bytes of visible ASCII excluding comma and whitespace. The same field
protects `POST /session`, `GET /snapshot`, `GET /events`, request detail,
approval, denial, and revocation; direct-mode capabilities use it on
`/plugins/brokerkit/api/v1` as well.

Standard `Authorization` is reserved for the hosting edge and for
server-to-server Operator V1 clients. Browser clients never use it, and never
put a delegated session in cookies, query parameters, local storage, or
session storage. Tokens must not be logged, traced, reflected in errors,
copied into an Operator V1 request, or persisted by the host or UI.

Because the packaged UI has an opaque origin under the required scripts-only
sandbox, a delegated host must accept only the expected `Origin: null`,
return `Access-Control-Allow-Origin: null`, allow `BrokerKit-Session` and
`Content-Type` in preflight responses, allow only its fixed route methods,
and set `Vary: Origin` plus `Cache-Control: no-store`. It must not return
`Access-Control-Allow-Credentials: true`; delegated API requests deliberately
omit cookies.

### Secure-navigation launcher

With `access: "read"`, each actionable request renders a **Review securely**
button instead of decision controls. The button posts this navigation-only
message:

```text
{ type: "brokerkit.delegated-web.open", version: 1, nonce }
```

The host verifies the exact opaque-origin frame source and navigates the
whole browser tab to the trusted UI URL. The top-level response is
unframeable and contains a server-enforced decision session, so approval,
denial, and revocation require a second explicit action in the trusted
document.

A host that does not provide a framed inbox can inject this marker so the UI
renders only the secure-navigation launcher:

```html
<meta name="brokerkit-delegated-top-level" />
```

### Parent session bridge

When the parent application is trusted, a sandboxed tab that cannot call the
delegated session endpoint directly may instead use this host-neutral bridge:

```text
request:  { type: "brokerkit.delegated-web.session.request", version: 1, nonce }
response: { type: "brokerkit.delegated-web.session.response", nonce, session }
```

The trusted parent must answer only requests from the embedded BrokerKit
frame and must bind each response to the supplied 128-bit nonce. `session` is
the same `brokerkit.io/delegated-web/v1` object returned by
`POST <basePath>/session`. The bridge is a BrokerKit interface; it contains
no host-product namespace or host-specific payload.
