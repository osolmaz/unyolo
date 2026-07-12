# OpenClaw BrokerKit

`openclaw-brokerkit` adds a provider-neutral Approvals tab and `/brokerkit`
commands to OpenClaw. It connects to one or more BrokerKit Operator V1 sources.
The brokers remain authoritative and retain all provider credentials and
executable plans.

The minimum supported host is `openclaw@2026.7.1-beta.5`, the first published
SDK used by this package that includes public tab descriptors.

## Install

After the package is published, install an exact release from
[npm](https://www.npmjs.com/package/openclaw-brokerkit) through OpenClaw:

```sh
openclaw plugins install npm:openclaw-brokerkit@<version>
```

For a local monorepo checkout, build and link the package explicitly:

```sh
pnpm --filter openclaw-brokerkit build
openclaw plugins install --link ./plugins/openclaw
```

This release is a direct cutover. State databases created by the earlier
prototype schema are rejected rather than migrated; remove the plugin-owned
`plugins/brokerkit/state.sqlite*` files before the first start when replacing a
prototype installation. Broker state is not stored in that database.

Choose one explicit trust mode:

- `direct` trusts the OpenClaw process with operator SecretRefs and enables the
  tab, background reconciliation, `/brokerkit` commands, and channel delivery.
- `delegated-web` packages only the tab UI and delegates authenticated browser
  requests to a same-origin trusted backend. It gives OpenClaw no broker
  credential and registers no command or background source service.

## Configuration

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
              endpoint: "http://127.0.0.1:18080",
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

Literal operator credentials are rejected. Non-loopback sources require HTTPS.
Each `endpoint` is the broker's Operator V1 listener, not its agent listener.
The plugin stores only cursors, opaque handles, generic channel destinations,
and delivery bookkeeping under the OpenClaw service state directory.

For a deployment that treats OpenClaw as untrusted, configure delegated web:

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
the human operator, and issues an in-memory decision token lasting no more than
five minutes. The base path must be a normalized same-origin absolute path.
The OpenClaw gateway must set `gateway.controlUi.embedSandbox` to `scripts` so
the approval tab can run while retaining its opaque sandbox origin. Do not use
`trusted`; delegated authentication is designed for the stricter scripts-only
sandbox.

When OpenClaw is outside the credential trust boundary, the trusted backend
must serve the packaged `dist/ui` files at the registered UI path itself. The
framed response contains no authority. It injects this marker so the UI renders
only a launcher:

```html
<meta name="brokerkit-delegated-top-level" />
```

The launcher posts this navigation-only message after the operator clicks:

```text
{ type: "brokerkit.delegated-web.open", version: 1, nonce }
```

The host verifies the exact opaque-origin frame source, then navigates the
whole browser tab to that frame's URL. The trusted backend accepts only an
authenticated top-level document navigation, rejects fetches, sets
`frame-ancestors 'none'`, and enforces an opaque origin with CSP `sandbox
allow-scripts`. It injects the short-lived session only into that unframeable
document:

```html
<meta name="brokerkit-delegated-session" content="BASE64URL_SESSION_JSON" />
```

The content is the base64url-encoded `brokerkit.io/delegated-web/v1` session
object. The UI removes the element as soon as it reads it and rejects embedded
sessions unless it is running as the top-level document. Before expiry, it
renews by posting to `<basePath>/session` with the current decision token as a
bearer credential, with cookies omitted. The host validates the current token
and opaque `Origin: null` before returning a replacement session.

When the parent application is trusted, a sandboxed tab that cannot call the
delegated session endpoint directly may instead use this host-neutral bridge:

```text
request:  { type: "brokerkit.delegated-web.session.request", version: 1, nonce }
response: { type: "brokerkit.delegated-web.session.response", nonce, session }
```

The trusted parent must answer only requests from the embedded BrokerKit frame
and must bind each response to the supplied 128-bit nonce. `session` is the
same `brokerkit.io/delegated-web/v1` object returned by `POST
<basePath>/session`. The bridge is a BrokerKit interface; it contains no
host-product namespace or host-specific payload.

## Commands

```text
/brokerkit subscribe
/brokerkit unsubscribe
/brokerkit pending
/brokerkit show <handle>
/brokerkit approve <handle>
/brokerkit deny <handle>
/brokerkit cancel <handle>
/brokerkit revoke <handle>
```

Commands are registered only in direct mode. They require an authorized sender
and the `operator.approvals` scope.
Subscriptions use OpenClaw's generic outbound adapter, so this package contains
no Telegram, Discord, Slack, or other channel-specific implementation.

## Verify

```sh
pnpm --filter openclaw-brokerkit check
pnpm --filter openclaw-brokerkit test
pnpm --filter openclaw-brokerkit test:browser
pnpm --filter openclaw-brokerkit build
pnpm --filter openclaw-brokerkit test:package
```

The browser suite runs direct and delegated hosting in Chromium, Firefox, and
WebKit at desktop and mobile sizes. The package test installs the tarball in a
fresh directory beside the exact minimum OpenClaw release and imports the
public plugin entry.
