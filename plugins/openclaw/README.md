# OpenClaw BrokerKit

`openclaw-brokerkit` adds a provider-neutral Approvals tab and `/brokerkit`
commands to OpenClaw. It connects to one or more BrokerKit Operator V1 sources.
The brokers remain authoritative and retain all provider credentials and
executable plans.

The minimum supported host is `openclaw@2026.7.1-beta.5`, the first published
SDK used by this package that includes public tab descriptors.

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
              endpoint: "http://127.0.0.1:8081",
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
