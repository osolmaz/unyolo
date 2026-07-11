# OpenClaw BrokerKit

`openclaw-brokerkit` adds a provider-neutral Approvals tab and `/brokerkit`
commands to OpenClaw. It connects to one or more BrokerKit Operator V1 sources.
The brokers remain authoritative and retain all provider credentials and
executable plans.

The minimum supported host is `openclaw@2026.7.1-beta.5`, the first published
SDK used by this package that includes public tab descriptors.

## Configuration

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

Commands require an authorized sender and the `operator.approvals` scope.
Subscriptions use OpenClaw's generic outbound adapter, so this package contains
no Telegram, Discord, Slack, or other channel-specific implementation.
