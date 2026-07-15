# Telegram approval ingress

BrokerKit uses one `brokerkit-telegram` ingress process for each Telegram bot
token. Provider brokers send approval messages and durable status updates, but
they do not call `getUpdates`. The ingress owns the bot update offset and routes
button decisions to the owning broker over its authenticated Operator V1 Unix
socket.

This boundary is required when several brokers share one bot. Telegram permits
only one long poller per bot token; running a poller in every broker races
callbacks and can produce false `Grant not found` or `Grant no longer pending`
answers.

## Linux setup

Install and configure each provider broker first. Keep the raw operator secret
files supplied to their setup commands. Then configure the shared ingress with
the same bot token and chat ID:

```sh
sudo brokerkit-telegram setup systemd \
  --telegram-bot-token-file ./telegram-bot-token \
  --telegram-chat-id 123456789 \
  --hf-operator-token-file ./hf-operator-secret \
  --gh-operator-token-file ./gh-operator-secret \
  --sudo-operator-token-file ./sudo-operator-secret
```

Omit a provider token flag when that provider is not installed. The default
Operator V1 sockets and access groups match the provider installers. Endpoint
and group flags are available for non-default layouts.

Setup creates a dedicated `brokerkit-telegram` service account, copies the bot
and operator tokens into `/etc/brokerkit-telegram` with service-only read
access, adds the account to the configured broker operator socket groups, and
installs `brokerkit-telegram.service`. Secrets are read from files and are not
accepted as command-line values.

The managed configuration has this shape:

```json
{
  "telegram_bot_token_file": "/etc/brokerkit-telegram/telegram-bot-token",
  "telegram_chat_id": 123456789,
  "routes": {
    "h": {
      "operator_endpoint": "unix:///run/brokerkit/huggingface/operator/broker.sock",
      "operator_token_file": "/etc/brokerkit-telegram/operator-token-h"
    }
  }
}
```

The route keys are `h` for Hugging Face, `g` for GitHub, and `s` for sudo.
Configuration rejects duplicate or unknown fields, unsupported routes, relative
secret paths, and malformed endpoints.

## Decision behavior

An accepted button tap is committed through the owning broker's Operator V1
API. The ingress immediately answers the callback and removes both buttons
without replacing the message text. The broker's durable notification outbox
then writes the authoritative terminal status. Repeated taps return the current
terminal state and cannot create a second decision.

Transient broker or socket failures leave the Telegram update unacknowledged so
the single ingress retries it. A wrong chat cannot decide a grant. Provider
credentials and agent credentials are never available to the ingress.
