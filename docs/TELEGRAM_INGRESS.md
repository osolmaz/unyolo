# Telegram approval ingress

BrokerKit uses one `brokerkit-telegram` ingress process for each Telegram bot
token. Provider brokers supply bounded semantic approval data and send durable
status updates, but they do not format Telegram HTML or call `getUpdates`. The
shared Telegram renderer owns layout, escaping, emoji, fixed Approve and Deny
buttons, terminal wording, and message limits. The ingress owns the bot update
offset and routes button decisions to the owning broker over its authenticated
Operator V1 Unix socket.

This boundary is required when several brokers share one bot. Telegram permits
only one long poller per bot token; running a poller in every broker races
callbacks and loses deterministic ownership of each update.

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
API. The ingress immediately answers the callback, renders the typed terminal
state, and removes both buttons in the same edit where possible. The broker's
durable notification outbox then reconciles the authoritative terminal render
from the exact stored pending message. Repeated or concurrent taps return the
current terminal state and cannot create a second decision.

Every pending notification stores the normalized semantic snapshot, exact
rendered HTML, renderer identity, and separate SHA-256 digests. The opaque
decision token is used only in the callback payload and is not retained in the
semantic snapshot. Dynamic provider values are HTML-escaped, bounded without
splitting UTF-8, and cannot supply markup, button labels, callback answers, or
status prose.

Transient broker or socket failures leave that message's buttons available and
ask the operator to try again. The update is acknowledged so an unavailable
broker cannot block callbacks for healthy brokers sharing the bot. A durable
decision followed by a Telegram edit failure remains committed and converges
through the status outbox. A wrong chat cannot decide a grant. Provider
credentials and agent credentials are never available to the ingress.
