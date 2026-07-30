# Telegram approval ingress

unYOLO uses one `unyolo-telegram` ingress process for each Telegram Bot API
endpoint. By default, that endpoint is the physical Telegram bot. It can also
be a loopback router endpoint when another application shares the same physical
bot. Provider brokers supply bounded semantic approval data and send durable
status updates, but they do not format Telegram HTML or call `getUpdates`. The
shared Telegram renderer owns layout, escaping, emoji, fixed Approve and Deny
buttons, terminal wording, and message limits. The ingress owns its update
offset and routes button decisions to the owning broker over its authenticated
Operator V1 Unix socket.

Telegram has one bot-wide update queue, so a deployment needs one deterministic
upstream owner. Running a poller in every broker races offsets and loses update
ownership. When OpenClaw also uses the bot, the owner must route separate local
queues. Hardened mode also requires that owner to protect unYOLO messages from
OpenClaw's outbound Bot API calls.

## Linux setup

Install and configure each provider broker first. Keep the raw operator secret
files supplied to their setup commands. Then configure the shared ingress with
the same bot token and chat ID:

```sh
sudo unyolo-telegram setup systemd \
  --telegram-bot-token-file ./telegram-bot-token \
  --telegram-chat-id 123456789 \
  --hf-operator-token-file ./hf-operator-secret \
  --gh-operator-token-file ./gh-operator-secret \
  --sudo-operator-token-file ./sudo-operator-secret
```

Omit a provider token flag when that provider is not installed. The default
Operator V1 sockets and access groups match the provider installers. Endpoint
and group flags are available for non-default layouts.

Setup creates a dedicated `unyolo-telegram` service account, copies the bot
and operator tokens into `/etc/unyolo-telegram` with service-only read
access, adds the account to the configured broker operator socket groups, and
installs `unyolo-telegram.service`. Secrets are read from files and are not
accepted as command-line values.

The managed configuration has this shape:

```json
{
  "telegram_bot_token_file": "/etc/unyolo-telegram/telegram-bot-token",
  "telegram_chat_id": 123456789,
  "inbox_path": "/var/lib/unyolo-telegram/callbacks.db",
  "inbox_key_file": "/etc/unyolo-telegram/inbox-key",
  "routes": {
    "h": {
      "operator_endpoint": "unix:///run/unyolo/huggingface/operator/broker.sock",
      "operator_token_file": "/etc/unyolo-telegram/operator-token-h"
    }
  }
}
```

The route keys are `h` for Hugging Face, `g` for GitHub, and `s` for sudo.
Configuration rejects duplicate or unknown fields, unsupported routes, relative
secret paths, and malformed endpoints.

## Sharing a physical bot

Sharing the unrestricted token with an untrusted application is not safe for
approvals. A token holder can recover inline button data, change the keyboard,
and turn a real Deny click into an Approve callback. An OpenClaw relay can also
invent the parsed callback and sender fields it sends to unYOLO. See [Chat
approval security](CHAT_APPROVAL_SECURITY.md#telegram) for the full analysis.

Trusted direct mode needs no mux because it treats OpenClaw as an operator.
Hardened mode needs a routing process outside OpenClaw. The routing function
could be added to `unyolo-telegram`, but `unyolo-telegram` does not currently
forward ordinary Telegram events to OpenClaw. Its custom API base expects an
external router.

Give unYOLO its own local client token and API base only after that router meets
the message-ownership requirements below. The command then has this form:

```sh
sudo unyolo-telegram setup systemd \
  --telegram-bot-token-file ./unyolo-mux-client-token \
  --telegram-api-base http://127.0.0.1:8080/client/unyolo \
  --telegram-chat-id 123456789 \
  --hf-operator-token-file ./hf-operator-secret
```

The token file contains the local router client token in this mode, not the
BotFather token. `telegram_api_base` is optional in the managed JSON
configuration. HTTPS is required for remote API bases; plain HTTP is accepted
only for loopback addresses.

A local token and exclusive callback queue are insufficient by themselves. The
router must reserve unYOLO callback prefixes and track ownership of messages
sent by each client. It must prevent OpenClaw from reading or changing unYOLO
approval markup through methods such as `getChat`, `pinChatMessage`,
`editMessageReplyMarkup`, delete, copy, and forward operations. It must also
keep approval callback envelopes away from OpenClaw. unYOLO must reject a
callback when its message ID, rendered content, or keyboard differs from the
stored approval.

A compatibility proxy that forwards ordinary Bot API methods unchanged provides
update fan-out, not a hardened boundary between OpenClaw and unYOLO. Do not call
shared-bot mode hardened until message-tampering tests pass against the real
router and Telegram service.

The broker that sends approval messages must use the same local token and API
base. HF Broker accepts `HF_BROKER_TELEGRAM_BOT_TOKEN_FILE` together with
`HF_BROKER_TELEGRAM_API_BASE` for this purpose.

Setup creates the inbox encryption key once and preserves it on every rerun.
The key is readable only by the ingress service. Losing or rotating it while
callbacks are pending makes those callbacks unreadable rather than falling
back to plaintext authority.

## Decision behavior

An accepted button tap is first committed to the ingress SQLite inbox together
with the next Telegram update offset. The decision token is encrypted with
AES-GCM before it reaches storage. Only then does the ingress answer Telegram
with neutral receipt text and dispatch through the owning broker's Operator V1
API. It renders the typed terminal state and removes both buttons in the same
edit where possible. The broker's
durable notification outbox then reconciles the authoritative terminal render
from the exact stored pending message. Repeated or concurrent taps return the
current terminal state and cannot create a second decision.

Every pending notification stores the normalized semantic snapshot, exact
rendered HTML, renderer identity, and separate SHA-256 digests. The opaque
decision token is used only in the callback payload and is not retained in the
semantic snapshot. Dynamic provider values are HTML-escaped, bounded without
splitting UTF-8, and cannot supply markup, button labels, callback answers, or
status prose.

Transient broker or socket failures leave the callback pending in the inbox
with bounded exponential retry. Entries are dispatched separately, so one
unavailable route does not block healthy routes. Restart resumes pending
callbacks from SQLite before fetching more updates. A durable decision followed
by a Telegram edit failure retries idempotently until the terminal render and
button removal converge. Terminal and expired records erase their nonce,
ciphertext, and decision token while retaining redacted lifecycle evidence.

Every route exposes its exact generated Operator V1 contract digest and build
identity. The ingress compares that digest before each poll batch. A missing or
different digest exits without consuming another Telegram update, allowing the
service manager or bundle rollback to repair the host. Temporary route outages
still enter the durable per-route retry path. A wrong chat cannot decide a
grant. Provider credentials and agent credentials are never available to the
ingress.
