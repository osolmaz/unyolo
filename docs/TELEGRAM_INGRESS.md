# Telegram approval owner

`unyolo-telegram` is the only unYOLO process that talks to the Telegram Bot
API. It holds the only copy of the bot token. For every installed broker it
sends the approval cards, edits them when a request changes, reads the button
clicks, and decides through that broker's Operator V1 API. Brokers contain no
Telegram code and no Telegram settings. The operator inbox stays the source of
truth: a card is a view of a request in that inbox.

Telegram has one bot-wide update queue, so a bot needs one deterministic owner.
Run exactly one `unyolo-telegram` for each bot. When OpenClaw also uses the
bot, the owner must route separate local queues. Hardened mode also requires
that owner to protect unYOLO messages from OpenClaw's outbound Bot API calls.

## Linux setup

Install and configure each provider broker first. Keep the raw operator secret
files supplied to their setup commands. Then configure the owner with the bot
token and chat ID:

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

### Upgrading from broker-sent cards

Older releases let each broker send its own cards. Those settings are gone:

- `gh-broker` refuses to start while `GH_BROKER_TELEGRAM_BOT_TOKEN_FILE` or
  `GH_BROKER_TELEGRAM_CHAT_ID` is set.
- `hf-broker` refuses to start while any `HF_BROKER_TELEGRAM_*` setting is
  set.
- `sudo-broker serve` refuses `--telegram-token-file` and `--telegram-chat-id`.

Each error names the setting to remove. Rerunning a broker's `setup systemd`
writes an environment without Telegram and removes the old
`telegram-bot-token` file from the broker configuration directory, so the bot
token remains only in `/etc/unyolo-telegram`.

The broker state format also changed: grants no longer carry decision tokens
or notification records. A broker started on older state reports that fresh
state is required.

## Cards

The owner follows each broker's Operator V1 event stream from a cursor that it
stores in its SQLite inbox.

- Without a stored cursor, it lists the broker's pending requests, sends a card
  for each request that has none, and settles every card it has not finished.
  It then stores the event cursor that the list returned.
- For each event, it reads the request, makes the card match it, and only then
  stores the event's cursor. A restart repeats an unfinished event instead of
  skipping it.
- When the broker no longer retains the stored cursor, the owner clears it and
  rebuilds from a fresh list.
- When a request no longer exists, its card shows that the request is
  unavailable.

Each request has at most one card. Before sending, the owner records the card
as `sending` with a new card token. After Telegram confirms the message, the
owner records the chat and message and marks the card `open`. If the owner
stops between those two steps, Telegram may hold a message that the owner never
recorded. The next pass sends a new card with a new token, and the earlier
message's buttons stop working.

An approved request keeps an open card so that later uses can appear on it.
Approved, used, denied, expired, revoked, canceled, and failed requests show
their state and lose their buttons. A request that can no longer change closes
its card. Closed cards are kept for 30 days to answer late clicks.

The shared renderer owns layout, escaping, emoji, the fixed Approve and Deny
buttons, terminal wording, and message limits. Dynamic broker values are
HTML-escaped, bounded without splitting UTF-8, and cannot supply markup, button
labels, callback answers, or status prose.

## Clicks

Each card carries its own random 12-byte token in the button data. The owner
stores only a SHA-256 digest of it. A click is accepted only when all of these
hold:

- it comes from the configured chat;
- the owner has an open or closed card for that route and request;
- the chat and message match the card;
- the token matches the card's digest;
- the clicked button's label is the label of the clicked action.

A click that fails these checks is answered as superseded and makes no
decision. An accepted click decides through the owning broker's Operator V1 API
with the request's expected revision, an idempotency key derived from the
click, and the Telegram operator as `on_behalf_of`. A repeated click returns
the current state and makes no second decision.

An accepted button tap is first committed to the inbox together with the next
Telegram update offset. The callback is encrypted with AES-GCM before it
reaches storage. Only then does the owner answer Telegram and dispatch the
decision. Transient broker or socket failures leave the callback pending in
the inbox with bounded exponential retry. Entries are dispatched separately, so
one unavailable route does not block healthy routes. Restart resumes pending
callbacks before fetching more updates. Terminal and expired records erase
their nonce and ciphertext while keeping redacted lifecycle evidence.

Setup creates the inbox encryption key once and preserves it on every rerun.
The key is readable only by the service. Losing or rotating it while callbacks
are pending makes those callbacks unreadable rather than falling back to
plaintext.

Every route exposes its exact generated Operator V1 contract digest and build
identity. The owner compares that digest before each poll batch. A missing or
different digest exits without consuming another Telegram update, allowing the
service manager or bundle rollback to repair the host. Provider credentials and
agent credentials are never available to the owner.

## Sharing a physical bot

Sharing the unrestricted token with an untrusted application is not safe for
approvals. A token holder can recover inline button data, change the keyboard,
and change the message text. An OpenClaw relay can also invent the parsed
callback and sender fields it sends to unYOLO. See [Chat approval
security](CHAT_APPROVAL_SECURITY.md#telegram) for the full analysis.

Trusted direct mode needs no mux because it treats OpenClaw as an operator.
Hardened mode needs a routing process outside OpenClaw. `unyolo-telegram` does
not forward ordinary Telegram events to OpenClaw. Its custom API base expects
an external router.

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
approval messages through methods such as `getChat`, `pinChatMessage`,
`editMessageText`, `editMessageReplyMarkup`, delete, copy, and forward
operations. It must also keep approval callback envelopes away from OpenClaw.

A compatibility proxy that forwards ordinary Bot API methods unchanged provides
update fan-out, not a hardened boundary between OpenClaw and unYOLO. Do not call
shared-bot mode hardened until message-tampering tests pass against the real
router and Telegram service.
