---
title: Approve from Telegram
description: Send approval requests to Telegram and record button decisions safely.
---

Telegram can show requests from the operator inbox. A Telegram button and the inbox API decide the
same stored request, and only the first decision takes effect.

## Single-poller requirement

unYOLO runs one `unyolo-telegram` ingress per Telegram bot token. Provider brokers supply
bounded semantic approval data and send durable status updates, but they do not format Telegram
HTML and they do not call `getUpdates`.

Telegram permits only one long poller per bot token. Running a poller inside every broker races
callbacks between them and loses deterministic ownership of each update, so a decision could be
consumed by a process that does not own the request. One ingress owns the offset and routes each
decision to the broker that owns it.

The shared renderer owns layout, escaping, emoji, the fixed Approve and Deny buttons, terminal
wording, and message limits. Providers supply facts, not markup.

## Setup

Install and configure each provider broker first, and keep the raw operator secret files you gave
their setup commands. Then configure the ingress with the same bot token and chat ID:

```sh
sudo unyolo-telegram setup systemd \
  --telegram-bot-token-file ./telegram-bot-token \
  --telegram-chat-id 123456789 \
  --hf-operator-token-file ./hf-operator-secret \
  --gh-operator-token-file ./gh-operator-secret \
  --sudo-operator-token-file ./sudo-operator-secret
```

Omit a provider flag when that provider is not installed. The default Operator V1 sockets and
access groups match the provider installers, and endpoint and group flags exist for non-default
layouts.

Setup creates a dedicated `unyolo-telegram` service account, copies the bot and operator tokens
into `/etc/unyolo-telegram` with service-only read access, adds the account to the configured
broker operator socket groups, and installs `unyolo-telegram.service`. Secrets are read from
files; command-line secret values are not accepted.

## Managed configuration

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

Route keys are `h` for Hugging Face, `g` for GitHub, and `s` for sudo. Configuration rejects
duplicate or unknown fields, unsupported routes, relative secret paths, and malformed endpoints.

Setup creates the inbox encryption key once and preserves it on every rerun. The key is readable
only by the ingress service. Losing or rotating it while callbacks are pending makes those
callbacks unreadable rather than falling back to plaintext authority, which is the correct failure
direction for stored decision tokens.

## Button tap handling

An accepted tap is committed to the ingress SQLite inbox together with the next Telegram update
offset, in one transaction. The decision token is encrypted with AES-GCM before it reaches storage.

Only after that commit does the ingress answer Telegram with neutral receipt text and dispatch
through the owning broker's Operator V1 API. It renders the typed terminal state and removes both
buttons in the same edit where possible. The broker's durable notification outbox then reconciles
the authoritative terminal render from the exact stored pending message.

Repeated or concurrent taps return the current terminal state and cannot create a second decision.

## Message integrity

Every pending notification stores the normalized semantic snapshot, the exact rendered HTML, the
renderer identity, and separate SHA-256 digests for the snapshot and the render. The opaque
decision token is used only in the callback payload and is not retained in the semantic snapshot.

Dynamic provider values are HTML-escaped and bounded without splitting UTF-8. They cannot supply
markup, button labels, callback answers, or status prose, so a provider fact containing markup
renders as text rather than becoming part of the interface.

## Failure behaviour

Transient broker or socket failures leave the callback pending in the inbox with bounded
exponential retry. Entries dispatch separately, so one unavailable route does not block healthy
routes. A restart resumes pending callbacks from SQLite before fetching more updates.

A durable decision followed by a failed Telegram edit retries idempotently until the terminal
render and the button removal converge. Terminal and expired records erase their nonce, ciphertext,
and decision token while keeping redacted lifecycle evidence.

## Contract drift

Every route exposes its exact generated Operator V1 contract digest and build identity, and the
ingress compares that digest before each poll batch. A missing or different digest makes the
ingress exit without consuming another Telegram update, which leaves the service manager or a
bundle rollback to repair the host.

Stopping is the safe behaviour here. An ingress that kept polling against a broker whose contract
had changed would consume updates it could not correctly route, and a consumed update is gone.

Temporary route outages are different and still enter the durable per-route retry path.

## Ingress limits

A wrong chat cannot decide a grant. Provider credentials and agent credentials are never available
to the ingress, and its authority is limited to the operator tokens it was configured with.

Observability is deliberately thin. Callback authority is visible only as aggregate queue
lifecycle. Operational logs may report callback receipt, retry, terminal state, route, update ID,
and a bounded attempt count. They must not report callback data, decision tokens, rendered
messages, usernames, or chat IDs.

## Turning it off

Rerunning provider setup without both Telegram flags disables notifications for that broker and
retires the managed token file after the restarted service passes its readiness check. Pending
requests remain available in the operator inbox, because Telegram was never the state machine.
