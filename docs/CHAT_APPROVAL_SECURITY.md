# Chat approval security

Chat buttons are safe approval inputs only when unYOLO can prove what the
operator clicked. Showing an Approve button is not proof. An untrusted agent or
chat process may be able to read the button value, invent a callback, change the
reported user, or replay an earlier click.

This document defines the required proof, explains the Telegram choices, and
records which other chat platforms can provide a suitable boundary.

## Security goal

The deployment may let OpenClaw carry ordinary conversation traffic, but
OpenClaw and its agent are not approval authorities. They may delay or discard a
real decision. They must not be able to:

- turn Deny into Approve;
- approve without an operator action;
- substitute another user, request, or action;
- reuse an expired or consumed decision;
- obtain a credential that can mint valid approvals.

The protected inputs are the operator identity, action, pending request,
revision, and approval limits. unYOLO must validate all of them before changing
broker state.

This goal does not prevent denial of service. An untrusted chat process can hide
an approval, delay delivery, delete a message, or suppress a real click. The
broker must remain pending or fail closed when that happens.

## Accepted proof patterns

Use one of these patterns. Do not treat an unsigned parsed callback from
OpenClaw as proof.

### Direct authenticated callback

The platform sends the original interaction request to unYOLO or to a trusted
ingress in front of it. The trusted component verifies the request before
parsing or forwarding it.

Depending on the platform, verification means one of the following:

- a signature over the exact raw request body and a fresh timestamp;
- a platform-issued bearer token received directly over TLS and verified for
  the expected issuer, audience, app, and endpoint;
- an authenticated homeserver or server-plugin connection that the untrusted
  chat client cannot use.

After verification, bind the platform event ID, operator identity, selected
action, and pending request. Consume the decision once. Reject duplicate event
IDs, stale timestamps, wrong users, wrong chats, and terminal requests.

A trusted ingress must not pass the platform authorization header, signing
secret, application-service token, or raw replayable request to OpenClaw. It may
send OpenClaw only the ordinary, non-authoritative event projection it needs.

### Opaque one-time action capability

This is acceptable only when the untrusted process cannot read an unclicked
action capability.

Create a different random capability for every action. Store only a verifier
and bind it to:

- one pending request and revision;
- exactly one action, such as Approve or Deny;
- one operator and conversation;
- an expiry time;
- one use.

The capability must have enough entropy to resist guessing. A capability for
Deny must never authorize Approve. Receiving one capability must not reveal a
sibling capability.

This pattern is weaker than a direct signed callback. It depends on the
platform keeping unclicked action data unavailable to the untrusted process.
Message history, message lookup, edit responses, administrative APIs, exports,
or callback envelopes can break that assumption.

### Separate approval identity

A separate bot, app, or account may own approval callbacks while OpenClaw owns
ordinary conversation traffic. The operator can keep both identities in one
group, room, or channel where the platform allows it. This needs no shared
poller, but it does require a second platform identity.

## Decision protocol

Every adapter follows this sequence:

1. The broker commits the pending request, immutable plan digest, revision,
   allowed operator, conversation, actions, limits, and expiry before sending a
   notification.
2. The notifier creates either non-secret action identifiers for a directly
   authenticated callback or a different random capability for each action.
   It stores capability verifiers, never plaintext capabilities, in broker or
   trusted ingress state.
3. unYOLO sends the approval message through the platform API. OpenClaw does
   not construct the authoritative action fields.
4. The platform sends the interaction to the trusted callback endpoint,
   exclusive ingress, or separate approval identity. OpenClaw may receive a
   non-authoritative copy only after verification.
5. The receiver authenticates the original request before parsing it. It
   checks signature or token claims, freshness, event ID, expected app, and
   transport endpoint as the platform contract requires.
6. unYOLO resolves the exact pending request and verifies the platform user,
   conversation, action, revision, limits, expiry, and current pending state. A
   capability, when used, must match its stored action-bound verifier.
7. Under one state lock or transaction, unYOLO records the platform event as
   consumed and applies at most one broker decision. A duplicate returns the
   existing safe terminal or pending state without repeating authority.
8. Only after durable commit does the adapter acknowledge the platform and
   reconcile the message to its terminal rendering. Delivery or edit failure
   retries idempotently and does not roll back the decision.

If a platform cannot preserve this sequence, use a separate approval identity
or an authenticated browser/native approval surface.

## Telegram

### One upstream update owner

Telegram exposes one bot-wide update queue. A `getUpdates` offset confirms
updates globally, and one shared `allowed_updates` setting applies to the bot.
The bot cannot use webhooks and `getUpdates` at the same time. OpenClaw and
unYOLO cannot poll the physical bot independently without racing or losing
updates.

A shared bot therefore needs one deterministic upstream owner. OpenClaw and
unYOLO may consume separate local queues after that owner records and routes an
update.

Telegram can put a configured secret header on webhook deliveries. That header
can authenticate a request delivered over TLS directly to a trusted ingress,
although it is not a signature over the body. It does not authenticate the new
request that an OpenClaw relay constructs for unYOLO. A webhook ingress that
also forwards ordinary updates to OpenClaw is the shared bot's routing process.

### OpenClaw as the owner

OpenClaw can own `getUpdates` and relay approvals when the deployment trusts the
OpenClaw process and its plugins as an operator. This is trusted direct mode.
Compromising OpenClaw then has the same effect as compromising an approval
operator.

Hardened mode assumes that OpenClaw can change its own code, plugins, runtime
state, and relay messages. OpenClaw cannot own approval ingress under that
assumption. It receives the callback data together with the message, chat ID,
and sender ID, then constructs a new request to unYOLO. unYOLO cannot tell
those parsed fields from values invented inside OpenClaw.

### Bot token authority

The physical bot token also lets OpenClaw inspect and change approval messages.
A token holder can recover hidden button data without a click:

1. It identifies or probes the outgoing approval message.
2. `pinChatMessage` permits non-service messages to be pinned in private chats.
3. `getChat` returns `ChatFullInfo.pinned_message`.
4. The returned `Message.reply_markup` can expose each button's
   `callback_data`.

A callback query can also include the originating message and its keyboard.
Telegram has no general private-chat history method, but that does not keep
button data secret from a token holder.

Reading the button data is only part of the problem. The token holder can call
`editMessageReplyMarkup` or replace the message. It can label a button “Deny”
while attaching the Approve callback data. The operator then makes a real click,
Telegram creates a real callback, and an ingress that checks only the callback
data records the wrong action.

Separate action codes do not stop this attack when OpenClaw can read and edit
the whole keyboard. Exclusive callback routing also does not stop it because
the altered message still produces a genuine callback on unYOLO's queue.

### Secure deployment choices

Telegram has two no-mux choices:

1. Trust OpenClaw as an operator and use direct mode.
2. Give unYOLO a separate approval bot in the same group. Telegram private bot
   chats cannot contain a second bot, so this does not preserve one private bot
   conversation.

One physical bot in one private chat needs a trusted routing function outside
the OpenClaw process. That function may run in a standalone mux or be added to
`unyolo-telegram`. In either case it is a separate process and OS trust
boundary. Putting the routing code inside OpenClaw provides no separation.

A hardened router must:

- Own the physical bot token and the only upstream update stream.
- Durably record each update and its next offset before acknowledging it.
- Send original approval callbacks only to unYOLO.
- Give OpenClaw only ordinary updates through a local authenticated interface.
- Reserve approval callback prefixes so OpenClaw cannot create them.
- Track which client owns each sent message and block OpenClaw from reading,
  editing, deleting, copying, forwarding, or pinning unYOLO approval messages.
- Keep raw approval callback envelopes and all ingress or broker operator
  credentials away from OpenClaw.
- Make unYOLO verify the expected chat, operator, message ID, text or render
  digest, and exact button layout before accepting the action.

Exclusive `getUpdates` routing is not enough. A compatibility proxy that splits
updates but forwards ordinary Bot API methods without message-ownership checks
solves queue sharing, but it does not separate mutually untrusted clients.
Until the router and unYOLO enforce these controls and pass message-tampering
tests, shared-bot mode has the trusted-client security level. It does not meet
the hardened security goal.

A separate approval bot does not share this boundary. unYOLO owns its token and
must verify the callback sender ID, group ID, message binding, request binding,
action, expiry, and single-use state. It must ignore callbacks from OpenClaw's
bot and from anonymous chat senders.

## Platform matrix

“Direct” means the platform request reaches a trusted verifier before
OpenClaw. “Separate identity” means unYOLO owns another bot, app, account, or
server-side integration in the same room. These ratings do not claim that an
unYOLO adapter already exists.

| Platform                   | Reliable proof available                                                                | Hardened same-chat verdict              | Required design                                                                                        |
| -------------------------- | --------------------------------------------------------------------------------------- | --------------------------------------- | ------------------------------------------------------------------------------------------------------ |
| Telegram                   | One bot-wide update stream; no body-bound callback signature                            | Conditional                             | Trusted router with message ownership for one bot, or a separate approval bot in a group               |
| Discord                    | Ed25519 signature over timestamp and raw interaction body                               | Yes                                     | Send component interactions directly to a trusted verifier                                             |
| Slack                      | HMAC signature over version, timestamp, and raw body                                    | Yes                                     | Use signed HTTP interactivity at a trusted ingress; do not relay through Socket Mode owned by OpenClaw |
| Microsoft Teams            | Bot Framework bearer token on activities                                                | Yes, with a trusted endpoint            | Verify the original Connector request over TLS, strip its token, then route the activity               |
| Google Chat                | Google-issued bearer token for the configured app endpoint                              | Yes, with a trusted endpoint            | Verify issuer, audience, and app identity before routing                                               |
| WhatsApp Cloud API         | Meta webhook HMAC over the raw body                                                     | Yes                                     | Verify the original webhook and route interactive replies to unYOLO                                    |
| LINE                       | HMAC signature over the raw body                                                        | Yes                                     | Verify `x-line-signature` before parsing and route postback events                                     |
| Lark / Feishu              | Version-dependent callback verification and encryption; body-bound proof not yet pinned | Not ready                               | Do not implement until one current official callback contract and conformance fixture are pinned       |
| Matrix                     | Authenticated application-service transactions with transaction IDs                     | Conditional                             | Use a trusted application service or a separate unYOLO client; define an explicit action event         |
| Mattermost                 | Server-confidential interactive action context                                          | Yes, with one-time capabilities         | Put a separate action-bound capability in each button context and send callbacks directly to unYOLO    |
| Nostr                      | Operator-signed events with stable event IDs                                            | Yes, with a defined event profile       | Verify the operator public-key signature and bind reply tags, request, action, and expiry              |
| Signal                     | No official bot/button callback API                                                     | Separate account only                   | Use a separate trusted Signal account in a group; do not share one `signal-cli` daemon with OpenClaw   |
| Twitch                     | EventSub HMAC over message ID, timestamp, and raw body                                  | Conditional; no native approval buttons | Receive signed chat events directly and define a narrow typed approval command                         |
| SMS through Twilio         | Twilio-signed webhook; no native buttons                                                | Conditional                             | Give OpenClaw a send-only API key and keep the webhook-signing Auth Token at trusted ingress           |
| IRC, iMessage, BlueBubbles | No portable signed button callback                                                      | Separate receiver only                  | Use another trusted account/receiver or an external approval surface                                   |

## Platform notes

### Discord

Discord signs each HTTP interaction with the application public key. Verify
`X-Signature-Ed25519` over the exact concatenation of
`X-Signature-Timestamp` and the raw request body. Discord requires a prompt
response and checks the endpoint during registration.

Component custom IDs and message components are not secrets. A bot credential
can fetch messages and inspect components. The direct signature is what proves
the clicked component and user. If OpenClaw consumes interactions from the
Gateway and forwards parsed fields, the proof is lost. Configure the
application's interaction endpoint at the trusted verifier while leaving only
non-authoritative traffic for OpenClaw.

### Slack

Slack signs HTTP requests with the app signing secret. Verify
`X-Slack-Signature` against the raw body and `X-Slack-Request-Timestamp`, reject
old timestamps, and record event or action identifiers for idempotency. Do not
parse form data before computing the signature.

Block action values can appear in stored messages and must not be treated as
secret capabilities. Use the signed interaction request. Socket Mode delivers
payloads over an app WebSocket instead of signed HTTP. If OpenClaw owns that
socket, it is not an approval boundary; use a trusted socket owner or signed
HTTP ingress for the whole app.

### Microsoft Teams

Bot Framework activities arrive with a bearer token. Validate the token using
the documented OpenID metadata and expected audience. Because this is transport
and sender authentication rather than a detached signature over the body, the
trusted endpoint must receive the request directly over TLS. It must validate
before passing parsed fields to any untrusted process and must not pass the
bearer token onward.

Bind `activity.id`, conversation, tenant, sender, action data, pending request,
and expiry. Reject duplicate activity IDs. Adaptive Card `Action.Submit` data
is ordinary message metadata, not a secret.

### Google Chat

Google Chat sends an authorization token to an HTTP app endpoint. Verify the
token for the configured audience or project and verify the expected app
identity. The trusted endpoint must receive the original request and remove the
token before any downstream projection reaches OpenClaw.

Card action parameters are not authority by themselves. Bind the verified user,
space, interaction event, action method, and pending request, then consume the
decision once.

### WhatsApp Cloud API

Meta webhooks can include `X-Hub-Signature-256`, an HMAC of the raw request body
using the app secret. Verify it before JSON parsing. The initial webhook
verification challenge proves endpoint control but does not authenticate later
events by itself.

Interactive reply IDs should identify a pending action, but they need not be
secret. The verified webhook body supplies the sender and selected reply. A
trusted ingress can route ordinary messages to OpenClaw and approval replies to
unYOLO without giving OpenClaw the app secret or original signed request.

### LINE

LINE signs webhook bodies in `x-line-signature` with the channel secret. Verify
the untouched body before deserialization. Postback data is visible application
data, so rely on the signature, source user or group, webhook event ID,
redelivery marker, and unYOLO's one-use request state. Keep the channel secret
out of OpenClaw.

### Lark and Feishu

Lark and Feishu have several generations of event subscription and interactive
card callbacks. Their verification, encryption, and field names differ between
the international and China documentation sites. This assessment did not pin a
current official card-action contract with body-bound proof. A static
verification token alone is not a body signature and is not enough when an
untrusted process may know it.

Do not enable support until an adapter pins one current official callback
version and has conformance fixtures from the platform. The review must verify
the exact raw request as required by that version, timestamp and nonce
freshness, app and tenant identity, authentication before decryption, and
rejection of legacy unsigned forms. If the proof uses a secret that OpenClaw
also needs for ordinary API access, the credential split is not sound. Card
action values are not secrets.

### Matrix

The Matrix Application Service API authenticates homeserver transactions with
an application-service token and supplies transaction IDs for idempotency. A
trusted application service can receive the room event directly, verify the
sender Matrix ID against the operator allowlist, and route non-approval events
to OpenClaw without sharing its token.

Matrix does not define one universal approval-button event. An implementation
must define and allowlist an event type or use a plain signed-in user response,
bind it to the pending request, and handle homeserver retries. If OpenClaw and
unYOLO are ordinary clients, give them separate access tokens; never accept an
unsigned object forwarded by OpenClaw as the operator event.

### Mattermost

Mattermost interactive messages send the acting user, post, channel, team, and
the selected action's context to its integration URL. Mattermost documents that
context as confidential and recommends a token, signature, or unguessable
action ID in it for authenticating the server.

This supports the one-time capability pattern even though the callback has no
portable raw-body signature. Put a different random, action-bound capability in
each Approve and Deny context. Send the callback directly to unYOLO, verify the
capability before trusting `user_id`, and consume it once. Do not place the
capability in ordinary post text or props exposed to clients. A server-side
plugin or mTLS between Mattermost and unYOLO adds a stronger deployment
boundary. Record post, channel, team, user, request, action, and one-use state.

### Nostr

Every Nostr event carries the author's public key, content, tags, timestamp,
and event ID under a Schnorr signature. unYOLO can verify an operator event
without trusting the relay or OpenClaw. Public action values cannot be secrets
and do not need to be.

An adapter still needs a narrow event profile: allowed event kind, request-event
reference tag, exact action encoding, operator public-key allowlist, expiry,
and one-use event ID. Ignore replaceable edits unless the profile explicitly
supports them. Privacy requires a separately specified encrypted direct-message
profile; signatures alone do not hide approval details.

### Signal

Signal has no official bot API or interactive button callback contract.
`signal-cli` is an unofficial client and local daemon interface. It does not
expose a portable platform-signed callback that unYOLO can verify independently
of the receiving client. A parsed envelope forwarded by OpenClaw is therefore
not approval proof.

A possible no-mux deployment uses a separate unYOLO Signal account in the same
group and accepts a narrowly formatted response from an allowed operator number
or account. unYOLO must own that account's trusted client and deduplicate message
timestamps or envelope identifiers. This is a custom adapter, not current
unYOLO support, and it should be tested against linked-device and group-update
behavior before use.

### Twitch, SMS, IRC, and device messaging

Twitch EventSub webhooks sign the message ID, timestamp, and raw request body
with a subscription secret. A trusted verifier can therefore authenticate a
chat message from an allowed operator and reject old or duplicate message IDs.
Twitch chat has no native approval-button contract, so an adapter would need a
strict reply command bound to the pending request.

Twilio signs inbound SMS webhooks with the account Auth Token. This is
independent of OpenClaw only if OpenClaw sends with a restricted API key and the
trusted verifier alone holds the Auth Token. SMS has no hidden button payload;
use a random request reference, a strict command, sender allowlisting, short
expiry, and one-use state. Account takeover and telephone-number reassignment
remain channel risks.

IRC, iMessage, and BlueBubbles do not provide a portable, platform-signed
button callback to an independent verifier. A nickname or sender field copied
by OpenClaw is not proof. Use a separate trusted account or receiver, or move
the decision to an authenticated web or native approval surface.

OpenClaw supports additional proprietary and self-hosted channels, including
Nextcloud Talk, QQ, WeChat, Synology Chat, Tlön, and Zalo variants. They are not
safe by analogy to a platform in this table. Each adapter needs evidence for
its exact callback version, credential split, user identity, replay handling,
and message-data visibility. Until that review and a real-service test are
complete, fail closed and use a separate approval identity or external approval
surface.

## Checks required for every adapter

Before calling a platform safe, reproduce all of these against the real service:

1. A real operator click reaches the trusted verifier with the expected user,
   conversation, request, and action.
2. Changing any signed byte, bearer-token claim, user, action, or request causes
   rejection.
3. A copied callback cannot be used twice, after expiry, or for another request.
4. Deny cannot be changed to Approve by a process that can read message history
   and use the ordinary bot or app credential.
5. OpenClaw receives no signing secret, app-service token, approval-bot token,
   original bearer token, or other credential that can mint approval proof.
6. Restarts preserve pending decisions and replay records before an upstream
   acknowledgement is considered complete.
7. Duplicate and out-of-order platform deliveries converge on one terminal
   broker state.
8. An unavailable OpenClaw process cannot cause approval; it can cause only
   delayed conversation or approval delivery.

A mocked callback, a successful message send, or a valid button render is not
end-to-end security verification.

## Official references

- [Telegram Bot API](https://core.telegram.org/bots/api)
- [Discord: receiving and responding to interactions](https://docs.discord.com/developers/interactions/receiving-and-responding)
- [Discord message resource](https://docs.discord.com/developers/resources/message)
- [Slack: verifying requests from Slack](https://docs.slack.dev/authentication/verifying-requests-from-slack/)
- [Slack: handling user interaction](https://docs.slack.dev/interactivity/handling-user-interaction/)
- [Microsoft Bot Connector authentication](https://learn.microsoft.com/en-us/azure/bot-service/rest-api/bot-framework-rest-connector-authentication)
- [Google Chat: verify requests](https://developers.google.com/workspace/chat/verify-requests-from-chat)
- [Google Chat interaction events](https://developers.google.com/workspace/chat/receive-respond-interactions)
- [Meta Webhooks](https://developers.facebook.com/docs/graph-api/webhooks/getting-started)
- [WhatsApp Cloud API interactive messages](https://developers.facebook.com/docs/whatsapp/cloud-api/guides/send-messages#interactive-messages)
- [LINE: receiving messages](https://developers.line.biz/en/docs/messaging-api/receiving-messages/)
- [LINE action objects](https://developers.line.biz/en/reference/messaging-api/#action-objects)
- [Lark event subscriptions](https://open.larksuite.com/document/server-docs/event-subscription-guide/event-subscription-configure-/request-url-configuration-case)
- [Matrix Application Service API](https://spec.matrix.org/latest/application-service-api/)
- [Mattermost interactive messages](https://developers.mattermost.com/integrate/plugins/interactive-messages/)
- [Nostr NIP-01](https://github.com/nostr-protocol/nips/blob/master/01.md)
- [`signal-cli`](https://github.com/AsamK/signal-cli)
- [Twitch EventSub webhook verification](https://dev.twitch.tv/docs/eventsub/handling-webhook-events/)
- [Twilio webhook request validation](https://www.twilio.com/docs/usage/webhooks/webhooks-security)
