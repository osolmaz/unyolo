# hf-broker — Specification

Status: draft for review, 2026-07-05. Companion to
[hf-auth-helper](https://github.com/osolmaz/hf-auth-helper); successor to
the GitCBA prototype, which it retires.

## Purpose

A small self-hosted broker that lets an agent work *directly* on Hugging
Face repos and buckets — no human click per change — while guaranteeing
that nothing the agent does is irreversible. The agent never holds a real
Hub credential: it talks to the broker, the broker enforces append-only
semantics per request, and only then forwards the operation upstream with
a server-side write token the agent can never read.

## Position in the Trust Ladder

| Level | Mode | Enforced by | Tool |
|-------|------|-------------|------|
| 1 | Propose-only: agent opens PRs, human merges | Hub token scopes | hf-auth-helper |
| 2 | Reversible autonomy: agent pushes commits directly, history is append-only | this broker | hf-broker |
| 3 | Bucket writes: append-only objects, snapshot before overwrite | this broker | hf-broker |
| 4 | Elevated operations: time-boxed, human-approved grants | this broker | hf-broker |

Level 1 needs no infrastructure and stays the recommendation for
low-trust setups. The broker exists for workflows where per-change review
is not sustainable (e.g. a scraper updating a dataset every few hours)
and the platform lacks the protections that would make direct writes safe
(the Hub has no force-push protection and no bucket versioning).

## Rationale

Prompt-injected agents cannot be prevented from *attempting* destructive
operations; the only defenses that hold are (a) credentials that cannot
express destruction and (b) a boundary the agent cannot cross that
refuses destruction per request. hf-auth-helper is (a). The broker is
(b): it synthesizes, at the request level, the two protections the Hub
does not offer — non-fast-forward rejection for git refs and
versioning/soft-delete for buckets — so that a full write token upstream
degrades to an append-only capability downstream.

Reversibility, not review, is the safety property: every accepted git
operation is undoable with `git revert`; every accepted bucket overwrite
leaves a snapshot; deletions are refused outright (or explicitly granted,
level 4).

## Threat Model

**Protected against:** history rewrites (force-push), branch/tag
deletion, bucket object deletion and unsnapshotted overwrite, credential
theft from the agent machine (the agent only ever holds a broker secret,
revocable and useless outside the broker), scope escape (operations
outside the configured repos/buckets are refused).

**Required for the guarantees to hold:** the broker process and its
upstream token must be unreachable from the agent's execution context —
a separate machine (Tailnet deployment, as with GitCBA) or at minimum a
separate Unix user. A broker running as the same user as the agent is
decoration. Network reachability is never treated as authorization;
every request must present a broker secret.

**Not protected against:** exfiltration of anything readable through the
broker (same residual risk as level 1); junk accumulation within scope
(spam commits, new branches, new objects — reversible and quota-bounded,
but real); denial of service against the broker itself. Stated
deliberately: the guarantee is "nothing irreversible," not "nothing
annoying."

## Security Invariants (inherited from GitCBA, non-negotiable)

- No API — internal or external — returns credential material: not the
  upstream token, not broker secrets, not reversible blobs, not token
  metadata.
- Scope configuration is a manually edited file; there is no endpoint to
  read or change it.
- The broker exposes no generic Hub API proxy, no arbitrary command
  execution, and no repo/bucket administration operations (create,
  delete, settings, members) in any mode.
- Every broker endpoint requires authentication; binding is localhost by
  default, exposure is Tailnet-or-equivalent only.
- Audit log lines never contain secrets, request bodies, or pack
  contents.
- Fail closed: a request the policy engine cannot classify is refused.

## Architecture

One Go binary, three surfaces:

```text
agent ── shared secret ──> hf-broker ── HF write token ──> huggingface.co
                            ├─ git smart-HTTP proxy   (level 2)
                            ├─ S3-compatible proxy    (level 3)
                            └─ health + (later) grant endpoints (level 4)
```

Configuration: environment for secrets (`BROKER_SHARED_SECRET`,
`BROKER_HF_TOKEN`), a hand-edited `scope.json` for what is reachable:

```json
{
  "repos": [
    {"id": "osolmaz/scraped-news", "type": "dataset", "mode": "append-only"}
  ],
  "buckets": [
    {"id": "osolmaz/pipeline-output", "mode": "append-only",
     "snapshot_prefix": "snapshots/"}
  ]
}
```

Modes: `read-only`, `append-only` (default), and — level 4 only —
temporary elevations layered on top by grants. There is no standing
"full write" mode; if a mode name like that ever seems needed, the answer
is a grant.

## Git Proxy (level 2)

Routes mirror git smart HTTP for configured repos only:

```text
GET  /{repo_path}/info/refs?service=git-upload-pack     (fetch/clone)
POST /{repo_path}/git-upload-pack
GET  /{repo_path}/info/refs?service=git-receive-pack    (push)
POST /{repo_path}/git-receive-pack
```

plus pass-through of the Xet/LFS transfer endpoints those flows require
(uploads to content-addressed storage are additive by construction and
carry no destructive capability).

### Push enforcement

Every `git-receive-pack` body is parsed (pkt-line framing) into ref
update commands `old-sha new-sha refname` before anything is forwarded.
Rules, applied per command, all-or-nothing for the push:

1. **Deletions refused**: `new-sha == 0` for any ref.
2. **Branch creation allowed**: `old-sha == 0` on `refs/heads/*`.
3. **Fast-forward required**: for updates to existing `refs/heads/*`,
   `old-sha` must be an ancestor of `new-sha`; otherwise the push is a
   history rewrite and is refused.
4. **Tags append-only**: new tags allowed, updates or deletions of
   existing `refs/tags/*` refused.
5. **Other ref namespaces** (`refs/pr/*` etc.): creation and fast-forward
   updates allowed, same deletion/rewrite rules.
6. Pushes exceeding the configured pack-size cap are refused before
   buffering completes (big content belongs to Xet, not the pack).

### Ancestry verification without duplicating data

The broker maintains, per configured repo, a **commits-only mirror**:
`git clone --bare --filter=tree:0` — the commit graph without trees or
blobs, megabytes even for terabyte repos. On each push: fetch the mirror
(commit objects only), index the incoming pack's commit objects, then
`git merge-base --is-ancestor old new`. The mirror also serves as an
append-only record of every history the broker has ever accepted.

Fallback if the Hub's git server rejects partial-clone filters
(pre-implementation verification item V1): **stage-then-promote** — the
push is forwarded to a temporary ref upstream (always safe), ancestry is
checked by walking the upstream commit listing API from `new` to `old`,
and on success the real ref is advanced with an empty-pack push (objects
already upstream). No local state at all in this variant.

## Bucket Proxy (level 3)

An S3-compatible subset for configured buckets, so existing tooling
(`hf` CLI, boto3, s5cmd) points at the broker via its endpoint-URL
setting. Per-verb policy in `append-only` mode:

| Operation | Policy |
|-----------|--------|
| GET / HEAD / LIST | allowed within scope |
| PUT / multipart to a **new** key | allowed |
| PUT / multipart to an **existing** key | snapshot, then allowed |
| DELETE (any form) | refused (grantable, level 4) |
| Bucket create/delete/settings | refused, not grantable |

**Snapshot** = server-side copy of the current object to
`{snapshot_prefix}{timestamp}/{key}` before the overwrite is forwarded.
Server-side copies move content hashes, not bytes: no data flows through
the broker, and Xet chunk dedup makes the storage cost near zero.
Snapshots are written through the same upstream token but are not
reachable for writes through any broker route (the snapshot prefix is
read-only downstream), so the agent cannot destroy its own undo log.

## Grants (level 4)

For the rare genuinely destructive need (delete a bucket prefix, prune a
branch), the agent may *request* an elevation; nothing is self-service:

1. Agent calls the request endpoint: operation class, target, duration,
   free-text reason.
2. The broker notifies the operator out-of-band and holds the request.
   Approval happens through an operator-only channel; nothing reachable
   with the agent's secret can approve.
3. On approval, the named operations are permitted for the grant's
   duration (default 15 minutes, hard cap 1 hour), for the named target
   only, and every use is audit-logged. Expiry is absolute; there is no
   renewal without a fresh approval.

Time-boxing here is honest about what it buys: it limits credential
persistence and forgotten access, not in-window damage — which is why
grants are narrow and short, and why nothing irreversible is ever
standing policy.

### Approval channels

**Channel separation is a security requirement, not a UX choice**: the
approval action must travel on a channel the agent's execution context
cannot reach or forge. In particular, approval is never an endpoint on
the broker surface the agent talks to — anything reachable with (or
adjacent to) the agent's secret is disqualified by construction.

Two channels are specified:

1. **Operator CLI on the broker host** (M3). `hf-broker grants` lists
   pending and active grants; `hf-broker approve <id> --minutes 15` and
   `hf-broker deny <id>` decide them; `hf-broker revoke <id>` kills an
   active grant early. The CLI talks to the broker process locally
   (unix socket or localhost port not exposed beyond the host);
   authentication is possession of a shell on the broker host, which the
   agent does not have. Zero additional secrets, zero additional
   surface.

2. **Push-notification approval** (M4): **Telegram bot**. The grant
   request is sent as a Telegram message to the operator's chat,
   carrying the request's operation class, target, duration, and
   reason, with inline Approve / Deny buttons. The decision
   authenticates through the bot conversation itself: the bot token and
   the operator's chat id are configured on the broker host, the broker
   accepts a decision only from that chat id, and nothing about the
   flow travels over a URL the agent could forge. Telegram is the v1
   notifier because it gives two-way interaction (buttons, replies) with
   a single bot token and no server-side callback to host — the broker
   long-polls the Bot API, so it works from behind the Tailnet with no
   inbound exposure. Deny requires no action: unapproved requests expire
   on their own (default 10 minutes pending, then auto-denied).

   The notifier is an interface, Telegram its first implementation.
   Noted for later behind the same interface, not in scope for v1:

   - **ntfy** — one-way unless self-hosted with auth; would pair a
     notification with CLI or reply-code approval to keep the decision
     off any agent-reachable surface.
   - **Slack** — interactivity is callback-URL based, so it would need an
     operator-side relay to preserve the no-inbound-surface invariant;
     heavier than Telegram, fits team operation.
   - **Signal / Matrix** — viable for operators who prefer them; each
     needs a bot with an outbound-poll or operator-relayed decision path.

There is no approval web UI in v1 (see Non-Goals). If one is ever added,
it is a read-mostly operator dashboard (pending requests, active grants,
audit tail, revoke) bound to an operator-only interface — reached from
the broker host, never from the agent's network scope — and the approval
mechanism itself remains one of the two channels above.

## Audit

Structured log line per request: timestamp, client id, operation class,
target, decision (allowed / refused / grant-used), refusal reason,
upstream status. Never bodies, never secrets. The audit stream is the
operator's answer to "what did the agent actually do?"

## Client Setup

```sh
# git: the broker is just a remote
git remote set-url origin https://broker.tailnet:8080/datasets/osolmaz/scraped-news

# hf CLI / S3 tooling: endpoint override + broker secret as the key
```

The intended pairing: `hf-auth-helper agent login` for level-1 access to
everything, broker remotes for the specific repos/buckets that need
direct writes.

## Milestones

- **M1 — git append-only proxy**: auth, scope file, upload-pack
  pass-through, receive-pack enforcement with commits-only mirror,
  audit. Shippable alone; delivers level 2.
- **M2 — bucket proxy**: S3 subset, verb policy, server-side snapshots.
- **M3 — grants**: request/approve/expire, operator CLI approval
  channel.
- **M4 — Telegram approvals**: grant requests as Telegram messages with
  inline Approve/Deny buttons, decided over outbound Bot API long-polling
  (no inbound surface), with pending-request expiry. Other notifiers
  (ntfy, Slack, Signal/Matrix) plug in behind the same interface later.

## Non-Goals (v1)

- GitHub support (native rulesets already provide level 2 there).
- Arbitrary Hub API proxying, repo/bucket administration, org management.
- Multi-tenant operation or per-agent identities beyond distinct shared
  secrets (one secret per agent client is supported; RBAC is not).
- Installing itself as a system service; deployment is documented, not
  automated.
- An approval web UI. Approvals are CLI (M3) and notifications (M4);
  a read-mostly operator dashboard may come later, but is never the
  approval mechanism.

## Pre-Implementation Verification Items

- **V1**: does the Hub git server support partial clone
  (`--filter=tree:0`)? Decides mirror vs stage-then-promote.
- **V2**: does the Hub accept pushes to arbitrary ref namespaces (needed
  only for stage-then-promote)?
- **V3**: exact Xet/LFS endpoint set a push/upload flow touches through a
  proxied remote, to enumerate the pass-through allowlist.
- **V4**: S3-compatible API coverage of server-side copy
  (`x-amz-copy-source`) on Hub buckets, for snapshots.
