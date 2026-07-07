# hf-broker — Specification

Status: implementation-ready, 2026-07-06. Companion to
[hf-auth-helper](https://github.com/osolmaz/hf-auth-helper); successor to
the GitCBA prototype, which it retires.

This document is written to be handed off: an implementer should be able
to build M1 end to end from it without further design decisions. Where a
behavior depends on unverified Hub behavior, the spec names both the
assumption and the concrete fallback, so no item is a blocker.

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

`hf-broker doctor` is the local verification tool for this runtime
boundary; `hf-broker doctor isolation` is the explicit form. It checks
the configured agent identity, broker process, token file, and optional
Unix socket and fails closed when the agent is host root,
root-equivalent through groups such as `sudo`, `wheel`, `docker`, `lxd`,
or `incus`, can read or modify the token file, can read the broker
process environment, can write/connect to the checked Unix socket, or
shares the broker UID. The doctor is a checker, not a sandbox: if it
reports unsafe, the deployment must be changed; no broker policy can
protect a local token from host root.

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

Configuration: environment for broker secrets (`HF_BROKER_SHARED_SECRET`
or `HF_BROKER_SECRETS_FILE`), environment or broker-only file for the
upstream token (`HF_BROKER_HF_TOKEN` or `HF_BROKER_HF_TOKEN_FILE`), and
a hand-edited `scope.json` for what is reachable:

```json
{
  "repos": [
    {
      "id": "osolmaz/scraped-news",
      "type": "dataset",
      "mode": "append-only",
      "grant_policy": {
        "git_history_rewrite": {
          "default_minutes": 5,
          "max_minutes": 60,
          "default_max_uses": 1,
          "max_uses": 3
        },
        "git_ref_delete": {
          "default_minutes": 5,
          "max_minutes": 60,
          "default_max_uses": 1,
          "max_uses": 3
        },
        "git_tag_update": {
          "default_minutes": 5,
          "max_minutes": 60,
          "default_max_uses": 1,
          "max_uses": 3
        }
      }
    }
  ],
  "buckets": [
    {"id": "osolmaz/pipeline-output", "mode": "append-only",
     "snapshot_prefix": "snapshots/",
     "grant_policy": {
       "bucket_delete": {"allowed": ["object", "prefix"]}
     }}
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

The chosen approach (V1 confirmed, see Verification Status) is a
per-repo **commits-only mirror**: `git clone --bare --filter=tree:0` —
the commit graph without trees or blobs, megabytes even for terabyte
repos. Verified against a live Hub dataset: the filtered clone returned
only commit objects (0 trees, 0 blobs), 56 KiB for 100 commits.

Enforcement algorithm per push, per updated `refs/heads/*` or
`refs/tags/*` command with a non-zero `old-sha`:

1. Acquire the per-repo lock (see Concurrency).
2. Ensure the mirror exists and is current: `git -C <mirror> fetch
   --filter=tree:0 origin '+refs/heads/*:refs/heads/*'
   '+refs/tags/*:refs/tags/*'` (the mirror uses the upstream token).
3. Confirm the client-claimed `old-sha` matches the mirror's current
   value for that ref. If it does not, the client is working from stale
   state; refuse and let it re-fetch (prevents lost-update races and
   TOCTOU between check and forward).
4. Unpack the incoming pack's commit objects into the mirror's object
   store (`git index-pack --stdin --fix-thin` against a copy, or
   `git unpack-objects`; commit objects reference trees the mirror lacks,
   so use `--filter`-tolerant reads: ancestry needs only commit parent
   links, which are self-contained in commit objects).
5. `git -C <mirror> merge-base --is-ancestor <old-sha> <new-sha>`: exit 0
   → fast-forward, allowed; non-zero → history rewrite, refuse.
6. If all commands in the push pass, forward the original request
   upstream; on a 2xx upstream response, advance the mirror's refs to the
   new values; release the lock.

The mirror doubles as an append-only record of every history the broker
has accepted — a recovery aid, though it holds commit graph only, not
file contents.

**Documented fallback (only if a future Hub change breaks partial
clone): stage-then-promote** — forward the push to a temporary
upstream ref (always safe: new ref), check ancestry by walking the
upstream commit-listing API from `new` back toward `old`, and on success
advance the real ref with an empty-pack push (objects already upstream),
then delete the temp ref via a grant-free internal path. No local state.
Not implemented in v1 because V1 confirmed the mirror path works; kept
here so the fallback needs no new design if it is ever needed.

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
   duration (default 5 minutes, hard cap 1 hour), for the named target
   only, and every use is audit-logged. Expiry is absolute; there is no
   renewal without a fresh approval.

Time-boxing here is honest about what it buys: it limits credential
persistence and forgotten access, not in-window damage. Grants therefore
have two additional constraints: a narrow target and an explicit use
budget or exact execution plan.

### Grant protocol v1

Grant requests are typed resources. The broker never accepts a generic
Hub API path, arbitrary HTTP method, caller-supplied upstream headers, or
opaque JSON patch as a grant.

Smallest valid git override request:

```json
{
  "operation": "git_history_rewrite",
  "target": "dataset/osolmaz/scraped-news",
  "ref": "refs/heads/main",
  "reason": "repair main after a bad push"
}
```

The broker fills defaults from `scope.json` grant policy: `minutes`
defaults to `5`, `max_uses` defaults to `1`, and no grant may exceed
`60` minutes. A push request is one use regardless of how many commits it
contains.

Grant modes:

| Mode | Used for | Behavior |
|------|----------|----------|
| `window` | Git push overrides | Operator approves a short-lived permission for one client, target, ref, and use budget. |
| `execution` | Settings/admin/bucket-destructive actions | Operator approves one broker-built plan. The broker executes that exact plan once. |

Window grants are appropriate when the broker cannot know the final
request body until the agent performs the operation, as with
`git-receive-pack`. Execution grants are required for settings,
repository administration, and bucket deletion because the broker can
precompute and display the exact mutation before approval.

Grant lifecycle:

```text
pending -> active -> consumed
pending -> denied
pending -> expired
active  -> expired
active  -> revoked
active  -> consumed
```

Only `active` grants can be used. A consumed, expired, denied, or revoked
grant is terminal. Reusing a terminal grant fails closed and is
audit-logged.

### Grant action registry

Initial grantable actions:

| Action | Mode | Target | Notes |
|--------|------|--------|-------|
| `git_history_rewrite` | `window` | repo + exact ref | May override a non-fast-forward update of a non-tag, non-replace ref when policy and use budget allow it. |
| `git_ref_delete` | `window` | repo + exact ref | May override deletion of a non-tag, non-replace ref, including a branch, when policy and use budget allow it. |
| `git_tag_update` | `window` | repo + exact tag ref | May override moving or deleting a tag when policy and use budget allow it. |
| `repo_create_private` | `execution` | exact repo id | Creates only a private repo predeclared in `scope.json`. |
| `repo_metadata_update` | `execution` | exact repo id | Non-security metadata only, such as description, tags, or card metadata. |
| `repo_visibility_update` | `execution` | exact repo id | Exact `private_to_public` or `public_to_private` direction must be allowed by policy. |
| `bucket_delete` | `execution` | bucket object or prefix | Requires a deletion manifest; object/prefix shape must be allowed by policy. |

Never grantable through hf-broker:

- generic Hugging Face API proxying
- arbitrary HTTP requests
- token, secret, webhook, or credential changes
- members, permissions, org roles, or resource groups
- repo transfer, namespace move, or ownership changes
- billing, paid hardware, storage tier, or quota changes
- Space secrets or variables that may expose credentials
- repo or bucket deletion as a whole

### Execution plans

Execution grants are approved over a canonical plan, not over loose text.
The broker builds the plan after reading upstream state. The operator
sees the action, target, before/after diff, risk label, expiry, and plan
hash.

Example visibility plan:

```json
{
  "mode": "execution",
  "action": "repo_visibility_update",
  "target": "dataset/dutifulbob/hf-broker-smoke",
  "before": {"private": true},
  "after": {"private": false},
  "plan_hash": "sha256:..."
}
```

Before execution, the broker re-reads upstream state under the relevant
target lock. If the current state no longer matches the plan's `before`
snapshot, execution is refused and a fresh request is required. Execution
plans are single-use; there is no multi-use settings/admin grant.

### Idempotency and concurrency

Grant requests may include `client_request_id`. The tuple
`client + client_request_id` is idempotent: retrying the same request
returns the original pending, active, denied, expired, consumed, or
revoked grant instead of creating a duplicate Telegram prompt.

The broker locks the relevant target while validating and executing a
grant use. Window grants are durably reserved, with a `reserved_at`
timestamp, before the broker forwards the operation upstream, so a crash
cannot reopen the same budget after a dangerous push has been attempted.
The reservation is released only for HTTP-layer refusals that could not
have applied a Git update. Once a receive-pack response is observed,
non-accepted or malformed results keep the reservation fail-closed unless
every requested ref is accepted and the reservation is converted into a
consumed use. If the broker restarts with a reservation that has remained
in-flight longer than the configured upstream timeout plus recovery
grace, the periodic grant sweep marks it retained and updates the
operator message for review. Execution grants are consumed after the
planned upstream mutation succeeds; if an upstream call may have
partially applied side effects, the broker records the ambiguous result
and refuses retries until an operator resolves it.

### Notification state

Notifier message metadata (`chat_id`, `message_id`, notifier kind) is
stored with the grant so restarts can still update operator messages.
Telegram messages are updated when a request is approved, denied, used,
expired, revoked, or fails during execution. Buttons are removed after
the first terminal decision.

Operator prompts must show:

- action and mode
- client
- target and ref/object/prefix
- requested duration and use budget
- reason
- before/after diff for execution plans
- risk label for high-risk actions such as `private_to_public`
- pending expiry

### Audit requirements

Every grant lifecycle event is audit-logged. Grant audit entries include
at least:

```json
{
  "event": "grant-used",
  "grant_id": "...",
  "client": "local-smoke",
  "action": "git_history_rewrite",
  "target": "dataset/dutifulbob/hf-broker-smoke",
  "ref": "refs/heads/main",
  "mode": "window",
  "plan_hash": "",
  "max_uses": 1,
  "used_count": 1,
  "operator": "telegram:@operator",
  "upstream_status": 200
}
```

Audit lines never include upstream tokens, broker client secrets,
Telegram tokens, request bodies that may contain secrets, pack contents,
or object payloads.

### Approval channels

**Channel separation is a security requirement, not a UX choice**: the
approval action must travel on a channel the agent's execution context
cannot reach or forge. In particular, approval is never an endpoint on
the broker surface the agent talks to — anything reachable with (or
adjacent to) the agent's secret is disqualified by construction.

Two channels are specified:

1. **Operator CLI on the broker host** (M3). `hf-broker grants` lists
   pending and active grants; `hf-broker approve <id> --minutes 5` and
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
mechanism itself remains one of the channels above.

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

## Repository Layout

Go module `github.com/osolmaz/hf-broker`, Go 1.23+. One binary
(`cmd/hf-broker`), business logic in `internal/` so nothing but the
command is importable.

```text
cmd/hf-broker/main.go            wiring, flag/env parsing, signal handling
internal/config/                 env + scope.json loading and validation
internal/auth/                   shared-secret extraction and constant-time check
internal/isolation/              local runtime isolation doctor checks
internal/scope/                  scope model + allow/deny decision engine
internal/gitproxy/               receive-pack parsing, enforcement, upstream forward
internal/gitproxy/pktline/       pkt-line framing reader/writer
internal/mirror/                 commits-only mirror lifecycle + ancestry check
internal/bucketproxy/            S3-verb policy + server-side snapshot (M2)
internal/grants/                 grant store, expiry, decision (M3)
internal/notify/                 Notifier interface + telegram impl (M4)
internal/httpapi/                router, handlers, refusal responses, audit
internal/audit/                  structured slog wiring
```

Boundaries (enforced by Slophammer `dependency_boundaries`): `httpapi`
depends on the feature packages; feature packages depend on `scope`,
`config`, `audit`; `scope`/`config`/`auth`/`pktline` depend on nothing
internal. Domain logic (parsing, policy decisions, ancestry) stays free
of `net/http` so it is unit-testable without a server.

## Configuration

### Secrets (never in files the agent could read)

| Variable | Required | Meaning |
|----------|----------|---------|
| `HF_BROKER_HF_TOKEN` | yes unless `HF_BROKER_HF_TOKEN_FILE` set | upstream Hugging Face write token; used only for outbound Hub requests |
| `HF_BROKER_HF_TOKEN_FILE` | yes unless `HF_BROKER_HF_TOKEN` set | path to a broker-only file containing the upstream Hugging Face write token; preferred for same-host deployments |
| `HF_BROKER_SHARED_SECRET` | yes unless `HF_BROKER_SECRETS_FILE` set | single client secret; min 32 bytes |
| `HF_BROKER_SECRETS_FILE` | no | path to a file of `name = secret` lines for per-client secrets (one secret per agent); enables named clients in audit |
| `HF_BROKER_BIND_ADDR` | no | default `127.0.0.1` |
| `HF_BROKER_PORT` | no | default `8080` |
| `HF_BROKER_SCOPE_FILE` | no | default `scope.json` |
| `HF_BROKER_STATE_DIR` | no | default `./state`; holds mirrors and grant store |
| `HF_BROKER_MAX_PACK_BYTES` | no | default `26214400` (25 MiB) |
| `HF_BROKER_HF_TIMEOUT` | no | upstream request timeout seconds, default `120` |
| `HF_BROKER_TELEGRAM_BOT_TOKEN` | no (M4) | bot token for approval channel |
| `HF_BROKER_TELEGRAM_CHAT_ID` | no (M4) | the single operator chat id decisions are accepted from |

Startup validation fails closed: missing required secret, setting both
`HF_BROKER_HF_TOKEN` and `HF_BROKER_HF_TOKEN_FILE`, unreadable or empty
token file, unreadable or invalid `scope.json`, secret under 32 bytes,
or a `snapshot_prefix` that overlaps a writable path all abort boot with
a specific error. The token value is never logged, even at startup.

### Local isolation doctor

The broker binary includes a local host checker:

```sh
hf-broker doctor \
  --agent-user agent \
  --broker-pid 12345 \
  --token-file /etc/hf-broker/hf-token \
  --socket /run/hf-broker/hf-broker.sock
```

`hf-broker doctor isolation` is equivalent and remains the explicit
subcommand form for scripts.

Options:

- `--agent-user` or `--agent-uid`: the agent identity to evaluate. If
  no agent identity or process is supplied, the current doctor process is
  checked so stale sessions with old supplementary groups are reported.
- `--agent-pid`: optional running agent process. When supplied, the
  doctor checks process UID, effective and permitted Linux capabilities,
  and HF token variable names in the process environment.
- `--broker-pid`: optional running broker process. When supplied, the
  doctor checks that the broker UID differs from the agent UID and uses
  an active probe to verify the agent cannot open
  `/proc/<broker-pid>/environ`.
- `--token-file`: optional upstream token file. The doctor checks Unix
  mode bits, parent-directory writability, POSIX ACL presence, and active
  read/write open probes when it can run as the agent identity.
- `--socket`: optional Unix socket path. The doctor checks that the path
  is a socket, is not world-writable, is not writable/connectable by the
  agent identity, does not use POSIX ACLs that make mode-bit checks
  incomplete, and is not under an agent-writable parent directory.
- `--json`: emits a stable machine-readable report.

Exit codes:

- `0`: isolation checks are OK.
- `1`: unsafe; the agent can plausibly read or bypass the credential.
- `2`: inconclusive; a required fact or active probe could not be
  verified from the current execution context.
- `64`: invalid arguments.

The doctor never prints secret values. Active probes only attempt
non-destructive opens of protected files and broker process environment
files; they do not read, write, or echo contents. Token-file option
values are not echoed in findings because configuration mistakes can put
the token value there. POSIX ACLs on token-file or socket paths make
mode-bit checks incomplete, so the report is inconclusive. Host-root or
root-equivalent agents are always unsafe because local permissions
cannot protect a credential from them.
For file-token deployments, `--token-file` must be supplied for an OK
result. `--broker-pid` verifies broker environment reachability and is
sufficient only for broker environment-token deployments; if the broker
process advertises `HF_BROKER_HF_TOKEN_FILE` and no `--token-file` is
supplied, the report is inconclusive.

### scope.json (full schema)

```json
{
  "repos": [
    {
      "id": "osolmaz/scraped-news",
      "type": "dataset",
      "mode": "append-only",
      "grant_policy": {
        "git_history_rewrite": {
          "default_minutes": 5,
          "max_minutes": 60,
          "default_max_uses": 1,
          "max_uses": 3
        },
        "git_ref_delete": {
          "default_minutes": 5,
          "max_minutes": 60,
          "default_max_uses": 1,
          "max_uses": 3
        },
        "git_tag_update": {
          "default_minutes": 5,
          "max_minutes": 60,
          "default_max_uses": 1,
          "max_uses": 3
        },
        "repo_metadata_update": {
          "default_minutes": 5,
          "max_minutes": 60
        },
        "repo_visibility_update": {
          "allowed": ["public_to_private"]
        }
      }
    }
  ],
  "buckets": [
    {
      "id": "osolmaz/pipeline-output",
      "mode": "append-only",
      "snapshot_prefix": "snapshots/",
      "grant_policy": {
        "bucket_delete": {
          "allowed": ["object", "prefix"],
          "default_minutes": 5,
          "max_minutes": 60
        }
      }
    }
  ]
}
```

- `repos[].id`: `owner/name`, required, must not contain `..` or a
  second slash beyond the single separator.
- `repos[].type`: one of `model` | `dataset` | `space`. Determines the
  upstream URL prefix (see Request Handling). Required.
- `repos[].mode`: `read-only` | `append-only`. Default `append-only`.
- `repos[].grant_policy`: optional object listing grantable operations
  for this exact repo entry. Omitted means no grants are available for
  this repo beyond standing `read-only` or `append-only` policy.
- `repos[].grant_policy.git_history_rewrite`,
  `repos[].grant_policy.git_ref_delete`, and
  `repos[].grant_policy.git_tag_update`: optional window-grant policies
  for the matching dangerous git capability on refs in this repo. Fields:
  - `default_minutes`: default grant duration. Default `5`; must be
    between `1` and `60`.
  - `max_minutes`: longest allowed grant duration. Default `60`; must be
    at least `default_minutes` and at most `60`.
  - `default_max_uses`: default push-use budget. Default `1`; one push
    request is one use, regardless of commit count.
  - `max_uses`: largest requested push-use budget accepted by policy.
    Default `default_max_uses`; must be at least `default_max_uses` and
    at most `25`.
- `repos[].grant_policy.repo_create_private`: optional execution-grant
  policy allowing the broker to create this exact repo id as private.
  It accepts `default_minutes` and `max_minutes`.
- `repos[].grant_policy.repo_metadata_update`: optional execution-grant
  policy for non-security metadata such as description/tags/card
  metadata. It accepts `default_minutes` and `max_minutes`.
- `repos[].grant_policy.repo_visibility_update`: optional
  execution-grant policy for visibility changes. It requires `allowed`,
  a non-empty list of `private_to_public` and/or `public_to_private`,
  and accepts `default_minutes` and `max_minutes`. `private_to_public`
  should be configured sparingly because it publishes data.
- `buckets[].id`: `owner/name`, same validation.
- `buckets[].mode`: `read-only` | `append-only`. Default `append-only`.
- `buckets[].snapshot_prefix`: required when mode is `append-only`;
  default `snapshots/`. Must end with `/`. Writes under this prefix are
  refused for all clients (it is the undo log).
- `buckets[].grant_policy`: optional object listing grantable operations
  for this exact bucket entry.
- `buckets[].grant_policy.bucket_delete`: optional execution-grant
  policy for object and prefix deletion. It requires `allowed`, a
  non-empty list of `object` and/or `prefix`, and accepts
  `default_minutes` and `max_minutes`.
- Unknown fields are rejected (fail closed), so a typo cannot silently
  widen access.
- There is no API to read or reload this file at runtime; changing scope
  is edit-file-then-restart. (Optional `SIGHUP` reload may be added later
  but is not required for v1.)

## Request Handling

### Authentication

Every route except `GET /healthz` requires the shared secret, accepted
two ways (identical to GitCBA, so stock `git` and S3 tools work):

- `Authorization: Bearer <secret>`, or
- HTTP Basic auth where the **password** is the secret (username
  ignored) — this is how `git` and boto3 present credentials.

The presented secret is compared constant-time against each configured
client secret; a match resolves the client name (for audit). No match →
`401` (missing) or `403` (present but wrong). Never both branches leak
which secrets exist.

### Routing and upstream mapping

Broker path → upstream URL, by repo type:

| Broker request | Upstream |
|----------------|----------|
| `/{owner}/{repo}.git/...` (model) | `https://huggingface.co/{owner}/{repo}.git/...` |
| `/datasets/{owner}/{repo}.git/...` | `https://huggingface.co/datasets/{owner}/{repo}.git/...` |
| `/spaces/{owner}/{repo}.git/...` | `https://huggingface.co/spaces/{owner}/{repo}.git/...` |
| bucket S3 verbs | Hub S3-compatible endpoint for `{owner}/{repo}` |

The `(owner, repo, type)` triple must match a `scope.json` entry or the
request is refused before any upstream contact. Upstream base URLs are
compile-time constants; only the policy-approved `owner`/`repo`/path-tail
is interpolated, so the agent cannot redirect the proxy elsewhere.

Outbound requests: strip the client's `Authorization`/`Cookie`, inject
the upstream token (`Basic x-access-token:<token>` for git,
SigV4/`Bearer` as the S3 endpoint requires for buckets), copy through the
remaining non-hop-by-hop headers. Response body is streamed back.

### Refusal responses (must be legible to the client)

A refusal must reach the human at the terminal, not just return a bare
500:

- **Git push refusals**: return HTTP `200` with a valid
  `git-receive-pack` **report-status** that reports the offending ref as
  failed with a message (`ng refs/heads/main non-fast-forward (hf-broker:
  history rewrite refused)`), *and* an ERR sideband line so `git push`
  prints the reason. The push must be rejected **before** any bytes reach
  upstream. (If report-status framing proves impractical for a given
  client, the documented fallback is HTTP `403` with the reason in the
  body — acceptable but less clean.)
- **Scope / auth refusals** on any route: `403` / `401` with a one-line
  plain reason.
- **Bucket refusals**: S3-style XML error body with an `AccessDenied`
  code and an `hf-broker:`-prefixed message, HTTP `403`.

### Health

`GET /healthz` → `200 {"ok": true}`, no auth, no secrets, for liveness
probes.

## On-Disk State

Everything the broker persists lives under `HF_BROKER_STATE_DIR`:

```text
state/
  mirrors/{type}/{owner}/{repo}.git/    commits-only bare mirror per repo
  grants/grants.json                    active + pending grants (M3)
```

- Mirrors are created lazily on first push to a repo and refreshed per
  push. They contain no file contents, only commit graph. Safe to delete;
  they rebuild.
- The grant store is written atomically (temp file + rename), mode `600`.
  Expired grants are pruned on read and on a periodic sweep. Stale
  in-flight use reservations are retained during the sweep so the
  operator can review crash-orphaned budget.
- No token value is ever written to disk by the broker.

## Concurrency

- **Per-repo push serialization**: pushes to the same repo take a
  per-repo mutex spanning the check-then-forward-then-advance-mirror
  window, so two concurrent pushes cannot both pass an ancestry check
  against the same base. Different repos proceed in parallel.
- The claimed-`old-sha`-matches-mirror check (step 3 above) is the
  correctness guard against a push whose base changed after the mirror
  refresh; combined with the lock it makes enforcement atomic per repo.
- Upstream calls carry the request context and the configured timeout;
  a slow upstream cannot hold the lock indefinitely (timeout → refuse,
  release, mirror unchanged).

## Quality Gates and CI

Slophammer Go standards (matching the tools-repo convention). `slophammer.yml`:

```yaml
go:
  coverage:
    threshold: 85
  targets:
    - .
  exclude:
    - "fixtures/**"
  dry:
    max_findings: 0
    paths:
      - cmd
      - internal
    exclude:
      - "**/*_test.go"
      - "fixtures/**"
    structural:
      enabled: true
      threshold: 0.82
      min_lines: 4
      min_nodes: 20
    copied_blocks:
      enabled: true
      min_tokens: 100
  crap:
    max_score: 8
  mutation:
    targets:
      - internal/scope
      - internal/gitproxy
      - internal/mirror
  dependency_boundaries: [ ... as in Repository Layout ... ]
```

CI (`.github/workflows/ci.yml`) runs, pinned to an exact Slophammer
version: `gofmt` check, `go vet ./...`, `go test -race -coverprofile`,
`golangci-lint` v2, coverage gate, `slophammer-go dry/crap/check`. Hard
targets: coverage ≥ 85, CRAP ≤ 8, production DRY = 0. `AGENTS.md` in the
repo restates these and the token-secrecy rule for future agents.

## Testing Strategy

The proxy is testable without a live Hub:

- **Unit (the bulk)**: pkt-line parsing, ref-command extraction,
  enforcement decisions, scope decisions, config validation, snapshot
  key derivation, grant policy validation, grant expiry, grant use
  budgets, idempotency, execution-plan hashing — all pure,
  table-driven.
- **Ancestry**: build throwaway real git repos in `tmp` with `git`
  plumbing, exercise `mirror` against them (fast-forward, non-ff,
  deletion, new branch, new tag, tag move) — real git, no network.
- **Proxy integration**: a stub upstream (`httptest.Server`) mimicking
  the Hub's `info/refs` + `receive-pack` responses asserts that refused
  pushes never reach it and allowed pushes are forwarded verbatim with
  the client Authorization stripped and the upstream token injected.
- **Secrecy invariant test**: capture all log output and both response
  streams across a representative run; assert no configured secret or
  token value ever appears (mirrors hf-auth-helper's approach).
- Live-Hub checks (V2–V4) are done once during their milestone as
  scripted probes, not in the unit suite; their outcomes are recorded
  back into this spec.

## Milestones

Each milestone is its own PR, green on all gates, with the acceptance
criteria below satisfied. M1 is shippable and useful on its own.

### M1 — git append-only proxy (delivers level 2)

Scope: config + scope loading, auth, the four git smart-HTTP routes,
Xet/LFS pass-through, receive-pack parsing and enforcement, commits-only
mirror with ancestry check, per-repo locking, audit, `/healthz`.

Acceptance criteria:
- `git clone` and `git pull` through the broker work for an in-scope repo.
- `git push` of a fast-forward commit succeeds and appears upstream.
- Force-push, branch deletion, tag move, and tag deletion are each
  refused with a legible message and never reach upstream (asserted
  against the stub upstream).
- New branch and new tag pushes succeed.
- A push to an out-of-scope repo, or with a wrong/missing secret, is
  refused before upstream contact.
- Concurrent pushes to one repo cannot both pass an ancestry check
  against the same base (race test).
- Secrecy-invariant test passes. All quality gates green.
- Grant policy settings reject unknown fields, invalid directions,
  invalid bucket delete shapes, over-cap durations, and invalid use
  budgets.

### M2 — bucket proxy (delivers level 3)

Scope: S3-compatible subset for in-scope buckets, per-verb policy,
server-side snapshot before overwrite.

Acceptance criteria:
- GET/HEAD/LIST and PUT-to-new-key work through the broker.
- PUT to an existing key produces a snapshot copy under
  `snapshot_prefix` before the overwrite is forwarded (verified via a
  stub S3 upstream, and once live during the milestone per V4).
- DELETE and any bucket admin verb are refused.
- Writes targeting the snapshot prefix are refused.
- All quality gates green.

### M3 — grants + operator CLI (delivers level 4, host channel)

Scope: grant request endpoint, grant store with absolute expiry, policy
integration (a live grant widens the decision for its target/duration
only), `hf-broker grants|approve|deny|revoke` over a host-local socket.

Acceptance criteria:
- An agent grant request is held pending; nothing reachable with the
  agent secret can approve it.
- `hf-broker approve` enables the granted op for the target only, for the
  duration only; expiry is enforced; `revoke` kills it early.
- `max_uses` defaults to one, decrements after each accepted matching
  push, and closes the grant when exhausted.
- `client_request_id` retries are idempotent and do not create duplicate
  operator prompts.
- Durable notifier metadata lets approve/deny/use/expire/revoke updates
  survive broker restarts.
- Every grant use is audit-logged. All quality gates green.

### M4 — Telegram approvals

Scope: `Notifier` interface + Telegram implementation; grant requests
sent as messages with inline Approve/Deny buttons; decisions read via
outbound Bot API long-polling; pending-request expiry.

Acceptance criteria:
- A request produces a Telegram message with working buttons.
- A decision is accepted only from the configured chat id; a press from
  any other chat is ignored.
- A replayed/stale button press is rejected (one-time id consumed).
- No inbound HTTP surface is added to the broker.
- Unapproved requests auto-deny after the pending timeout.
- All quality gates green.

Other notifiers (ntfy, Slack, Signal/Matrix) plug in behind the same
interface later; out of scope for v1.

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

## Verification Status

None of these blocks starting M1; each has a defined path.

- **V1 — partial clone (`--filter=tree:0`): CONFIRMED (2026-07-06).**
  A filtered bare clone of a live Hub dataset returned commit objects
  only (0 trees, 0 blobs; 56 KiB / 100 commits). The commits-only mirror
  is therefore the chosen ancestry mechanism; stage-then-promote is the
  documented fallback only.
- **V2 — arbitrary ref namespaces: not needed for the chosen path.**
  Only relevant to the stage-then-promote fallback. Verify only if that
  fallback is ever adopted.
- **V3 — Xet/LFS endpoint set touched by a proxied push: confirm during
  M1.** Enumerate by running one real `git push` of a large file through
  the broker with verbose transfer logging and recording every host/path
  hit; the pass-through allowlist is built from that trace. Assumption:
  large-file transfer uses Xet/LFS endpoints that are additive-only
  (uploads to content-addressed storage), so pass-through is safe; the
  M1 acceptance run validates this.
- **V4 — S3 server-side copy on Hub buckets: confirm during M2.** Verify
  `x-amz-copy-source` (or the Hub's documented equivalent) performs a
  metadata-only copy; if the Hub exposes copy under a non-S3 API instead,
  the snapshot step uses that API — the policy (snapshot before
  overwrite) is unchanged, only the call differs.

Probes use a disposable private repo/bucket under an owner the runner can
write to (e.g. `dutifuldev/broker-probe`), and are deleted after. They
require a real write token and so are run by a human-authorized session,
not baked into CI.
