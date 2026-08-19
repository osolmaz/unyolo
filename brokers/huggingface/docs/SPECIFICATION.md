# hf-broker specification

Status: current.

## Purpose

A small self-hosted broker that lets an agent work directly on Hugging Face
repositories while keeping the upstream credential server-side. The broker
classifies every request, applies policy and grants, enforces Git safety, and
only then forwards an allowed operation.

## Safety model

Standing policy covers routine reads and append-only writes. Dangerous Git
operations require time-bounded, use-bounded operator approval. The agent holds
only a broker client secret and cannot retrieve the upstream token or an
operator credential.

## Rationale

Prompt-injected agents cannot be prevented from attempting destructive
operations. The broker is a boundary the agent cannot cross: it withholds the
upstream credential and rejects non-fast-forward Git updates unless a matching
grant is active.

## unYOLO boundary

`github.com/osolmaz/unyolo` is the shared base for the broker family:
`hf-broker`, `gh-broker`, and `sudo-broker`.

hf-broker keeps Hugging Face-specific behavior local: Git/LFS/Xet routing,
commits-only mirrors, append-only enforcement, inference request
classification, Hub token forwarding, and HF-specific approval wording.
unYOLO owns:

- auth
- policy core
- grant lifecycle
- approval workflow
- audit-safe metadata helpers
- notifier interfaces
- reusable Telegram transport and callback handling
- strict config/storage helpers
- privileged service account, managed-file, ownership, systemd unit, and
  activation helpers
- provider-neutral Git parsing helpers shared with `gh-broker`

Reversibility is the standing Git safety property: accepted append-only updates
remain reachable and can be reverted. Destructive operations are refused unless
an explicit request rule and active grant authorize the exact operation.

## Threat model

**Protected against:** unauthorized history rewrites and ref deletion,
credential theft from the agent machine, and scope escape. The agent holds only
a revocable broker secret that is useless outside the broker.

**Required for the guarantees to hold:** the broker process and its
upstream token must be unreachable from the agent's execution context. Use a
separate machine or at minimum a separate Unix user. A broker running as the same user as the agent is
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
broker; junk accumulation within scope (spam commits, new branches, or new
objects that remain reversible and quota-bounded); denial of service against
the broker itself. Stated
deliberately: the guarantee is "nothing irreversible," not "nothing
annoying."

## Security invariants

- Internal and external APIs never return credential material. This includes
  the upstream token, broker secrets, reversible blobs, and token metadata.
- Scope configuration is a manually edited file; there is no endpoint to
  read or change it.
- The broker exposes no generic Hub API proxy or arbitrary command execution.
  Hub administration is available only through fixed, typed catalog
  operations with closed targets and arguments.
- Every broker endpoint requires authentication; binding is localhost by
  default, exposure is Tailnet-or-equivalent only.
- Audit log lines never contain secrets, request bodies, or pack
  contents.
- Fail closed: a request the policy engine cannot classify is refused.

## Architecture

One Go binary exposes bounded agent and operator surfaces:

```text
agent ── shared secret ──> hf-broker ── HF write token ──> huggingface.co
                            ├─ Git smart-HTTP and LFS/Xet
                            ├─ repository reads and inference
                            ├─ agent grant requests
                            └─ separate operator API and Telegram approvals
```

Configuration: environment for broker secrets (`HF_BROKER_SHARED_SECRET`
or `HF_BROKER_SECRETS_FILE`), environment or broker-only file for the
upstream token (`HF_BROKER_HF_TOKEN` or `HF_BROKER_HF_TOKEN_FILE`), and
a hand-edited `scope.json` for what is reachable:

```json
{
  "rules": [
    {
      "id": "append-scraped-news",
      "effect": "allow",
      "clients": ["agent"],
      "operations": ["repo.contents.read", "git.fetch", "git.push.append"],
      "targets": [
        {"kind": "repo", "type": "dataset", "owner": "osolmaz", "name": "scraped-news"}
      ]
    },
    {
      "id": "request-dangerous-git-updates",
      "effect": "request",
      "clients": ["agent"],
      "operations": ["git.push.force", "git.ref.delete", "git.tag.update"],
      "targets": [
        {"kind": "repo", "type": "dataset", "owner": "osolmaz", "name": "scraped-news"}
      ],
      "grant_policy": {
        "default_minutes": 5,
        "max_minutes": 60,
        "request_ttl_minutes": 5,
        "default_max_uses": 1,
        "max_uses": 3
      }
    }
  ]
}
```

Routine operations use standing `allow` rules. Dangerous operations use
`request` rules and temporary grants. There is no standing full-write mode.

## Git proxy

Routes mirror git smart HTTP for configured repos only:

```text
GET  /{repo_path}/info/refs?service=git-upload-pack     (fetch/clone)
POST /{repo_path}/git-upload-pack
GET  /{repo_path}/info/refs?service=git-receive-pack    (push)
POST /{repo_path}/git-receive-pack
```

plus pass-through of the Xet/LFS transfer endpoints those flows require
(uploads to content-addressed storage are additive by construction and
carry no destructive capability). Git LFS upload requests do not carry
the Git ref, so they are authorized against repo-level append permission
or an active append grant; the later `git-receive-pack` request enforces
the concrete ref before any Git mutation reaches upstream.

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
per-repo **commits-only mirror** built with `git clone --bare
--filter=tree:0`. It stores the commit graph without trees or blobs and stays
small even for terabyte-scale repositories. Verified against a live Hub dataset: the filtered clone returned
only commit objects (0 trees, 0 blobs), 56 KiB for 100 commits.

Enforcement algorithm per push, per updated `refs/heads/*` or
`refs/tags/*` command with a non-zero `old-sha`:

1. Acquire the per-repo lock (see Concurrency).
2. Ensure the mirror exists and is current by fetching branch and tag refs
   with the upstream token:

   ```sh
   git -C <mirror> fetch --filter=tree:0 origin '+refs/heads/*:refs/heads/*' '+refs/tags/*:refs/tags/*'
   ```
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

The mirror also records every history the broker has accepted. It can aid
recovery even though it contains only the commit graph and no file contents.

## Grants

For a dangerous Git operation, the agent may request an elevation; nothing is
self-service:

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
  "operation": "git.push.force",
  "target": {
    "kind": "repo",
    "type": "dataset",
    "owner": "osolmaz",
    "name": "scraped-news",
    "refs": ["refs/heads/main"]
  },
  "reason": "repair main after a bad push"
}
```

The broker fills omitted values from the matching `scope.json` grant rule. In
the default policy, `minutes` defaults to `5`, `max_uses` defaults to `25`, and
no force-push grant may exceed `60` minutes. A push request is one use
regardless of how many commits it contains.

Grant modes:

| Mode | Used for | Behavior |
|------|----------|----------|
| `window` | Git push overrides | Operator approves a short-lived permission for one client, target, ref, and use budget. |

Window grants are appropriate when the broker cannot know the final
request body until the agent performs the operation, as with
`git-receive-pack`. The runtime does not expose repository administration,
settings, members, create, delete, or generic Hub API operations.

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
| `git.push.force` | `window` | repo + exact ref | May override a non-fast-forward update of a non-tag, non-replace ref when policy and use budget allow it. |
| `git.ref.delete` | `window` | repo + exact ref | May override deletion of a non-tag, non-replace ref, including a branch, when policy and use budget allow it. |
| `git.tag.update` | `window` | repo + exact tag ref | May override moving or deleting a tag when policy and use budget allow it. |

Repository administration, settings, members, create, delete, and generic Hub
API operations are not grantable.

Never grantable through hf-broker:

- generic Hugging Face API proxying
- arbitrary HTTP requests
- token, secret, webhook, or credential changes
- members, permissions, org roles, or resource groups
- repo transfer, namespace move, or ownership changes
- billing, paid hardware, storage tier, or quota changes
- Space secrets or variables that may expose credentials
- repository deletion

### Idempotency and concurrency

Grant requests must include `client_request_id`. The tuple
`client + client_request_id` is idempotent: retrying the same request
returns the original pending, active, denied, expired, consumed, or revoked
grant instead of creating a duplicate unyolo notification prompt.

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
operator message for review. If an upstream call may have partially applied
side effects, the broker records the ambiguous result and refuses retries
until an operator resolves it. A retained reservation
quarantines the entire grant: no remaining use budget can authorize another
operation until the ambiguous result is resolved.

### Notification state

Notifier message metadata (`chat_id`, `message_id`, notifier kind) is stored
with the grant so restarts can still update operator messages. The generic
approval, notifier metadata, and Telegram transport belong in unYOLO;
hf-broker keeps the HF-specific message summary. Telegram messages are
updated when a request is approved, denied, used, expired, revoked, or fails
during execution. A verified callback can atomically recover missing notifier
metadata after an ambiguous send in the same durable transaction as the grant
decision. The unYOLO Telegram ingress commits callbacks through Operator V1.
A durable write failure leaves the callback unanswered and its Telegram update
pending for retry. After a successful transaction, the ingress acknowledges the
callback and removes the buttons; restart-safe broker status delivery writes the
authoritative terminal text.

Operator prompts must show:

- action and mode
- client
- target and ref
- requested duration and use budget
- reason
- pending expiry

### Audit requirements

Every grant lifecycle event is audit-logged. Grant audit entries include
at least:

```json
{
  "event": "grant-used",
  "grant_id": "...",
  "client": "local-smoke",
  "action": "git.push.force",
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
cannot reach or forge. Approval is never an endpoint on the broker surface the
agent uses. Anything reachable with the agent's secret is disqualified.

Two operator surfaces are supported:

1. **Operator API.** The shared unYOLO operator API runs on a separate
   listener and accepts only credentials from the operator secret file. Trusted
   hosts use this API for bounded lists, durable event streams, and
   revision-checked approve, deny, and revoke decisions. Requesters cancel their
   own pending requests through the authenticated Agent API. Agent client
   credentials cannot use the operator listener.

2. **Telegram.** The grant
   request is sent as a Telegram message to the operator's chat,
   carrying the request's operation class, target, duration, and
   reason, with inline Approve / Deny buttons. The decision
   authenticates through the bot conversation itself: the bot token and
   the operator's chat id are configured on the broker host, the shared
   ingress accepts a decision only from that chat id, and nothing about the
   flow travels over a URL the agent could forge. Telegram gives two-way
   interaction with
   a single bot token and no server-side callback to host. One unYOLO-owned
   ingress long-polls the Bot API and dispatches over authenticated Operator V1,
   so it works from behind the Tailnet with no
   inbound exposure. Deny requires no action: unapproved requests expire
   on their own.

The reusable operator API and Telegram transport belong in unYOLO. hf-broker
owns only the HF-specific prompt text and safe presentation fields.

## Audit

Structured log line per request: timestamp, client id, operation class,
target, decision (allowed / refused / grant-used), refusal reason,
upstream status. Never bodies, never secrets. The audit stream is the
operator's answer to "what did the agent actually do?"

## Client setup

```sh
# Standard Git clients use a deployment-owned HTTPS ingress.
git remote set-url origin https://hf-broker.example.com/datasets/osolmaz/scraped-news
```

## Repository layout

Go package tree `github.com/osolmaz/unyolo/brokers/huggingface`, using the
root unYOLO module and toolchain `go1.26.7`. One binary
(`cmd/hf-broker`), business logic in
`internal/` so nothing but the command is importable.

```text
cmd/hf-broker/main.go            wiring, flag/env parsing, signal handling
internal/config/                 HF env loading and validation
internal/isolation/              local runtime isolation checks
internal/policy/                 HF classifiers over unyolo/authorization/policy
internal/gitproxy/               HF enforcement and upstream forwarding
internal/gitproxy/               provider adapter over unyolo/git/protocol
internal/mirror/                 commits-only mirror lifecycle + ancestry check
internal/hfgrant/                HF target and attr mapping to unyolo/authorization/grants
internal/hfplan/                 immutable grant-plan storage and validation
internal/approval/               HF-specific operator approval wording
internal/jsend/                  JSON API response envelopes
internal/httpapi/                Echo router, handlers, refusal responses, audit
```

Boundaries (enforced by Slophammer `dependency_boundaries`): `httpapi`
depends on Echo and the feature packages; feature packages depend on
`policy`, `config`, `audit`; `policy`/`config`/`auth`/`pktline` depend
on nothing internal. Domain logic (parsing, policy decisions, ancestry)
stays free of HTTP framework types so it is unit-testable without a server.

## Configuration

### Secret files

| Variable | Required | Meaning |
|----------|----------|---------|
| `HF_BROKER_HF_TOKEN` | yes unless `HF_BROKER_HF_TOKEN_FILE` set | upstream Hugging Face write token; used only for outbound Hub requests |
| `HF_BROKER_HF_TOKEN_FILE` | yes unless `HF_BROKER_HF_TOKEN` set | path to a broker-only file containing the upstream Hugging Face write token; preferred for same-host deployments |
| `HF_BROKER_SHARED_SECRET` | yes unless `HF_BROKER_SECRETS_FILE` set | single client secret; min 32 bytes |
| `HF_BROKER_SECRETS_FILE` | no | path to a file of `name = secret` lines for per-client secrets (one secret per agent); enables named clients in audit |
| `HF_BROKER_AGENT_ENDPOINT` | yes | complete `unix`, `tcp`, `activation`, or `fd` endpoint URI |
| `HF_BROKER_OPERATOR_SHARED_SECRET` | no | single operator credential; requires a distinct operator endpoint |
| `HF_BROKER_OPERATOR_SECRETS_FILE` | no | protected named operator credentials file; requires a distinct operator endpoint |
| `HF_BROKER_OPERATOR_ENDPOINT` | with operator credentials | complete endpoint URI distinct from the agent endpoint |
| `HF_BROKER_DEVELOPMENT` | no | explicit `true` enables relative paths, loopback HTTP origins, and loopback TCP port `0` |
| `HF_BROKER_NETWORK_EXPOSURE` | no | must be `allow` before a non-loopback TCP endpoint is accepted |
| `HF_BROKER_SCOPE_FILE` | yes | policy path; absolute in production |
| `HF_BROKER_STATE_DIR` | yes | state path; absolute in production |
| `HF_BROKER_ADMISSION_CONFIG` | no | optional authenticated-client quota configuration |
| `HF_BROKER_MAX_PACK_BYTES` | no | default `26214400` (25 MiB) |
| `HF_BROKER_HF_TIMEOUT` | no | upstream request timeout seconds, default `120` |
| `HF_BROKER_UPSTREAM_HUB_URL` | no | Hub origin, default `https://huggingface.co`; intended for tests or private mirrors |
| `HF_BROKER_UPSTREAM_ROUTER_URL` | no | Router origin, default `https://router.huggingface.co`; intended for tests or private gateways |
| `HF_BROKER_TELEGRAM_BOT_TOKEN` | no | bot token for approval channel |
| `HF_BROKER_TELEGRAM_BOT_TOKEN_FILE` | no | path to a broker-only Telegram bot token file; preferred for same-host services and mutually exclusive with the inline token |
| `HF_BROKER_TELEGRAM_API_BASE` | no | optional Telegram-compatible Bot API base; remote bases require HTTPS and loopback bases may use HTTP |
| `HF_BROKER_TELEGRAM_CHAT_ID` | no | the single operator chat id decisions are accepted from |

Startup validation fails closed: missing endpoints or paths, unsafe network
exposure, missing required secret, setting both
`HF_BROKER_HF_TOKEN` and `HF_BROKER_HF_TOKEN_FILE`, either inline token and
its corresponding token-file variable, unreadable, oversized, or empty token
file, unreadable or invalid `scope.json`, or a secret under 32 bytes all abort
boot with a specific error. The token value is never logged, even at startup.

### Local isolation doctor

The broker binary includes a local host checker on Linux and macOS:

```sh
hf-broker doctor \
  --agent-user agent \
  --broker-pid 12345 \
  --token-file /etc/hf-broker/hf-token \
  --socket /run/unyolo/huggingface/agent/broker.sock
```

`hf-broker doctor isolation` is equivalent and remains the explicit
subcommand form for scripts.

Options:

- `--agent-user` or `--agent-uid`: the agent identity to evaluate. If
  no agent identity or process is supplied, the current doctor process is
  checked so stale sessions with old supplementary groups are reported.
- `--agent-pid`: optional running agent process. When supplied, the
  doctor checks process UID. On Linux it also checks effective and
  permitted capabilities and HF token variable names in the process
  environment. On macOS, process environment checks are reported as
  unknown because the stdlib does not expose a safe no-secret process
  environment-name primitive.
- `--broker-pid`: optional running broker process. When supplied, the
  doctor checks that the broker UID differs from the agent UID. On Linux,
  it uses an active probe to verify the agent cannot open
  `/proc/<broker-pid>/environ`. On macOS, broker environment
  readability is reported as unknown.
- `--token-file`: optional upstream token file. The doctor checks Unix
  mode bits, ACL effects, parent-directory writability, symlink targets,
  and active read/write open probes when it can run as the agent identity.
- `--socket`: optional Unix socket path. The doctor checks that the path
  is a socket, is not world-writable, is not writable/connectable by the
  agent identity, does not have ACLs that grant socket access outside
  mode bits, and is not under an agent-writable parent directory.
- `--json`: emits a stable machine-readable report.

Exit codes:

- `0`: isolation checks are OK.
- `1`: unsafe; the agent can plausibly read or bypass the credential.
- `2`: inconclusive; a required fact or active probe could not be
  verified from the current execution context.
- `64`: invalid arguments.

The doctor never prints secret values. Active probes only attempt
non-destructive opens of protected files, broker process environment
files where the platform exposes them safely, and Unix socket connects;
they do not read, write, or echo contents. Token-file option values are
not echoed in findings because configuration mistakes can put the token
value there. POSIX ACLs on token-file or socket paths make mode-bit
checks incomplete, so the report is inconclusive unless the platform
doctor can inspect the ACL and prove it does not grant access to the
agent. On macOS, unparseable ACL state is reported as unknown. Host-root
or root-equivalent agents are always unsafe because local permissions
cannot protect a
credential from them; on macOS this includes `admin` and `wheel`.
For file-token deployments, `--token-file` must be supplied for an OK
result. `--broker-pid` verifies broker environment reachability and is
sufficient only for broker environment-token deployments; if the broker
process advertises `HF_BROKER_HF_TOKEN_FILE` and no `--token-file` is
supplied, the report is inconclusive.

### scope.json

The runtime format is the wildcard/rule-based policy format specified in
`docs/POLICY_RULES_SPEC.md`. The top level contains only
`rules`; each rule has an `effect` (`allow`, `request`, or `deny`),
`clients`, `operations`, `targets`, and optional `attrs` and
`grant_policy`.

Unknown fields are rejected fail-closed, so a typo cannot silently widen
access. There is no API to read or reload this file at runtime; changing
scope is edit-file-then-restart.

Agent-facing operations are advertised only when a typed runtime adapter is
registered. Repository creation, deletion, settings, membership, and other
supported administrative actions execute through Agent Operations V1 and an
immutable plan. The broker does not expose a generic Hub API proxy.

## Request handling

### Authentication

Every route except `GET /healthz` requires the shared secret, accepted two ways
so stock Git clients work:

- `Authorization: Bearer <secret>`, or
- HTTP Basic auth where the **password** is the secret (username ignored).

The presented secret is compared constant-time against each configured
client secret; a match resolves the client name (for audit). No match →
`401` (missing) or `403` (present but wrong). Never both branches leak
which secrets exist.

### Routing and upstream mapping

The authenticated inference surface is deliberately limited to:

| Broker request | Router request |
|----------------|----------------|
| `GET /v1/models` | `GET {HF_BROKER_UPSTREAM_ROUTER_URL}/v1/models` |
| `POST /v1/chat/completions` | `POST {HF_BROKER_UPSTREAM_ROUTER_URL}/v1/chat/completions` |

Chat requests must be JSON, fit within 100 MiB, and contain a canonical
`owner/model` identifier with an optional provider suffix. Streaming and
non-streaming responses preserve their content type and status. The broker
forwards only fixed headers, replaces authorization with the real HF token,
refuses redirects, bounds responses, and applies explicit connection, response
header, TLS, and total timeouts. Conversation length is bounded by the 100 MiB
request limit rather than a separate message-count ceiling, so tool-heavy
sessions remain valid. Every other `/v1/*` path is refused before any
upstream contact. Inference audit entries contain the operation, model, status,
and decision, never prompts, completions, tools, images, or credentials.

The authenticated Agent Operations V1 surface is fixed to discovery, submit,
status, cancellation, and bounded long-poll routes under
`/api/agent/v1/operations`. Every execution-scoped Hugging Face capability has
a registered typed adapter. Approval binds the operation revision, canonical
target, closed arguments, observed preconditions, credential selector, client,
expiry, use limit, and immutable plan digest. hf-broker executes only that
stored plan with the upstream credential and returns a bounded, redacted
result. Ordinary read and administrative tools use the same operation
lifecycle. Authorization policy may allow them directly, authorize them with
an active window grant, require approval, or deny them; authorization mode
does not choose a separate MCP or CLI dispatch path. Native Git and LFS remain
bounded protocol data planes and are not advertised as completed JSON actions.

Hub and Git paths map by repo type:

Broker path → upstream URL, by repo type:

| Broker request | Upstream |
|----------------|----------|
| `/{owner}/{repo}.git/...` (model) | `https://huggingface.co/{owner}/{repo}.git/...` |
| `/datasets/{owner}/{repo}.git/...` | `https://huggingface.co/datasets/{owner}/{repo}.git/...` |
| `/spaces/{owner}/{repo}.git/...` | `https://huggingface.co/spaces/{owner}/{repo}.git/...` |

The classified Hub operation and `(owner, repo, type)` target must match a
`scope.json` policy rule or an active generated grant before upstream
contact. Upstream origins come only from trusted startup configuration; only
the policy-approved `owner`/`repo`/path-tail is interpolated, so the agent
cannot redirect the proxy elsewhere.

Outbound requests: strip the client's `Authorization`/`Cookie`, inject
the upstream token, and copy through the remaining non-hop-by-hop headers.
Response bodies are streamed back.

### Refusal responses (must be legible to the client)

A refusal must reach the human at the terminal. A bare 500 response is
insufficient:

- **Git push refusals**: return HTTP `200` with a valid
  `git-receive-pack` **report-status** that reports the offending ref as
  failed with a message (`ng refs/heads/main non-fast-forward (hf-broker:
  history rewrite refused)`), *and* an ERR sideband line so `git push`
  prints the reason. The push must be rejected **before** any bytes reach
  upstream. (If report-status framing proves impractical for a given
  client, the documented fallback is HTTP `403` with the reason in the body.
  This fallback is acceptable but less clean.)
- **Scope / auth refusals** on any route: `403` / `401` with a one-line
  plain reason.
### Health

`GET /healthz` → `200 {"ok": true}` for unauthenticated liveness probes. The
response contains no secrets.

## On-disk state

Everything the broker persists lives under `HF_BROKER_STATE_DIR`:

```text
state/
  mirrors/{type}/{owner}/{repo}.git/    commits-only bare mirror per repo
  state.db                              grants + plans + lifecycle + operations
```

The operation ledger is bounded to 2,048 records. Terminal records older than
30 days are pruned when a new operation is accepted. If nonterminal or recent
records fill the bound, new submissions fail closed until capacity becomes
available.

- Mirrors are created lazily on first push to a repo and refreshed per
  push. They contain no file contents, only commit graph. Safe to delete;
  they rebuild.
- Grant lifecycle mutations and their event and decision records commit in one
  SQLite transaction. Expired grants are pruned on read and on a periodic sweep. Stale
  in-flight use reservations are retained during the sweep so the
  operator can review crash-orphaned budget.
- A new request commits its immutable provider plan, pending grant, and
  `request.created` lifecycle event and approval-notification outbox entry
  together; any failed write rolls back the complete request.
- Notification claims, ambiguous sends, retry availability, attempt counts,
  and successful delivery are durable. On restart the sweeper resumes due
  approval deliveries without requiring the client to repeat its request.
- SQLite state is migrated at startup, uses WAL mode, and is protected by a
  single-process ownership lease. Plans are addressed by their canonical
  content digest and operation updates use optimistic revisions.
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

## Quality gates and CI

The root CI workflow runs formatting, vet, race tests, coverage, builds,
linting, vulnerability checks, architecture checks, and the configured
Slophammer gates. The checked-in workflow and `slophammer.yml` are the source of
truth for exact commands and thresholds. Mutation testing is disabled and
non-blocking.

## Testing strategy

The proxy is testable without a live Hub:

- **Unit (the bulk)**: pkt-line parsing, ref-command extraction,
  enforcement decisions, scope decisions, config validation, grant policy
  validation, grant expiry, grant use budgets, idempotency, and plan hashing.
  These tests are pure and table-driven.
- **Ancestry**: build throwaway real git repos in `tmp` with `git`
  plumbing, exercise `mirror` against them (fast-forward, non-ff,
  deletion, new branch, new tag, tag move) using real Git with no network.
- **Proxy integration**: a stub upstream (`httptest.Server`) mimicking
  the Hub's `info/refs` + `receive-pack` responses asserts that refused
  pushes never reach it and allowed pushes are forwarded verbatim with
  the client Authorization stripped and the upstream token injected.
- **Secrecy invariant test**: capture all log output and both response
  streams across a representative run; assert no configured secret or
  token value ever appears.

## Non-goals

- GitHub operations, which belong in gh-broker.
- Arbitrary Hub API proxying, repository administration, and organization
  management.
- Multi-tenant operation or per-agent identities beyond distinct shared
  secrets (one secret per agent client is supported; RBAC is not).
