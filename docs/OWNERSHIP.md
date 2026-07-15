# brokerkit Ownership

brokerkit owns the generic broker control plane. A consuming broker owns only
the platform adapter: request classification, upstream execution, platform
credentials, and platform-specific user-facing wording.

The rule is:

```text
brokerkit decides who may do what, on which target, under which grant, with
which audit trail.

the broker decides how a Hugging Face, GitHub, or Unix action is classified and
executed.
```

## Owned By brokerkit

brokerkit should provide these reusable packages.

### Identity And Auth

- named broker clients
- bearer shared-secret authentication
- basic-auth password authentication for Git clients
- client ids
- approver identities
- constant-time secret comparison
- secret validation
- auth error types that brokers can map to their own HTTP response shape

brokerkit should not depend on Echo or another HTTP framework. Brokers wrap the
auth primitives in their own middleware.

### Policy

- policy file schema
- strict parsing and validation
- rule ids
- effects: `deny`, `allow`, `request`
- decision result: `allow`, `request`, `deny`, `no_match`
- fixed decision order:

```text
deny > active generated grant > allow > request > no_match
```

- client, operation, target, and attr matching
- generated grant overlays
- provider registry mechanism
- rejection of unknown operations, target kinds, attrs, and fields
- audit-safe decision metadata

brokerkit should not ship Hugging Face, GitHub, or Unix operation semantics as
global built-ins. Brokers register their own vocabulary.

### Operation And Target Registry

- generic registry API
- operation validation
- target kind validation
- attr validation
- grantability flags
- field type rules
- fixtures for registry conformance tests

The registry mechanism is shared. The registered vocabulary is broker-local.

### Agent Operations

- provider-neutral operation identity, lifecycle states, transitions, revision,
  idempotency, retention, waiting, and restart recovery
- durable operation repository contracts
- shared HTTP, client, and conformance mechanics

Providers register operation names and own target and argument validation,
approval presentation, immutable plans, credentials, execution, and safe result
formatting. Shared `agentops`, `agentapi`, `agentclient`, and
`agentconformance` code must not import a provider.

Each broker stores grants, immutable plans, and Agent operations in its own
shared SQLite `state.db`; provider packages must not restore JSON lifecycle
files or filesystem plan stores.

### Agent Tool Compatibility

BrokerKit owns the MCP request-ID contract, secure generated IDs, immediate
submission, transcript-safe operation/page documents, bounded get/wait/list
recovery, structured request-ID conflicts, and host compatibility profile.
Shared code must not branch on provider names.

Each provider owns canonical-to-MCP JSON Pointer projections for its public
false-positive fields and applies them in both directions. Providers also own
the classification of canonical secret inputs and their sealed or credential
slot boundary. A public key can be projected to `public_material`; an access
token cannot be renamed around secret handling.

Every generated provider schema is audited, including operations not currently
advertised. The pinned host fixture comes from the actual OpenClaw package, and
the concise manifests under provider `docs/generated/` are checked against the
catalogs. Future Sudo Broker MCP surfaces must consume these shared contracts.

### Grants

- pending, approved, denied, expired, consumed, canceled, and revoked states
- idempotency keys
- request TTL
- approved access duration
- expiry checks
- use budgets
- reservation, commit, and release of uses
- fail-closed recovery of crash-stale and ambiguous reservations
- overlapping reservation recovery measured from the most recent reserve or
  settlement, so a live newer use is never aged from an older use's start time
- durable notification references and delivered-status keys
- leased notification-send claims and conditional cancellation
- durable unresolved-delivery state for ambiguous sends and lease-bound retry
- atomic notification-reference recovery from accepted callbacks
- atomic approve/deny plus callback-reference transactions
- restart-safe discovery of notification updates that remain due
- generated temporary allow rules
- durable store interface
- default local durable store
- clock injection for tests
- bounded opaque provider metadata that is persisted and included in
  idempotency, but never interpreted by brokerkit policy or lifecycle code;
  metadata must not contain credentials, decision tokens, or other secrets

Generated grants must never use wildcard clients.

### Approval Workflow

- approval request model
- approver matching hooks
- decision tokens
- callback verification
- operator approve, deny, and revoke handling
- requester-owned cancellation of pending requests
- status update model
- grant-to-notification correlation
- fail-closed behavior for ambiguous approval state
- shared approval-channel actor identities and terminal decision-result mapping

### Operator Inbox

- bounded pending, active, history, and all-state queries
- opaque deterministic pagination and durable lifecycle event cursors
- revision-checked operator approve, deny, and revoke commands
- safe broker-owned presentation validation with generic fallback
- dedicated operator authentication separate from broker clients
- operator-only JSON and SSE handlers with atomic durable audit metadata and a
  mandatory external audit exporter
- trusted-host Go client, checked-in wire fixtures, and fake test server

The consuming broker supplies provider wording and exposes the handler on a
protected operator transport. A trusted web host keeps the operator credential
server-side and renders the safe projection. BrokerKit does not own
browser sessions, frontend components, or provider execution plans.

### Notifications

- generic notifier interfaces
- generic approval message model
- generic status update model
- retry/error contracts
- reusable adapters for common approval channels

Broker-specific text is not part of the shared notifier. Brokers prepare a
domain-specific approval summary, then pass it to brokerkit notification
adapters.

### Telegram Adapter

Telegram is a shared approval channel for `hf-broker`, `gh-broker`, and
`sudo-broker`, so the reusable Telegram implementation belongs in brokerkit.

brokerkit should own:

- Bot API client
- sending approval messages
- explicit approval status edits requested by the broker
- immediate best-effort terminal edits after a committed callback decision
- inline approve/deny buttons
- callback payload parsing without interpreting the decision token
- configured-chat filtering
- Telegram operator metadata extraction
- callback-query answers
- retry behavior
- offset-preserving callback retry without acknowledgement after durable-store
  failure
- offset-preserving handoff when a broker sharing the bot does not own a grant
- transport errors
- shared tests for callback and token safety

Status: brokerkit now owns the reusable Telegram client, inline callback data,
long polling, configured-chat filtering, callback answering, and status edits.
The adapter is stateless and never tracks pending or active expiry. After the
broker durably commits a callback decision, the adapter immediately writes the
returned terminal status into the original message and removes its inline
keyboard. That edit is best effort: the shared grant store remains authoritative
and its durable status outbox retries the edit after transport failures or
restart. The store owns decision-token verification, durable delivery claims,
notification references, expiry, due status updates, atomic approve/deny
transitions, channel actor naming, and retry classification. Brokers own
domain-specific approval summaries and later lifecycle status wording. A broker
with extra approval invariants implements the shared decider interface; it does
not reimplement channel mapping. A retry leaves the callback unanswered and
does not advance its update offset. This also lets several brokers share one bot:
a broker that cannot find the referenced grant leaves the update pending for the
owning broker instead of showing a false failure to the operator.

### Control-Plane Assembly

The `controlplane` package assembles the canonical grant store, named client
authentication, separately named operator authentication, operator inbox,
audit exporter, and approval-channel decider. Brokers provide their platform
presenter and optionally a stricter decider. HTTP framework middleware and
listener ownership remain broker-local.

The `secretfile` package is the sole parser and renderer for named client and
operator credential files. Raw single-secret operator files are not part of
the broker-family contract.

The `conformance` package runs the shared contract against real HTTP handlers.
Every broker invokes it in its own tests. `brokerkit-coverage` and
`brokerkit-release` provide common quality and release behavior. Mutation
targets remain broker-local and checked in, but are disabled and non-blocking
until a later explicit decision re-enables them.

brokerkit should not own text such as "approve this force-push" or "approve
this shell as deploy." Brokers compose those summaries.

### Audit

- audit event schema
- secret-safe field helpers
- JSONL writer
- request decision records
- grant lifecycle records
- approval decision records
- redaction helpers
- common fields:

```text
broker
client
operation
target
attrs
decision
reason
matched_rule_ids
grant_id
approver
time
duration
status
error_code
```

Broker-specific metadata, such as a GitHub request id or Unix executor name,
should be attached through typed extension fields.

### Common API Helpers

- stable error codes
- denial response helpers
- grant API response shapes
- strict JSON decoding helpers
- request body limits
- no-store headers
- safe header filtering

Brokers may still choose Git-shaped, JSON, or local-socket response formats at
their edges.

### Config And Storage Primitives

- strict YAML/JSON decoding helpers
- config file discovery helpers
- secret-safe validation errors
- atomic file writes
- file locking
- local state directory conventions
- test clocks and deterministic ids

Broker-specific config fields stay in the broker.

### Generic Git Helpers

`hf-broker` and `gh-broker` both speak Git smart HTTP. Generic Git parsing and
safety helpers should move to brokerkit when the API is clear.

brokerkit may own:

- pkt-line parsing
- receive-pack command parsing
- ref update classification
- branch create/update/delete classes
- tag create/update/delete classes
- safe Git request size limits
- pack/body redaction helpers
- shared Git operation naming conventions where both brokers agree

brokerkit must not own:

- Hugging Face mirror management
- Hugging Face ancestry checks
- Xet/LFS provider behavior
- GitHub App tokens
- GitHub branch protection or ruleset checks
- GitHub REST or GraphQL calls

## Owned By Brokers

### hf-broker

hf-broker owns:

- Hugging Face route parsing
- model, dataset, and space target mapping
- Hugging Face token handling
- Git/LFS/Xet forwarding
- commits-only mirrors
- append-only checks
- inference request classification and forwarding
- HF-specific request classification
- HF-specific audit extension fields
- HF-specific approval wording

### gh-broker

gh-broker owns:

- GitHub App JWT signing
- installation token minting
- GitHub REST and GraphQL calls
- GitHub webhook verification
- repository listing through GitHub installation visibility
- pull request validation and forwarding
- GitHub ruleset and branch-protection checks
- GH-specific request classification
- GH-specific audit extension fields
- GH-specific approval wording

### sudo-broker

sudo-broker owns:

- Unix target-user and group-id lookup
- command catalog parsing and validation
- exact command execution
- the peer-authenticated privileged helper and systemd integration
- local isolation doctor checks
- OS-specific installer and service files
- sudo-specific request classification
- sudo-specific audit extension fields
- sudo-specific approval wording

V1 does not include shell/session lifecycle, TTY handling, stdin, arbitrary
argv/environment input, or a launchd installer.

## Conformance Tests

Each broker should prove:

- the broker registers only its provider vocabulary
- valid requests go through brokerkit decisions
- malformed or unclassified requests fail closed before execution
- deny overrides active grants
- active grants match only the approved client, operation, target, attrs,
  duration, and use budget
- audit output contains no secrets, request bodies, Git pack contents, command
  output, approval tokens, or upstream credential metadata
- Telegram callbacks cannot approve a different grant than the one displayed
