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

There is no backward-compatibility requirement for old broker-local control
planes. When a broker adopts a brokerkit package, the local duplicate should be
deleted in the same change.

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
- approve, deny, cancel, revoke handling
- status update model
- grant-to-notification correlation
- fail-closed behavior for ambiguous approval state

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
- inline approve/deny buttons
- callback payload parsing without interpreting the decision token
- configured-chat filtering
- Telegram operator metadata extraction
- callback-query answers
- retry behavior
- transport errors
- shared tests for callback and token safety

Status: brokerkit now owns the reusable Telegram client, inline callback data,
long polling, configured-chat filtering, callback answering, and status edits.
The adapter is stateless. It never tracks pending or active expiry and never
edits a message as a side effect of receiving a callback. The shared grant
store owns durable delivery claims, notification references, expiry, and due
status updates. Brokers own decision-token verification, domain-specific
approval summaries and status wording, and the final approve/deny/revoke calls.

This is the only supported lifecycle. There is no in-memory Telegram tracking
mode and no compatibility option that enables one.

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
- bucket snapshot behavior
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

- Unix user, group, and host lookup
- command catalog parsing and validation
- command execution
- shell/session lifecycle
- TTY handling
- sudo, systemd, launchd, or privileged-helper integration
- local isolation doctor checks
- OS-specific installer and service files
- sudo-specific request classification
- sudo-specific audit extension fields
- sudo-specific approval wording

## Cutover Tests

Each broker cutover should prove:

- old local auth, policy, grants, approval, Telegram, audit, storage, and
  notification runtimes were removed
- the broker registers only its provider vocabulary
- valid requests go through brokerkit decisions
- malformed or unclassified requests fail closed before execution
- deny overrides active grants
- active grants match only the approved client, operation, target, attrs,
  duration, and use budget
- audit output contains no secrets, request bodies, Git pack contents, command
  output, approval tokens, or upstream credential metadata
- Telegram callbacks cannot approve a different grant than the one displayed
