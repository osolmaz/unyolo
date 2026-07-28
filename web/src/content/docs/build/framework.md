---
title: Framework overview
description: What unYOLO gives you when you build a broker, and the four things you have to write yourself.
---

unYOLO is a Go framework for building credential brokers. The three brokers in this repository
are consumers of it, not the product. If you need to put a policy boundary in front of some other
credential, an internal API key, a cloud role, a database superuser, you write the parts that know
about that provider and the framework supplies everything else.

The split is deliberate and enforced. `scripts/check-architecture.sh` fails a build where shared
code imports a provider, and Go's `internal/` rules stop one provider importing another.

## Your responsibilities

Four things, and nothing else is required.

**A classifier.** Turn an incoming request into one client, one operation, one target, and a set of
attrs. This is the part that knows your provider's URL shapes, payloads, or command lines. The
policy engine never sees the raw request.

**A registry.** Declare your operation names, target kinds, attrs, which operations may be granted,
and how each field matches. See [provider registry](/docs/build/registry).

**An executor.** Perform the upstream action, holding the credential. Validate targets and
arguments, build immutable plans, and format results safely.

**Approval wording.** Supply bounded semantic titles, summaries, targets, facts, warnings, risk,
and a plan identity. You do not supply markup, button labels, callback answers, layout, or terminal
prose; the framework renders those.

## Supplied by the framework

Authentication for named clients, including bearer shared secrets, Git Basic auth, constant-time
comparison, and secret validation. The policy schema, strict parsing, rule matching, and the fixed
`deny > active grant > allow > request > no_match` order.

The whole grant lifecycle: pending, approved, denied, expired, consumed, canceled, and revoked
states, idempotency keys, request TTL, use budgets, reservation and commit and release of uses,
fail-closed recovery of crash-stale reservations, and generated temporary allow rules.

Agent Operations V1 with provider-neutral identity, lifecycle states, revision, idempotency,
retention, waiting, and restart recovery, plus the HTTP surface, Go client, and conformance
mechanics. The MCP request-ID contract, transcript-safe operation documents, and bounded
get/wait/list recovery sit on top of that.

The operator inbox with bounded queries, opaque deterministic pagination, durable lifecycle event
cursors, revision-checked decisions, operator authentication kept separate from broker clients, a
trusted-host Go client, and a fake server for your tests.

Notifications as a bounded semantic envelope, plus the reusable Telegram client, renderer, escaping,
fixed controls, and the single inbound poller shared across brokers.

Audit event schema, secret-safe field helpers, and the JSONL writer. Strict config decoding, atomic
file writes, file locking, state directory conventions, test clocks, and deterministic IDs. Stable
error codes, denial response helpers, request body limits, no-store headers, and safe header
filtering.

For a Git-speaking provider it also owns pkt-line parsing, receive-pack command parsing, ref update
classification, size limits, and pack redaction, so you implement provider forwarding rather than
Git mechanics.

## Assembling a broker

`broker/controlplane` wires the pieces together. It assembles the canonical grant store, named
client authentication, separately named operator authentication, the operator inbox, the audit
exporter, and the approval-channel decider. You provide your platform presenter and, if you want
one, a stricter decider.

HTTP framework middleware and listener ownership stay in your broker, so unYOLO does not pick
your web framework. `internal/config/secretfile` is the only parser and renderer for named client
and operator credential files; raw single-secret operator files are outside the contract.

Each broker stores grants, immutable plans, and Agent operations in its own shared SQLite
`state.db`. Provider packages must not restore JSON lifecycle files or filesystem plan stores.

## Prohibitions in shared code

The rules that keep the framework honest are worth stating as prohibitions, because they are what
CI checks.

Shared packages must never contain provider-specific operation names or target kinds as global
built-ins, provider-specific approval wording, or provider API calls. Shared `agent/runtime`,
`agent/api`, `agent/client`, and `agent/conformance` code must not import a provider, and shared
code must not branch on provider names.

unYOLO does not own browser sessions, frontend components, or provider execution plans. It does
not own text such as "approve this force-push" or "approve this shell as deploy"; brokers compose
those summaries.

## Security invariants you inherit

Building on the framework gives you these properties, and the conformance suite tests them:

- A broker client secret is never the protected upstream credential.
- Upstream credentials and privilege tokens are never returned to clients.
- Auth, policy, grant, and audit code fails closed.
- Unknown operations, target kinds, and attrs are rejected unless your registry declares them.
- Audit records carry no secrets, request bodies, pack contents, shell input, raw upstream
  responses, or token metadata.
- A grant is scoped to one client, one operation, one target, and the attrs policy approved.
- Generated grants never use wildcard clients.

What you do not inherit is safety in your own executor. The framework decides whether a request may
run; it cannot make a buggy provider call safe. Parsing, validating, and executing correctly stays
yours.

## The line in the shipped brokers

The three shipped brokers are the reference for how much provider code is normal.

`gh-broker` owns GitHub App JWT signing, installation token minting, REST and GraphQL calls,
webhook verification, repository listing through installation visibility, pull request validation,
ruleset and branch-protection checks, its own request classification, its audit extension fields,
and its approval wording.

`hf-broker` owns Hugging Face route parsing, model and dataset and space target mapping, token
handling, Git and LFS and Xet forwarding, commits-only mirrors, append-only checks, and inference
request classification.

`sudo-broker` owns Unix target-user and group lookup, command catalog parsing, exact command
execution, the peer-authenticated privileged helper, and local isolation doctor checks.

Everything else in those three brokers came from the framework.

## Next

[Provider registry](/docs/build/registry) covers declaring your vocabulary.
[Conformance tests](/docs/build/conformance) covers what your broker has to prove before it is
trustworthy.
