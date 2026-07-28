# Hugging Face Operation Coverage Plan

Date: 2026-07-13

Status: implemented and verified

## Implementation Record

The cutover shipped as one branch with 258 cataloged capabilities, of which 257
are agent-facing. Catalog descriptors now generate the CLI, MCP, policy, and
documentation surfaces. Administrative operations use immutable Agent V1
plans, explicit policy, one-use execution authority, reconciliation, and sealed
payload handling where required.

Local verification passed the full race suite, 85.1% aggregate Go coverage,
lint, architecture, SQL, DRY, CRAP, and complete Slophammer gates. The
OpenClaw plugin suite and both GitHub Actions jobs also passed.

A live test submitted `repo.delete` as the `bob` client for one exact private,
disposable dataset. Telegram accepted and delivered each approval
notification. No phone decision arrived during the test windows, so the final
request was approved through Operator V1 with a five-minute, one-use
constraint. The broker deleted the repository, Hugging Face authenticated
lookup confirmed it was absent, and an idempotent replay returned the original
successful operation without a second execution. The temporary policy rule was
then removed. Telegram callback decisions remain covered by the real protocol
integration suite with a scripted Bot API.

## Objective

Make every supported Hugging Face action available through the broker as a
fixed, typed operation or account for it as internal, operator-only, or local.
Policy may allow an agent-facing operation directly, require an operator
approval, or deny it. The broker must not reject a valid Hub action merely
because it is mutating or destructive.

This is a fresh-state cutover. Replace the current `repo.create` special case
with a generic provider operation framework, migrate every operation to it in
one branch, and delete the replaced paths. Do not add compatibility readers,
dual execution paths, or a second protocol version.

This plan extends the Agent Operations V1 and SQLite lifecycle work in
`2026-07-12-refactor-plan.md`. That plan remains authoritative for shared
lifecycle, storage, audit, outbox, and authorization behavior. This document is
authoritative for Hugging Face operation coverage and provider execution.

The complete provider baseline is the
[dated operation inventory](2026-07-13-hugging-face-operation-inventory.md).
Every operation in that inventory must receive a descriptor and disposition in
this cutover. A short example list in this plan must never be treated as the
capability boundary.

## Non-Goals

- Do not expose a generic Hub HTTP proxy, arbitrary URL, arbitrary method, or
  arbitrary request body.
- Do not move Hugging Face vocabulary, credentials, API clients, or operation
  semantics into provider-neutral unYOLO packages.
- Do not grant an interactive shell or raw token to the requesting agent.
- Do not treat approval as permission to perform a related but different
  action.
- Do not preserve the current `repo.create`-specific implementation.
- Do not add mutation testing to the quality gate in this cutover.

## Required Security Model

Each action is a separately registered operation with a closed target schema,
a closed argument schema, a policy classification, a safe presentation, an
executor, and a reconciler. Unknown operation names and unknown fields fail
closed.

An approval authorizes one immutable operation plan. It does not authorize a
repository, a provider API family, or future arguments supplied after approval.
The plan binds:

- operation name and schema revision;
- canonical resource identity and resource kind;
- normalized arguments;
- broker-observed preconditions;
- credential selector, never credential material;
- requester and policy decision context;
- approval mode, use limit, and expiry;
- canonical payload digest; and
- redacted operator presentation.

The canonical plan format continues to be `hf-broker.io/plan/v1`. Replace the
pre-release V1 schema in place. Do not introduce V2 or support old V1 plans.

## Operation Architecture

Define one Hugging Face-owned adapter interface under
`brokers/huggingface/internal/operations`:

```go
type Adapter interface {
	Descriptor() Descriptor
	Decode(target, arguments json.RawMessage) (Input, error)
	Resolve(context.Context, Input) (Plan, error)
	Authorize(Plan) policy.Request
	Present(Plan) agentv1.Presentation
	Execute(context.Context, Plan) (json.RawMessage, error)
	Reconcile(context.Context, Plan) (agentops.Outcome, error)
}
```

The concrete types may differ where Go type safety benefits from generic or
internal interfaces, but the ownership and lifecycle must remain equivalent.

`Descriptor` is the single provider-owned registry record for:

- stable operation name;
- summary and risk class;
- target and argument schema identifiers;
- execution or window authorization mode;
- default request and approval TTL ceilings;
- maximum uses;
- whether explicit policy matching is required;
- whether the operation may match family globs;
- whether it carries sealed secret input;
- MCP and CLI exposure metadata; and
- executor and reconciler registration.

Startup validates that operation names are unique and every descriptor has all
required components. MCP registration, CLI registration, policy validation,
documentation tables, and tests consume the same descriptors so their
operation lists cannot drift.

## Operation Taxonomy

The dated operation inventory is the exhaustive taxonomy. It covers:

- identity, public discovery, repository metadata, files, Git, commits, refs,
  LFS/Xet, administration, gated access, discussions, and pull requests;
- Space runtime, logs, hardware, dev mode, variables, secrets, and volumes;
- buckets and object manifests, collections, webhooks, Jobs, scheduled Jobs,
  Sandboxes, Inference Endpoints, and every typed Inference task;
- organization settings, roles, billing, audit, resource groups, service
  accounts, SCIM, user notifications, papers, SQL embeds, and agentic
  provisioning; and
- credential-vending and local helper surfaces that must be internal or
  operator-only rather than agent-facing.

Keep normal read and protocol operations on bounded reusable window grants when
that is the correct authorization shape. Implement discrete mutations through
Agent Operations V1. Every mutation is independently named and typed. There is
no `repo.admin`, `space.admin`, `http.request`, or broad settings mutation.

The capability manifest has one of these implementation states in addition to
its security disposition:

- `implemented`: a typed adapter and tests exist;
- `protocol`: handled by an existing bounded protocol path;
- `internal`: consumed only inside another exact approved operation;
- `operator-only`: available only through trusted installation/bootstrap UX;
- `local`: no remote provider capability exists; or
- `blocked-upstream`: the pinned official operation cannot be implemented due
  to a precise upstream blocker.

`blocked-upstream` is not an implementation backlog state. It requires the
exact upstream operation, observed blocker, and reference. Never work around a
gap by accepting arbitrary HTTP.

## Immutable Plan V1

Replace the current HF plan V1 with one envelope and typed operation payloads:

```json
{
  "api_version": "hf-broker.io/plan/v1",
  "operation": "repo.delete",
  "operation_revision": 1,
  "target": {},
  "arguments": {},
  "preconditions": {},
  "credential_selector": {},
  "presentation": {},
  "created_at": "...",
  "expires_at": "..."
}
```

Canonical JSON bytes and their digest are stored in the shared lifecycle
transaction. The digest covers every execution-relevant field. Database IDs,
notifications, and mutable lifecycle status are outside the digest.

The broker, not the requester, resolves canonical resource IDs and observed
state. The requester supplies a human-readable target and desired change. The
adapter rejects ambiguous identities. Immediately before execution, it checks
the bound preconditions. A changed identity, owner, revision, visibility,
runtime generation, or other safety-relevant value fails with
`operation_precondition_failed` and requires a new request and approval.

## Generic Agent Operation Lifecycle

Replace `submitAgentOperation` and every `repoCreate*` lifecycle function with
one registry-driven service:

1. Strictly decode the operation name, target, arguments, reason, and
   idempotency key.
2. Resolve the adapter or fail with `operation_not_registered`.
3. Decode closed target and argument schemas with duplicate-key, trailing-data,
   unknown-field, and size rejection.
4. Resolve provider-observed canonical state without trusting requester-supplied
   metadata.
5. Build and validate the immutable plan and digest.
6. Classify the exact plan through policy.
7. Deny, execute directly, or persist a request according to the policy result.
8. Persist plan, operation, first event, decision context, and notification
   outbox atomically through the shared SQLite lifecycle.
9. On approval, mint one-use execution authority bound to the plan digest.
10. Recheck preconditions, execute once, reconcile, and record the final event.

The worker is generic over adapters but never generic over HTTP. It loads the
immutable plan, validates its digest and operation revision, resolves the
registered adapter, and invokes only that adapter.

## Policy Rules

Registration makes an operation understandable, not allowed. No-match remains
deny. Administrative operations marked `explicit policy only` cannot be
selected by operation-family globs or broad fallback rules.

The normal safe default for a destructive action is an exact request rule, for
example:

```yaml
- effect: request
  principals: [bob]
  operations: [repo.delete]
  targets: [osolmaz/*]
  constraints:
    authorization_mode: execution
    max_uses: 1
    request_ttl: 15m
    approval_ttl: 5m
```

The final schema and field names must follow the canonical policy format; this
example specifies the required semantics. Broad `allow` rules must not absorb
destructive operations. Policy validation rejects an execution-only operation
configured with a window grant, multiple uses, or a TTL above its descriptor
ceiling.

Generated setup policy may provide owner-scoped `request` examples, but it must
not enable destructive actions globally. Operators opt into each principal,
operation, and target scope.

## Upstream Client Boundary

Add a typed Hub administration client interface owned by the HF broker. Prefer
the official maintained client where it exposes the required operation with
acceptable semantics. Wrap all third-party types at this boundary.

For each operation:

- send only adapter-produced canonical arguments;
- use bounded request and response bodies;
- apply explicit deadlines and cancellation;
- classify authentication, authorization, conflict, rate-limit, validation,
  unavailable, and ambiguous-result errors into stable broker error codes;
- redact upstream response bodies and credentials from user-visible errors;
- preserve rate-limit metadata needed for safe retries; and
- make retry policy operation-specific.

Do not automatically retry a destructive request after a timeout or connection
loss when the upstream result is unknown. Reconcile first:

- delete operations check that the exact resource is absent;
- create operations check that it exists and matches the plan;
- update operations fetch and compare the desired fields;
- runtime actions compare the new runtime generation and state; and
- if the result cannot be proven, finish as `upstream_result_unknown` and
  require operator resolution rather than issuing the mutation again.

## Secret Inputs and Outputs

Secret values must never appear in operation rows, immutable plans, audit
events, Telegram messages, operator inbox payloads, logs, traces, errors, or
idempotency records.

Implement a small encrypted payload store before enabling any secret-bearing
operation, including Space secrets, webhook secrets, Job/Endpoint environment
secrets, service-account tokens, OAuth bootstrap, and provisioning credential
rotation:

- accept the value only over an authenticated local or TLS-protected boundary;
- encrypt it immediately with an installation key held outside the database;
- store ciphertext under a random, single-purpose reference;
- bind the reference and plaintext digest to the immutable plan;
- reveal plaintext only in memory to the exact approved executor;
- delete ciphertext after terminal execution, cancellation, denial, or expiry;
- never return the value through get, wait, list, audit, or notification APIs;
- route generated credential outputs directly into an operator-selected sealed
  broker credential slot instead of returning plaintext to the agent;
- bind the destination credential slot and expected credential kind into the
  approved plan;
- permit one-time operator retrieval only for an explicitly operator-only
  bootstrap flow, through a separate authenticated local UX with no agent
  principal;
- make backup and key-loss behavior explicit; and
- test redaction against every serialization and failure path.

Variable values are not credentials by definition, but operator presentation
and audit should show their name and digest by default, not their full value.
An adapter may mark a value display-safe only through a narrow, tested rule.

## MCP and CLI UX

Expose one explicit, discoverable MCP tool for every agent-facing operation in
the exhaustive inventory. Representative administrative tools include:

- `hf_repo_create`
- `hf_repo_delete`
- `hf_repo_set_visibility`
- `hf_repo_move`
- `hf_repo_set_gating`
- `hf_space_restart`
- `hf_space_pause`
- `hf_space_set_hardware`
- `hf_space_set_variable`
- `hf_space_delete_variable`
- `hf_space_set_secret`
- `hf_space_delete_secret`
- `hf_bucket_create`
- `hf_bucket_delete`
- `hf_job_run`
- `hf_endpoint_create`
- `hf_webhook_create`
- `hf_service_account_token_rotate`

Generate or register these tools from operation descriptors while retaining
strongly typed input schemas and user-facing descriptions. Keep the common
operation `get`, `wait`, and `cancel` tools. A generic raw submission tool may
remain an internal protocol surface for trusted integrations, but it is not the
primary agent UX and cannot bypass descriptor validation.

Mirror the same operation vocabulary in the CLI using explicit subcommands.
Submission returns the durable operation ID, current status, and whether an
approval was requested. `get`, `wait`, and `cancel` use the shared lifecycle.

## Operator Presentation

Telegram, delegated web, and direct operator inbox modes consume one redacted
Agent V1 presentation produced by the adapter. For every operation it shows:

- requesting principal;
- exact operation in plain language;
- canonical owner, resource name, kind, and ID where available;
- current state and requested state;
- destructive or irreversible consequences;
- reason, bounded by the canonical 2,000-character limit;
- expiry and one-use semantics; and
- plan digest fingerprint.

The notification contains enough information to make the decision without
opening raw JSON. It never contains tokens, secret values, sealed payloads, raw
upstream bodies, or attacker-controlled markup. Telegram is a transport, not a
policy or execution implementation.

## Stable Outcomes and Audit

Use provider-neutral lifecycle states and provider-owned stable error details.
At minimum distinguish:

- `operation_not_registered`
- `operation_input_invalid`
- `operation_target_not_found`
- `operation_target_ambiguous`
- `operation_policy_denied`
- `operation_approval_expired`
- `operation_precondition_failed`
- `operation_upstream_rejected`
- `operation_upstream_unavailable`
- `upstream_result_unknown`
- `operation_reconciliation_failed`

Audit records bind requester, operation, canonical target, policy result,
approver, plan digest, execution attempt, reconciled outcome, timestamps, and
redacted error class. They do not store raw secrets or upstream response bodies.

## Implementation Order

### 1. Freeze Inventory and Fixtures

- Pin the upstream HF client/API version used for the cutover.
- Freeze the dated operation inventory into the machine-readable capability
  manifest and verify all 161 `HfApi` methods, all 33 `InferenceClient` methods,
  the matching async client, all Sandbox/filesystem/scheduler/CLI workflows, and
  all 311 live OpenAPI operations have an explicit mapping and disposition.
- Capture sanitized HTTP fixtures for success, conflict, forbidden, rate-limit,
  timeout, ambiguous completion, and reconciliation.
- Finalize operation names, closed schemas, risk class, and policy defaults.

### 2. Registry and Plan Replacement

- Add the descriptor registry and startup validation.
- Replace HF plan V1 in place with the canonical adapter envelope.
- Implement strict typed decoding, canonicalization, digesting, and
  preconditions.
- Move `repo.create` onto the first adapter and delete its bespoke plan code.

### 3. Generic Lifecycle and Worker

- Replace `repo.create` submission and worker branches with registry dispatch.
- Connect the shared SQLite Agent Operations lifecycle and transactional outbox.
- Implement one-use authority consumption, expiry, cancellation, restart, and
  idempotent replay.
- Delete every `repoCreate*` service, worker, and HTTP helper.

### 4. Repository and Space Operations

- Implement all repository adapters in the inventory.
- Implement Space lifecycle, hardware, variable, and non-secret settings
  adapters.
- Add exact precondition and reconciliation logic for each operation.

### 5. Sealed Secrets

- Implement key management and encrypted single-use payload storage.
- Add exhaustive redaction and lifecycle deletion tests.
- Enable secret-bearing adapters only after these gates pass.

### 6. Remaining Provider Operations

- Implement every remaining bucket, inference, organization, membership,
  resource-group, service-account, SCIM, collection, webhook, Job, Endpoint,
  user-setting, paper, SQL embed, and provisioning operation in the inventory.
- Keep each action separate even when several call the same upstream endpoint.
- Document any `blocked-upstream` entries with the exact missing capability.

### 7. MCP, CLI, Policy, and Operator Surfaces

- Generate or register explicit MCP and CLI commands from descriptors.
- Add policy validation for operation-specific mode, use, TTL, and glob limits.
- Add safe presentations for Telegram and both web hosting modes.
- Generate the capability reference and setup policy examples.

### 8. Delete Legacy Paths and Ship

- Remove the old registry duplication and all `repo.create` special cases.
- Remove documentation claiming administrative operations are unsupported.
- Remove obsolete fixtures, routes, generated artifacts, and policy examples.
- Run the complete quality and end-to-end gates before merging the cutover.

## Test Strategy

### Adapter Contract Tests

Run the same suite for every adapter:

- valid input canonicalizes deterministically;
- duplicate keys, unknown fields, trailing JSON, invalid UTF-8, and oversized
  fields are rejected;
- target identity is resolved by the broker;
- requester-supplied canonical IDs cannot override observed identity;
- presentation is complete, escaped, and secret-free;
- policy receives the exact canonical operation and target;
- plan mutation changes the digest;
- stale preconditions stop execution;
- execution calls only the expected typed client method;
- reconciliation proves success or returns an ambiguous outcome; and
- logs, errors, events, and notifications remain redacted.

### Lifecycle Tests

- direct allow, request, deny, cancellation, expiry, and rejection;
- one-use authority under concurrent workers;
- restart between request, approval, execution, and reconciliation;
- duplicate idempotency keys with identical and conflicting payloads;
- notification outbox retry without duplicate execution;
- policy change after submission according to the canonical activation rule;
- database transaction rollback at every write boundary; and
- deterministic clock and entropy failure behavior.

### Provider Integration Tests

Use a scripted fake Hub server for exhaustive failure behavior and a disposable
real Hub namespace for a bounded smoke matrix. The real test creates resources,
updates each supported property, exercises an approval through the real
operator transport, deletes the resources, and verifies final remote state.
Always use unique names and cleanup reconciliation.

Destructive end-to-end coverage must include `repo.delete` initiated by a
non-owner agent identity, approved through Telegram or the operator inbox,
executed with the broker-held credential, and verified absent upstream. Also
prove the same action is denied without its exact request rule and cannot be
replayed after one use.

### UX and Contract Tests

- snapshot every MCP tool schema generated from descriptors;
- verify every registered admin operation has an MCP tool, CLI command, policy
  metadata, presentation, executor, reconciler, and documentation row;
- run packed OpenClaw plugin installation and cross-browser delegated/direct UI
  tests for representative low-risk, destructive, stale, expired, ambiguous,
  and secret-bearing requests; and
- verify the 2,000-character reason limit at protocol, HTTP, MCP, and UI
  boundaries.

### Required Gates

- `go test ./...`
- `go vet ./...`
- repository Slophammer format, lint, complexity, duplication, and coverage
  gates with no blanket exit-code exceptions;
- race tests for lifecycle, registry, worker, and sealed payload storage;
- OpenAPI and generated-artifact freshness checks;
- OpenClaw plugin check, unit tests, build, packed-install test, and Playwright
  suite;
- architecture boundary check; and
- secret-scanning and explicit redaction tests over test artifacts and logs.

Mutation testing remains disabled for this implementation.

## Superseded Code Deletion List

Delete in the same branch that replaces them:

- operation-name switches in Agent V1 submission and workers;
- `repoCreate*` request, plan, worker, and response helpers;
- hand-maintained MCP and CLI operation lists replaced by descriptor-driven
  registration;
- duplicate policy metadata outside the operation registry;
- old HF plan V1 fields and validators;
- documentation that describes only repository creation as supported; and
- any broad refusal text that tells agents mutations are categorically
  unavailable when a typed operation exists.

Do not delete normal Git, bucket object, or inference protocol routes merely to
force them through Agent Operations. Their authorization shape remains based on
the operation taxonomy.

## Acceptance Criteria

The cutover is complete only when:

1. Every official capability in the pinned inventory is implemented as a typed
   adapter/protocol, or has an explicit internal, operator-only, local, or
   precise `blocked-upstream` disposition.
2. `repo.delete` and every other destructive action can be requested by an
   agent, approved through Telegram and the operator inbox, executed once, and
   reconciled against Hub state.
3. No generic provider HTTP execution path exists.
4. No operation can execute with arguments, target identity, credentials, or
   preconditions different from the approved immutable plan.
5. Unknown operations, unknown fields, stale plans, expired approvals, replay,
   and policy no-match all fail closed.
6. Secret values are absent from all durable and operator-visible surfaces and
   encrypted payloads are removed at terminal state.
7. MCP, CLI, policy, docs, and runtime registration derive from one descriptor
   registry and have drift tests.
8. The `repo.create` special case and replaced pre-release state are gone.
9. A real disposable-Hub end-to-end test passes for create, update, approve,
   execute, reconcile, and delete.
10. All required local and CI gates are green before merge.
