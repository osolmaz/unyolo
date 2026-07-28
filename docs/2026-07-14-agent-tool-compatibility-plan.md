# Agent-Tool Compatibility Implementation Plan

Date: 2026-07-14

Status: complete

Implemented by unYOLO commit
`88d7135` (`feat(mcp): add resumable agent tool compatibility`, PR #41).
MLClaw pinned the resulting contract and completed the live test-space matrix
documented in
`osolmaz/mlclaw:docs/2026-07-14-broker-agent-tool-compatibility-plan.md`.

## Objective

Make every unYOLO MCP surface safe for agents whose hosts redact sensitive
tool arguments before replaying conversation history. Preserve durable
idempotency, provider-native behavior, and secret isolation without requiring
an agent to remember a field that its host deliberately masks.

This is one coordinated pre-release version 1 cutover. Replace the current MCP
contract in place. Do not add aliases for the old MCP fields, compatibility
readers, dual schemas, v2 formats, state migrations, or mixed old/new tests.
Provider Agent V1, policy, execution plans, and upstream APIs remain
provider-specific where they are provider-specific.

The companion MLClaw adoption and live verification plan is
`osolmaz/mlclaw:docs/2026-07-14-broker-agent-tool-compatibility-plan.md`.

## Confirmed Failure

OpenClaw classifies structured field names such as `idempotency_key`, `key`,
`request_key`, `token`, `secret`, `password`, `signature`, and related suffixes
as sensitive. That is correct for credentials but not for every identifier
whose name happens to match the rule.

In the live HF Broker path:

- an initial operation stored the full caller value;
- OpenClaw replayed only a redacted representation to the model;
- a later model turn sent the redacted representation as a new real value;
- the broker durably stored the literal value `***`; and
- unrelated later operations correctly conflicted on `(client_id, "***")`.

Restarting the MCP server or broker did not and should not clear durable
idempotency records.

The MCP schema also permits approval waits up to 900 seconds. A host transport
can terminate the MCP request earlier, leaving a durable pending operation
whose ID was never returned to the agent. HF's current client exposes get and
wait by operation ID but no bounded list or request-ID recovery path. The agent
therefore retries blindly and magnifies the identity problem.

## Design Principles

- Idempotency remains durable and exact.
- New operations do not require caller-generated identity.
- Explicit exact retries remain possible.
- Submission and approval waiting are separate operations.
- Every client-visible handle needed later survives transcript replay.
- Secret values remain sealed or credential-slot-backed.
- Provider-native field names and behavior remain inside provider adapters.
- Shared packages contain no Hugging Face, GitHub, sudo, OpenClaw, or MLClaw
  branches.
- Generated MCP schemas fail closed when a redaction collision is unresolved.
- A client never needs a broker restart to recover a committed operation.

Window-mode catalog entries authorize a later Git, HTTP, or provider-protocol
action. They remain grants and use the existing grant lifecycle; they are not
wrapped in synthetic Agent operations. The submission/result and operation
recovery requirements below apply to execution-mode MCP tools. Window grant
tools still use optional transcript-safe request IDs and return immediately.

## Agent-Facing Request Identity

### MCP execution submission input

Replace the required MCP property:

```json
{
  "idempotency_key": "caller-managed-value"
}
```

with:

```json
{
  "request_id": "optional-stable-exact-retry-id"
}
```

Rules:

- `request_id` is optional for a new operation.
- When omitted, the MCP server generates a cryptographically random bounded
  identifier before calling Agent V1.
- When supplied, it is trimmed, length-bounded, syntax-validated, and used as
  the exact idempotency identity.
- Identical `(client, request_id, operation, target, arguments)` replay returns
  the existing operation.
- Reusing `(client, request_id)` with a different immutable request returns a
  structured `request_id_conflict` error and a bounded summary of the existing
  operation.
- The request ID is not a credential, authorization grant, operation ID, or
  approval ID.
- Generated IDs use secure entropy and fail closed when entropy is unavailable.

The internal Agent V1 request and SQLite column may retain the term
`idempotency_key`; that is an implementation boundary, not an MCP field. The
MCP adapter maps `request_id` to the internal value exactly once.

### MCP execution submission result

Every immediate submission result contains:

```json
{
  "api_version": "unyolo.io/mcp-operation/v1",
  "id": "op_...",
  "request_id": "req_...",
  "operation": "repo.create",
  "state": "pending",
  "revision": 1,
  "created_at": "2026-07-14T00:00:00Z",
  "updated_at": "2026-07-14T00:00:00Z",
  "presentation": {
    "title": "Create Hugging Face repository",
    "summary": "Create private dataset example/data"
  }
}
```

The MCP projection must not expose the internal `idempotency_key` alongside
`request_id`. `unyolo.io/mcp-operation/v1` is a closed version 1 MCP
document, not an Agent V1 document with one silently renamed field. Operation
JSON returned by Agent V1 remains governed by Agent V1; MCP tools return the
transcript-safe projection.

## Separate Submission From Waiting

Remove `wait_seconds` from every provider operation submission tool. A
submission tool performs durable admission and returns the current operation
immediately. It does not hold an MCP request open for an approval lifetime.

Generate provider-prefixed utility tools with closed schemas:

### Operation get

```json
{
  "operation_id": "op_..."
}
```

Returns the current transcript-safe operation projection immediately.

### Operation wait

```json
{
  "operation_id": "op_...",
  "timeout_seconds": 25
}
```

Rules:

- `timeout_seconds` defaults to 25 and is bounded from 0 through 25.
- A timeout returns the latest nonterminal operation as a successful tool
  result; it is not an MCP transport error.
- Terminal operations return immediately.
- Repeated waits do not mutate the operation.

### Operation list and recovery

```json
{
  "request_id": "optional exact request filter",
  "state": "optional exact state filter",
  "limit": 20,
  "cursor": "optional opaque cursor"
}
```

Rules:

- results are scoped to the authenticated agent client;
- ordering is newest first with a deterministic ID tie-breaker;
- `limit` defaults to 20 and cannot exceed 50;
- cursors are opaque, bounded, tamper-evident or server-validated, and reveal no
  database offsets or credentials;
- an exact request-ID filter returns zero or one operation;
- returned operations use the same transcript-safe projection as submit/get;
- retention rules remain owned by `agentops`; and
- authorization never broadens from knowing another operation ID or request ID.

List/recovery must use indexed state queries. Do not load every operation and
filter in memory.

The list result is a closed page:

```json
{
  "api_version": "unyolo.io/mcp-operation-page/v1",
  "operations": [],
  "next_cursor": null
}
```

`operations` contains only `unyolo.io/mcp-operation/v1` documents.
`next_cursor` is either an opaque string or `null`. Empty pages use an empty
array and `null`; they do not omit fields or return a different shape.

## Structured Conflict Contract

Return a stable bounded error shape for conflicting request-ID reuse:

```json
{
  "code": "request_id_conflict",
  "message": "request_id is already bound to a different operation",
  "existing": {
    "id": "op_...",
    "request_id": "req_...",
    "operation": "repo.create",
    "state": "pending",
    "revision": 1
  }
}
```

Do not include raw arguments, sealed references, credentials, upstream bodies,
or an unbounded target in the conflict response. Identical replay is not an
error and returns the existing operation.

## Transcript-Safe MCP Projection

### Compatibility profile

Add a provider-neutral compatibility package under `capability/` that can
classify an MCP schema property as:

- safe and model-visible;
- intentionally sensitive and required to be sealed or slot-backed; or
- unsafe because a non-secret field collides with the supported host-redaction
  profile.

The profile must cover the pinned OpenClaw structured-field behavior without
importing OpenClaw. Keep it as small data and deterministic validation, not a
copy of OpenClaw's logging implementation.

At minimum, classify exact sensitive names and conventional sensitive suffixes
for keys, tokens, secrets, passwords, credentials, authorization values,
signatures, sessions, cookies, and payment credentials. Tests use the actual
pinned OpenClaw redactor as an external conformance fixture so the local profile
cannot silently drift.

### Provider-owned field projections

Provider-native canonical schemas remain unchanged inside provider adapters.
Each provider owns an explicit bidirectional MCP projection for false-positive
fields. A projection maps JSON Pointer paths between the agent-facing schema
and canonical provider request/result without changing values or types.

Projection requirements:

- closed input and output schemas;
- no duplicate source or destination path;
- no alias collision at one object level;
- exact type and requiredness preservation;
- rejection of unknown or partially projected fields;
- deterministic inbound and outbound mapping;
- no mapping of genuine secret values into a model-visible field;
- generated documentation and examples use only projected names; and
- every projection is covered by round-trip and redaction-replay tests.

Do not apply a global mechanical rename such as `key` to one universal word.
The provider owns semantic aliases because `key` can mean a variable name,
cache identifier, public cryptographic material, or document selector.

### Required Hugging Face projections

Cover at least:

| Canonical provider path | MCP path | Notes |
| --- | --- | --- |
| `arguments.key` for `space.variable.set/delete` | `arguments.variable_name` | Non-secret variable identifier |
| `arguments.key` for `space.secret.set/delete` | `arguments.secret_name` | Secret name; the value remains sealed |

Generated and upstream-bound HF operations must pass the same audit. Any
additional false positive blocks generation until an explicit provider-owned
projection or sealed classification is added.

### Required GitHub projections

Cover all currently generated hazards, including:

| Canonical provider path | MCP path | Notes |
| --- | --- | --- |
| cache `key` | `cache_identifier` | Cache selector, not a credential |
| document/license `key` | `document_name` | Public resource selector |
| SSH/signing/deploy `key` | `public_material` | Public key material |
| `armored_public_key` | `armored_public_material` | Public GPG material |
| commit `signature` | `commit_signature` | Public signature payload |
| stream `request_key` | `transfer_id` | Opaque bounded stream correlation handle |
| `hide_secret` | `hide_sensitive_value` | Preserve boolean type |

Actual invitation, OIDC, access, refresh, webhook-secret, and password values
must remain sealed or otherwise protected. Renaming a real secret to evade
redaction is forbidden.

The GitHub schema generator must emit an unresolved-projection report and fail
when a generated schema introduces a new colliding property. Human review
decides whether the field is public and projected, secret and sealed, or not
agent-facing.

### Stream references

Change the MCP-visible `stream_input.request_key` and corresponding output
handle to `stream_input.transfer_id` or the final reviewed transcript-safe
name. The internal `streamstore.Reference.RequestKey` may remain unchanged.

Upload, download, retry, ownership, purpose, digest, size, media type, and
expiry binding remain identical. Round-trip tests must prove the projected
reference still cannot be replayed by another client, operation, or request.

## Shared Surface Changes

Update `capability/surface.go` and related shared packages so generated MCP
tools:

- expose optional `request_id`;
- remove required `idempotency_key`;
- remove submission `wait_seconds`;
- apply provider-owned input and result projections;
- generate the provider-prefixed operation utility tools;
- describe exact replay and immediate-return behavior concisely; and
- fail generation when any non-secret property conflicts with the compatibility
  profile.

Keep generic surface code provider-neutral. It accepts descriptors, schemas,
projection metadata, ID generation, and operation query interfaces; it does
not contain operation-name conditionals.

## Hugging Face Broker Changes

Update the HF MCP implementation under
`brokers/huggingface/cmd/hf-broker/`:

- replace `mcpCatalogOperationInput.IdempotencyKey` with optional
  `RequestID`;
- generate a secure request ID before Agent V1 submission when absent;
- return immediately after `client.submit`;
- remove the wait branch from catalog operation calls;
- add provider-prefixed operation get, wait, and list/recovery handlers;
- project operation results into the transcript-safe shape;
- apply HF input aliases before provider validation; and
- return structured conflict information without leaking arguments.

Update CLI behavior separately only where consistency is useful. The CLI may
continue to call the internal Agent V1 idempotency field through a
human-oriented `--request-id` option, but MCP and CLI flags must not claim that
restarting clears durable identity.

## GitHub Broker Changes

Update `brokers/github/cmd/gh-broker/mcp.go`, `internal/mcpcatalog`, generated
schemas, and stream adapters:

- adopt the shared optional request-ID contract;
- remove submission waits;
- add the operation utility tools;
- apply generated and explicit projections on input and output;
- keep sealed-argument and credential-slot behavior intact;
- project stream references without weakening their binding; and
- regenerate catalogs, documentation, and conformance fixtures.

All 1,436 generated operation schemas must be audited automatically. A small
advertised MCP subset does not exempt the rest because exposure profiles can
change at runtime.

## Sudo Broker And Future Brokers

Audit Sudo Broker even if it does not currently advertise the same generated
MCP surface. Any future MCP surface must consume the shared contract and
compatibility validator rather than define another request identity field.

Provider onboarding documentation must require:

- secure server-generated request IDs;
- immediate submission;
- bounded recovery tools;
- explicit secret classification;
- transcript-safe public identifiers; and
- conformance against every supported host profile.

## Persistence And Fresh-State Replacement

Do not weaken or delete durable idempotency. The operation store continues to
enforce a unique client/request identity and exact replay semantics.

Because this is pre-release:

- replace version 1 MCP schemas and generated artifacts in place;
- initialize fresh broker state for coordinated test deployments;
- do not add a migration that rewrites `***` or ellipsis-masked records;
- do not special-case old stored keys; and
- retain internal database names when they remain semantically correct and are
  not part of the MCP contract.

Existing masked records are valid historical values. They are not evidence of
database corruption.

## Automated Verification

### Shared contract tests

Add table-driven tests for:

- omitted request ID and secure generation;
- supplied request ID validation and exact preservation;
- identical replay;
- conflicting reuse with structured existing-operation summary;
- entropy failure;
- immediate pending return;
- get, bounded wait, terminal wait, list, exact request lookup, pagination,
  retention, and client isolation;
- malformed cursors and out-of-range limits/timeouts; and
- cancellation and disconnect after durable admission.

### Projection tests

For every projected field:

- validate the generated MCP schema;
- decode projected input and compare canonical provider JSON;
- project canonical output and compare MCP JSON;
- round-trip values and types without loss;
- run the projected tool call through the pinned OpenClaw transcript redactor;
- replay it and revalidate against the same MCP schema; and
- prove genuine secret values remain redacted or absent.

Include explicit regressions for `***`, short values, long ellipsis masks,
parallel tool calls, transcript compaction, and restored sessions.

### Catalog-wide conformance

Generate a deterministic report for every HF and GitHub agent-facing schema.
The quality gate fails on:

- an unresolved redaction collision;
- a required field whose type changes after redaction/replay;
- a public output handle that is not replay-safe;
- a genuine secret exposed outside sealed arguments or credential slots;
- duplicate projected names;
- projection paths absent from the canonical schema; or
- generated docs that use canonical unsafe names instead of MCP names.

Commit only the concise deterministic compatibility manifest needed for review;
do not commit large transient audit output.

### Timeout and recovery tests

Use a real MCP subprocess and bounded fake approval source to prove:

- submission returns before approval;
- approval can outlive many MCP calls;
- a 25-second wait returns current state rather than a transport timeout;
- an injected lost response after commit is recoverable by request ID/list;
- the recovered operation can be approved and reaches one terminal result;
- no retry creates a duplicate approval; and
- restart recovery preserves the same operation and request ID.

### Provider tests

Run HF, GitHub, and sudo provider suites plus root conformance. Update snapshots,
generated catalogs, CLI/MCP help, and docs in the same cutover.

## Documentation

Update:

- `docs/UNIFIED_BROKER_CONTRACT.md` with request identity and recovery
  semantics;
- `docs/OPERATIONS_RUNTIME.md` with immediate submission and bounded waiting;
- `docs/OWNERSHIP.md` with projection and compatibility ownership;
- provider READMEs and generated MCP examples;
- stream and sealed-payload documentation; and
- plugin/host integration notes explaining that durable conflicts are not
  repaired by restart.

Documentation must distinguish request ID, operation ID, approval ID, transfer
ID, and credential slot with one stable term for each.

The version 1 MCP operation and page schemas are canonical generated artifacts
under `protocol/`. They are not added to Agent V1 and must not reuse the Agent
V1 discriminator.

## Required Checks

Run all repository-required checks:

```sh
go fmt ./...
go vet ./...
go test ./...
golangci-lint run
slophammer-go check .
```

Run package and generated-artifact checks already defined by the repository.
Do not run mutation testing.

## Replacement

Implement and ship the change as one coordinated branch:

1. add shared request identity, operation recovery, compatibility validation,
   and projection primitives;
2. cut HF and GitHub MCP surfaces to the new contract;
3. regenerate and audit every provider schema and document;
4. complete root and provider conformance, including the pinned OpenClaw
   replay fixture;
5. merge unYOLO only when all required checks pass;
6. let MLClaw pin the exact merged commit and rebuild its image;
7. recreate the test deployment's unYOLO state; and
8. publish no package release until the MLClaw live matrix passes.

Do not merge a state where one broker still advertises required
`idempotency_key`, submission `wait_seconds`, or unresolved unsafe public
fields.

## Acceptance Criteria

- No agent-facing MCP submission schema contains `idempotency_key`.
- New operations succeed without caller-supplied request identity.
- Every execution submission immediately returns a durable operation ID and
  request ID.
- Exact replay returns the original operation; conflicting reuse is structured
  and actionable.
- No submission tool waits for approval.
- Bounded get, wait, list, and exact request recovery work for every provider.
- Every non-secret identifier required for retry or chaining survives the
  pinned OpenClaw redaction and transcript replay unchanged.
- Every genuine secret remains sealed, slot-backed, redacted, and absent from
  model-visible results.
- All HF and GitHub agent-facing schemas pass catalog-wide compatibility
  conformance.
- Provider-native behavior remains in provider implementations; shared code has
  no provider branches.
- Durable idempotency and restart recovery remain intact.
- No compatibility aliases, old-state readers, dual schemas, or new wire
  version are introduced.
- Root, HF, GitHub, sudo, generated-artifact, lint, and Slophammer checks pass.
