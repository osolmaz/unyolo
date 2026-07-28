# Hugging Face resource write access implementation plan

Date: 2026-07-23

Status: proposed

## Objective

Finish the Hugging Face broker's repository and bucket data workflows so an
agent can receive narrow, reusable write access without receiving a Hugging
Face token. An operator must be able to approve access to one exact repository,
bucket, ref, path pattern, or object-key pattern for a bounded period such as
24 hours or seven days. unYOLO must check that grant for every later action
and revoke it immediately when requested.

This work extends the grant, policy, Agent V1, Operator V1, MCP, stream, and
immutable-plan machinery already in unYOLO. It does not add another access
model. The main implementation work belongs to the Hugging Face provider,
particularly bucket object reads and Xet-backed writes.

The final design must also remove the gap between the Hugging Face operation
catalog and the operations that clients can actually run. Every agent-facing
catalog entry must identify a registered Agent adapter or a reviewed native
protocol path. Operations that lack either one cannot be presented as usable.

unYOLO is still pre-release. Replace changed V1 contracts in place, remove
superseded paths in the same branch, and coordinate fresh state when a persisted
format changes. Do not add compatibility aliases, parallel request shapes,
fallback execution, V2 protocols, or state converters.

## Current implementation

unYOLO already provides the control plane needed by this work:

- provider-neutral policy matching over classified requests.
- deny, active-grant, allow, request, and no-match decision ordering.
- execution and window grants with expiry, use budgets, reservations,
  cancellation, and revocation.
- immutable provider plans and durable Agent V1 operation recovery.
- a protected Operator V1 inbox and delegated OpenClaw approval UI.
- transcript-safe MCP operation submission and bounded recovery tools.
- sealed payloads, bounded byte streams, admission limits, and durable state.
- provider-owned catalogs with execution and presentation metadata.
- release and doctor tooling with audit, backup, and failure recovery.

The pinned Hugging Face catalog contains 258 capabilities. It has 144
registered Agent runtime adapters and three additional implemented native Git
mutations. Native Git and LFS use separate bounded data planes. The two
supported Router endpoints also stay outside the Agent runtime.

Repository support is already substantial. Agents can create and manage model,
dataset, and Space repositories. They can read and write repository files,
create commits, manage refs, and use normal Git workflows through the broker.
`git.push.append` already uses a reusable window grant when policy requires
approval.

Bucket support currently has executable adapters for:

- `bucket.batch.apply`.
- `bucket.create` and `bucket.delete`.
- `bucket.move`.
- `bucket.object.copy` and `bucket.object.delete`.
- `bucket.resource_group.set`.
- `bucket.sync.apply`.
- `bucket.visibility.update`.

The catalog also contains `bucket.list`, `bucket.metadata.read`,
`bucket.object.list`, `bucket.object.read`, and `bucket.object.write`. Those five
entries are marked as protocol operations, but they have no registered Agent
adapter and no separate bucket object protocol that fulfills the catalog
claim. In particular, `bucket.object.write` exists in policy vocabulary and
approval presentation without an execution path that can upload arbitrary
content.

Explicit grant creation also has an incomplete client contract. The shared
authorization coordinator and `POST /api/grants` already accept provider-owned
requests, but the HF CLI only builds repository and ref targets. HF MCP exposes
grant lookup and lifecycle management without a corresponding deliberate grant
request tool. The ordinary operation tools correctly submit Agent operations
and must continue doing so.

Finally, the shared policy parser and grant store enforce a one-hour maximum.
That ceiling is suitable for the existing defaults but cannot represent an
operator-approved 24-hour or seven-day repository or bucket write window.

## Design decisions

### Existing grant model

Keep one grant model. A grant remains bound to one client, one operation, one
provider target, the relevant attrs, an expiry, and a use budget. The policy
engine keeps its existing decision order, and deny rules continue to override
active grants.

This plan does not add grant bundles. Access to a dataset repository and a
bucket remains two grants because the operations and targets differ. The UI may
present nearby requests clearly, but it must not hide several authorities
inside one broad grant.

### Write operations

Use a small set of normal write operations for reusable access:

- `git.push.append` remains the native Git capability for repeated normal Git
  pushes.
- `repo.commit.create` becomes the canonical Agent operation for repeated API
  writes to a model, dataset, or Space repository.
- `bucket.object.write` becomes the canonical Agent operation for repeated
  object writes to a bucket.

Each later Agent operation still carries exact arguments and produces an
immutable plan. An active window grant changes the authorization result. It
does not let the client replace or edit the stored plan.

Keep destructive and administrative operations narrow. Repository deletion,
bucket deletion, force pushes, ref deletion, visibility changes, resource-group
changes, and comparable actions retain their existing short or one-use
approval behavior. Convenience operations such as `repo.file.delete` may stay
execution-scoped even when `repo.commit.create` is available for a reviewed
path-scoped write workflow.

### Scope

A repository write grant names an exact owner, repository name, and repository
type. It may also restrict refs and recursive path patterns. A bucket write
grant names an exact owner and bucket name and may restrict recursive object-key
patterns.

Execution requests contain concrete target selectors. Grant requests may
contain the provider's existing policy matcher syntax. unYOLO must validate
that the concrete execution target is within the approved matcher before it
reserves a use.

Normal Git push grants remain ref-scoped. They do not claim path-level
confinement because the current smart-HTTP proxy does not inspect complete tree
contents for policy matching.

### Duration and use limits

Replace the fixed one-hour policy ceiling with operation-aware bounds. Seven
days is the initial absolute ceiling for a write window. Each provider
operation sets a lower maximum when needed.

The operator may approve a shorter duration or smaller use budget. Policy may
also permit unlimited uses until expiry for ordinary repository and bucket
writes. Existing finite use budgets remain available.

This plan does not add cumulative byte accounting to grants. unYOLO must
retain transport size limits, disk quotas, request limits, and upstream
timeouts because those protect service health. They are operational limits,
not grant accounting.

### Data transport

Use unYOLO stream references for object and file content. Raw file bytes do
not belong in MCP results, operation history, approval records, logs, or model
transcripts.

The first complete bucket write path may use the existing durable one-shot
stream upload. The broker then reads the stored stream, uploads its Xet shards,
and registers the resulting Xet hash through the bucket batch endpoint. Xet
chunk retries and content-addressed deduplication must recover interrupted
upstream work without asking the model to resend content.

Add resumable client-to-broker transfer sessions after the basic path is
verified with realistic large objects. This remains a shared unYOLO
capability because GitHub assets and future providers can reuse it. The
resumable contract must stay under V1 and replace the one-shot-only contract. A parallel stream API would create two transfer paths to maintain.

### Provider boundary

The Xet implementation belongs under `brokers/huggingface`. Shared packages may
own stream storage, transfer lifecycle, hashing contracts, and HTTP safety.
They must not import Hugging Face endpoints, token refresh behavior, shard
formats, or bucket semantics.

Do not shell out to `hf`, run an arbitrary helper, expose a generic Hub proxy,
or pass the upstream token to a client process. The broker executes fixed
reviewed HTTP and Xet operations with its protected credential.

## User workflows

### Repository write access

An agent deliberately requests a window grant before using an API write path.
A seven-day dataset request has this logical shape:

```json
{
  "operation": "repo.commit.create",
  "target": {
    "kind": "repo",
    "type": "dataset",
    "owner": "alice",
    "name": "training-runs",
    "refs": ["refs/heads/main"],
    "paths": ["runs/2026/**"]
  },
  "duration_minutes": 10080,
  "max_uses": null,
  "reason": "Publish reviewed training outputs for the current run",
  "request_id": "training-runs-2026-write"
}
```

After approval, each `repo.commit.create` submission still names concrete files
and commit metadata. The adapter checks the exact ref and affected paths against
the active grant, resolves preconditions, stores an immutable plan, and executes
the commit with the broker credential.

Normal Git users can request `git.push.append` for an exact repository and ref,
then continue using ordinary `git push`. Force pushes and ref deletion remain
separate capabilities.

### Bucket write access

A bucket request uses the same lifecycle with a bucket target:

```json
{
  "operation": "bucket.object.write",
  "target": {
    "kind": "bucket",
    "owner": "alice",
    "name": "artifacts",
    "keys": ["runs/2026/**"]
  },
  "duration_minutes": 10080,
  "max_uses": null,
  "reason": "Store reviewed run artifacts",
  "request_id": "artifacts-2026-write"
}
```

The client uploads content into unYOLO stream storage, then submits a
`bucket.object.write` operation containing the stream reference and one
concrete object key. unYOLO validates ownership and purpose of the stream,
checks the active grant, uploads through Xet, commits the bucket batch, verifies
the result, and retires the stream.

Copy, delete, sync-with-delete, bucket deletion, and settings changes continue
to use their own operations and policy rules.

### Approval and revocation

The delegated OpenClaw UI and every Operator V1 consumer show the requested
operation, exact resource, ref or path pattern, requested duration, use limit,
and relevant warnings. The operator may narrow the duration and use count.

Revocation closes the grant immediately. A request that has not reserved a use
must fail on its next policy check. In-flight execution follows the existing
reservation and ambiguity rules so the broker never reports an unknown write as
safely absent.

## Shared unYOLO changes

### Operation-aware grant bounds

Extend `authorization/policy.OperationSpec` with provider-supplied grant
ceilings. The exact field shape should use the existing `GrantMode` and
`usebudget.Limit` types and cover:

- allowed grant mode.
- maximum duration.
- maximum finite uses.
- whether unlimited uses until expiry are allowed.

`Registry.Validate` rejects missing or contradictory bounds for grantable
operations. `policy.Parse` validates each request rule against every operation
it names. A family rule that spans operations must fit the strictest operation.
The operator must split a rule that exceeds those bounds.

Keep a provider-neutral absolute duration ceiling as defense in depth, and set
its initial value to seven days. Provider descriptors remain authoritative for
lower limits. `grants.Store` must use the same absolute ceiling, while the
authorization coordinator continues checking the selected policy rule before a
request is persisted.

Map the Hugging Face and GitHub catalog fields into these shared registry
bounds. Sudo keeps execution mode, one use, and its short duration. Add
cross-provider tests proving that one provider cannot widen another provider's
limits.

This change replaces the current hard-coded 60-minute parser limit in V1. The
wire representation already uses bounded duration values, so no Operator V2 or
Agent V2 is needed.

### Transcript-safe grant tools

Add a small provider-neutral MCP grant projection beside `mcp/operation`. It
owns public request IDs, closed grant lifecycle documents, bounded errors, and
get, wait, cancel, and revoke behavior. Provider code supplies:

- the operation selector and target schema.
- canonical target and attr projection.
- the provider grant client.
- safe presentation and result projection.
- the set of operations exposed for deliberate window-grant requests.

Extend `protocol/openapi/mcp-v1.yaml` in place with the closed
`unyolo.io/mcp-grant/v1` documents. Grant results must omit decision tokens,
plan digests, internal metadata, credentials, notification destinations, and
provider responses.

HF MCP exposes one deliberate `hf_grant_request` tool in addition to the
existing lifecycle tools. It accepts `operation`, `target`, optional attrs, requested duration, and the
requested use limit. It also accepts a reason and optional `request_id`. The
operation and target remain provider-validated. Ordinary tools continue to
submit Agent operations and never turn into implicit grant preflights.

Replace the HF CLI's repository-only positional grant parser with the same
closed typed request contract. The CLI keeps a blocking wait by default and
reuses the same durable grant ID across internal poll intervals. JSON output
uses the same safe projection as MCP.

GitHub and sudo do not need to adopt the new request tool in the first slice,
but the shared code and conformance fixtures must allow them to do so without a
second implementation.

### Transfer sessions

Keep the existing `/api/agent/v1/streams` contract for the first bucket write
slice. Add the following invariants where they are not already explicit:

- a stream belongs to one authenticated client, operation purpose, and request
  key.
- the reference binds content metadata, creation time, and expiry.
- only the owning operation can consume or retire it.
- operation replay reuses the same reference and cannot substitute new bytes.
- terminal success or definitive failure retires the bytes.
- ambiguous upstream results retain the stream until reconciliation.
- startup cleanup cannot remove a stream still referenced by active work.

The later resumable replacement adds chunk admission, per-chunk digests, final
content verification, durable completion state, and bounded cleanup. It does
not add grant-level byte accounting.

## Hugging Face provider changes

### Catalog integrity

Replace the ambiguous use of `implementation_status: protocol` with a verified
binding rule. Every agent-facing descriptor must resolve to exactly one of:

- an Agent runtime adapter with a declared executor kind.
- a registered native protocol binding.
- an operator-only or internal implementation.
- a precise `blocked-upstream` disposition.

A protocol descriptor includes a stable binding identifier that startup and CI
can resolve. Documentation-only catalog entries cannot use `protocol` as a
placeholder. The policy preset and generated capability documentation must
report whether an operation is executable for an agent.

Extend `operations.Registry.ValidateCoverage` and catalog generation tests so a
phantom operation fails CI. The MCP tool list remains the runtime intersection,
but the catalog, policy preset, and documentation can no longer imply that a
missing executor is usable.

### Bucket read adapters

Implement fixed typed adapters for:

- `bucket.list`.
- `bucket.metadata.read`.
- `bucket.object.list`.
- `bucket.object.read`.

Bucket listing queries the authenticated Hub and filters every result through
policy before projection. Object listing accepts an exact bucket and optional
prefix, follows bounded pagination, and returns a closed entry projection.
Metadata reads distinguish an absent object from an inaccessible bucket.

Small object reads may return bounded inline content where the descriptor
allows it. Larger reads produce an owned output-stream reference. The CLI can
materialize that stream into a caller-selected local file without returning the
bytes through MCP.

### Bucket object write adapter

Register `bucket.object.write` as a window-authorized stream adapter. Its public
input contains an exact bucket, object key, media type, overwrite intent, and a
unYOLO stream reference. The canonical plan binds:

- the client and operation request IDs.
- bucket owner and name.
- the exact object key.
- stream identity and digest metadata.
- the broker-observed bucket identity.
- existing object metadata or an absent-object precondition.
- overwrite intent.
- policy decision and active grant ID.
- safe approval presentation.

The adapter rechecks bucket identity and overwrite preconditions before it
contacts Xet. A changed existing object fails with
`operation_precondition_failed` unless the approved request explicitly permits
overwrite under the matching grant.

Add a provider-owned Xet uploader that follows the pinned Hub protocol:

1. Acquire a bucket Xet write token from the fixed bucket endpoint.
2. Chunk and shard the stored stream with a reviewed deterministic
   implementation.
3. Upload missing shards to the permitted CAS endpoint with bounded retries.
4. Collect the final Xet file hash.
5. Submit one NDJSON `addFile` operation to the exact bucket batch endpoint.
6. Read back the object and compare its key with the expected content metadata.
7. Return a bounded result containing resource identity and safe metadata.

The protected HF token and Xet write token never enter the plan, result, audit,
or client process. Redirects cannot forward either credential. CAS endpoints
and token refresh URLs come only from validated Hub responses for the pinned
origin.

Classify transport loss after shard upload as retryable because content is
addressed by hash. Classify an ambiguous batch commit through readback. The
operation succeeds only when readback proves the intended object state. An
unprovable result ends as `upstream_result_unknown` and retains enough protected
state for operator diagnosis without exposing credentials or bytes.

### Repository window writes

Keep `git.push.append` as a window capability and raise only its descriptor
ceiling when the policy permits longer access.

Change `repo.commit.create` from execution authorization to window
authorization. Its default policy effect remains `request`. The adapter already
produces exact immutable plans. Extend its authorization projection so the policy request contains every affected path and the exact
destination ref.
Explicit grant requests may use recursive path matchers, while submitted
operations always use concrete paths.

Keep repo creation, deletion, movement, visibility, gating, access management,
force push, and ref deletion on their current narrow authorization modes. Review
`repo.file.upload`, `repo.file.copy`, and `repo.file.delete` as convenience
operations. They remain execution-scoped unless a separate path-scoped window
use case justifies changing each descriptor.

### Policy preset and protected targets

Update the `request-all-agent-operations` preset from catalog metadata. The
normal write operations default to approval and may advertise a seven-day
maximum. The default requested duration stays short.

Extend the HF policy profile and renderer with exact protected targets. The
first required target is a private bucket. A rendered protected-bucket rule
denies every operation whose catalog target kind is `bucket` for that exact
owner and name. The profile and policy manifest record the target and digest so
`doctor policy` detects drift.

Expose the setting through a typed `hf-broker policy render` flag. MLClaw uses
that command at startup to render its deployment-specific policy with the state
bucket protected. MLClaw must not synthesize unYOLO policy JSON or maintain
its own list of bucket operations.

The protected-target feature does not claim to defeat a host administrator who
replaces broker configuration and credentials. It prevents an agent request or
ordinary approval from overriding the deployment's active deny rule.

### Remaining protocol coverage

After the repository and bucket write slice is complete, review every remaining
HF descriptor marked `protocol`.

Real native paths receive registered binding identities. This includes Git
fetch and append push, supported LFS routes, Router model listing, and Router
chat completions.

Bounded JSON reads should move to generated or custom Agent adapters. Expected
families include Hub discovery, job and scheduled-job reads, Space runtime and
log reads, sandbox reads, repository metadata reads, and organization views.
Large provider responses use stream adapters. Interactive
connections receive an honest scoped protocol-access result or a precise
blocked disposition.

Complete one family at a time. The final coverage gate requires all 257
agent-facing HF capabilities to have a verified execution or native-protocol
binding, or to be reclassified with a documented non-agent disposition. The
gate does not require exposing an arbitrary upstream endpoint.

## Client and MCP behavior

Generate schemas and descriptions from the provider catalog and registered
runtime bindings. A write tool describes the action it performs. A grant tool
describes access it creates for later actions.

Add CLI workflows for local data:

```text
hf-broker client bucket object write --target-json ... --source ./artifact.bin
hf-broker client bucket object read --target-json ... --output ./artifact.bin
hf-broker client bucket object list --target-json ...
hf-broker client grant request --operation bucket.object.write --target-json ...
```

The write command uploads the local file through Agent V1 stream storage,
submits the durable operation, and waits through internal poll intervals until
execution is terminal. A lost client response is recovered with the same
request ID. The read command verifies the returned stream digest while writing
to a new local destination.

MCP tools accept stream references so they never embed large bytes. Broker
skills explain how to stage and retrieve streams with the installed client.
Do not add an MCP tool that reads an arbitrary host path inside the broker
process.

Normal Git URLs continue to work through the existing Git installation. This
plan does not replace Git with file-operation tools.

## Protocol and state changes

Keep these protocol identifiers at V1:

- `unyolo.io/agent/v1`.
- `unyolo.io/operator/v1`.
- `unyolo.io/mcp-operation/v1`.
- `unyolo.io/mcp-grant/v1`.
- `hf-broker.io/plan/v1`.
- the unYOLO stream reference and transfer-session V1 formats.

Extend the canonical OpenAPI and JSON Schema artifacts in place, regenerate Go
and TypeScript outputs, and update exact contract digests. Mixed old and new
MCP grant projections are invalid.

Operation-aware duration bounds do not require a grant-table shape change.
New bucket operation plans use new operation names and revisions. If resumable
stream sessions require a persisted schema change, replace the current V1
schema and use a coordinated fresh-state release. Do not add old-state readers
or converters.

## MLClaw adoption

unYOLO owns the provider implementation. MLClaw adopts one exact compatible
HF Broker release and the matching OpenClaw plugin release when the Operator or
MCP contract digest changes.

MLClaw must:

- render the HF policy through the unYOLO CLI with its state bucket as an
  exact protected target.
- keep the broad Hugging Face token in the trusted broker and state supervisor.
- expose only the broker client credential to the untrusted OpenClaw process.
- update the managed Hugging Face skill with grant requests, bounded waits,
  writes, reads, recovery, and revocation.
- preserve the existing delegated approval boundary.
- snapshot current unYOLO state according to the coordinated state contract.
- release one tested unYOLO and MLClaw pairing built from exact pins.

MLClaw does not implement bucket APIs, Xet, grant matching, policy parsing, or a
generic forwarding route.

## Implementation sequence

### Contract fixtures

Freeze current behavior with tests that prove:

- core policy and grant state work before any extension.
- the one-hour ceiling is enforced today.
- HF CLI grant requests cannot currently express bucket targets.
- HF MCP has no grant request tool.
- the five bucket protocol entries have no Agent adapter.
- bucket batch and sync adapters do not upload arbitrary local bytes.
- MLClaw's current policy preset contains no deployment-specific state-bucket
  deny.

### Shared grant bounds

Add operation-aware duration and use ceilings to the shared registry, policy
parser, coordinator checks, and store configuration. Update provider registries
and policy conformance tests together. Keep current behavior for every operation
until its descriptor changes.

### Grant request clients

Add the V1 MCP grant projection and provider-neutral helper. Replace the HF CLI
request parser and add `hf_grant_request`. Test replay, conflicts, blocking CLI
waits, bounded MCP waits, and the full grant lifecycle.

Prove that ordinary operation tools still execute or request approval through
Agent V1 and never dispatch to `/api/grants` automatically.

### Bucket reads

Implement bucket listing, metadata, object listing, and object reads. Add
pagination, missing-object, inaccessible-bucket, stream-output, policy-filter,
and response-bound tests.

### Bucket writes

Implement the stream-bound object write adapter and Xet uploader. Start with a
fake Hub and CAS protocol fixture, then run live tests against a disposable
private bucket. Add retry, deduplication, overwrite, precondition, and ambiguous commit tests.
Also cover readback, stream cleanup, and secret scanning.

### Repository windows

Change only `repo.commit.create` and the approved normal Git descriptors to the
new window ceilings. Add explicit path and ref grant tests with active-grant reuse. Cover
out-of-scope denial and every terminal grant state. Test concurrent use
reservations separately.

### Protected targets

Add HF profile support for exact protected buckets and generate deny rules from
target-kind metadata. Extend policy manifests and doctor. Integrate the renderer
into the MLClaw runtime and prove that an approved request cannot override the
state-bucket deny.

### Catalog completion

Replace every unverified protocol disposition family by family. Add one shared
coverage test that fails whenever an agent-facing descriptor lacks a runtime or
native binding. Regenerate the capability inventory and maintained docs after
each family.

### Resumable transfer replacement

After the one-shot stream and Xet path passes live object-size testing, replace
the stream upload contract with resumable V1 sessions. Run interruption tests
at every chunk boundary and during finalization, broker restart, Xet upload,
and bucket batch commit.

### Coordinated release

Publish no unYOLO component until shared tests, HF tests, OpenClaw plugin
tests, and the live Hugging Face matrix pass. Tag the exact HF Broker and plugin
revisions, update MLClaw's release metadata from its package source of truth,
build the runtime image, and deploy only the designated test Space first.

## Test strategy

### Shared unit and conformance tests

Cover:

- operation-specific duration and use validation.
- family rules using the strictest operation bounds.
- finite and unlimited-use policy behavior.
- request ID replay and conflict.
- grant request projection redaction.
- approval narrowing and widening rejection.
- all grant lifecycle states and concurrent reservations.
- stream ownership, purpose, replay, retention, and cleanup.
- all exact protocol contract digests.

Run the same authorization matrix for all three provider registries
to prove that the shared change preserves provider boundaries.

### Hugging Face adapter tests

Use fixed fake Hub, Xet token, and CAS servers. Cover successful upload,
existing-shard reuse, token refresh, rate limiting, retryable transport errors,
redirect refusal, malformed responses, missing hashes, wrong-origin endpoints,
batch rejection, and readback mismatch.

Adapter contract tests must reconstruct every plan from canonical bytes, compare
authorization and presentation, recheck preconditions, and prove that secrets
and stream bytes are absent from every observable output and test fixture.

### Restart and failure tests

Restart the broker across each nonterminal and terminal grant state.
Restart during stream retention, Xet shard upload, batch commit, and ambiguous
readback. Every case must recover one durable operation without duplicate
provider mutation or silent data loss.

Test state corruption, expired streams, missing stream files, exhausted disk
quota, unavailable Hub, unavailable CAS, notification failure, and audit export
failure. Readiness and terminal outcomes must remain fail-closed.

### Live Hugging Face validation

Use disposable private resources under a dedicated test account:

1. Request and approve a short `repo.commit.create` grant for one dataset path.
2. Create several commits under the approved path and reject one outside it.
3. Revoke the grant and verify the next matching commit is refused.
4. Request and approve a bucket write grant for one key prefix.
5. Upload representative object sizes through the real Xet path.
6. Read and list the objects through the new adapters.
7. Restart the broker and resume one interrupted operation.
8. Reject overwrite when the bound precondition changed.
9. Revoke access and verify no later object write reaches the Hub.
10. Delete all disposable resources through separately approved operations.

No live test may use the MLClaw state bucket or a personal production
repository.

### MLClaw validation

Deploy the exact candidate pairing to the designated private test Space. Verify
from a fresh OpenClaw session that the model can request access, the operator
can approve a longer duration, several writes reuse the grant, revocation takes
effect, and operation recovery survives a Space restart.

Attempt the same workflow against the deployment state bucket. The request must
be denied before an approval is created, and no bucket object may change.

Inspect the model-visible transcript, runtime logs, snapshot contents, and
Operator V1 payloads for provider tokens, broker credentials, Xet tokens,
stream bytes, decision tokens, and protected plan data.

## Required checks

Run the root quality gates for every implementation branch:

```sh
go fmt ./...
go vet ./...
go test ./...
golangci-lint run
slophammer-go check .
```

Run the Hugging Face gates before any HF Broker release:

```sh
go mod tidy
git diff --exit-code -- go.mod go.sum
go mod verify
gofmt -l .
go vet ./...
go test -race ./brokers/huggingface/...
go build ./brokers/huggingface/cmd/hf-broker
golangci-lint run
govulncheck ./...
slophammer-go dry .
slophammer-go crap .
slophammer-go check .
```

Run protocol generation and drift checks whenever canonical contracts or the
catalog change. Run the OpenClaw plugin suite when generated Operator or MCP
artifacts change. Do not run mutation testing unless it is explicitly
requested.

Tests and CI support the live validation matrix. They do not replace it.

## Acceptance criteria

The implementation is complete when all of the following are true:

- unYOLO still has one shared authorization and operation lifecycle.
- An authenticated agent can deliberately request a reusable window grant for
  `repo.commit.create`, `git.push.append`, or `bucket.object.write`.
- Policy can permit a 24-hour or seven-day write grant without widening short
  limits on destructive operations.
- Repository grants match only the approved target selectors.
- Bucket grants match only the approved bucket and object-key patterns.
- Every later write uses an exact immutable Agent operation plan.
- Bucket listing, metadata, object listing, object reading, and object writing
  have registered runtime adapters.
- Bucket object writes upload arbitrary local content through protected stream
  storage and the real Xet protocol.
- Large object content never enters MCP JSON, model transcripts, plans,
  approvals, logs, or audits.
- Revocation and expiry stop later writes before they contact Hugging Face.
- Destructive and administrative operations keep their narrow approval modes.
- MLClaw's state bucket is denied by its generated active policy, and active
  grants cannot override that deny.
- Every agent-facing HF catalog entry has a verified runtime or native-protocol
  binding, or a precise non-agent disposition.
- CLI, MCP, policy, generated documentation, and runtime discovery agree on
  which operations are usable.
- Interrupted operations recover without duplicate writes or lost terminal
  state.
- The exact unYOLO and MLClaw candidate passes the live dataset, bucket, and
  restart matrix.
- No upstream Hugging Face credential or derived Xet credential crosses the
  broker boundary.

## Exclusions

This plan does not add:

- grant-level byte accounting.
- one approval that silently creates unrelated grants.
- a broad Hugging Face token, shell, or HTTP proxy.
- arbitrary caller-selected URLs, methods, headers, or executables.
- long-lived grants for destructive or administrative operations.
- path-level claims for native Git pushes that the Git data plane cannot
  verify.
- provider behavior in shared unYOLO packages.
- compatibility aliases, legacy state readers, migrations, or a V2 protocol.
- automatic authorization merely because an operation appears in the catalog.
