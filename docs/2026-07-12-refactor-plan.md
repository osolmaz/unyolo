# BrokerKit Refactor Plan

Date: 2026-07-12

Status: active

## Objective

Remove the remaining provider-neutral duplication without moving Hugging Face,
GitHub, or Unix behavior into BrokerKit. The result should have one shared
implementation for common protocol, Git framing, audit, and host-inspection
mechanics while each broker retains its own classification, credentials,
execution, plans, and user-facing wording.

Most slices are behavior-preserving refactors. The Agent V1 slice is an
intentional public protocol cutover for discrete agent operations across all
three brokers. It preserves security semantics and provider capabilities, but
does not preserve replaced routes or state formats.

## Extraction Rule

Code moves to a root package only when all of these are true:

1. The behavior is provider-neutral.
2. Its security invariants are identical for every consumer.
3. At least two brokers need or are committed to the same API, unless the
   implementation already duplicates an existing root package.
4. The shared package can be tested without importing a provider.
5. The provider copy is deleted in the same change that adopts the shared API.

Similar naming or control flow is not enough. Provider policy registries,
approval presentations, immutable plan schemas, configuration, credentials,
and executors remain separate.

## Current Baseline

- Root and all broker-local Slophammer DRY checks report zero copied blocks.
- `scripts/check-architecture.sh` passes.
- BrokerKit already owns authentication, policy, grants, Operator V1,
  notifications, Telegram transport, audit primitives, installation, setup,
  doctor primitives, plan storage, and generic Git receive-pack parsing.
- HF, GH, and sudo are committed to Agent Operations V1 for discrete approved
  agent operations.
- The remaining duplication is architectural rather than literal copied code.

## Implementation Order

Each numbered section is an independently reviewable slice. A slice must be
green and committed before the next one starts.

### 1. Make Protocol Artifacts Single-Source

Problem: Operator V1 and Agent V1 are represented by canonical JSON Schemas,
handwritten Go structs, generated TypeScript types, and handwritten runtime
validators. Limits and enums can drift between these representations.

Implementation:

- Keep `protocol/schema` and `protocol/agent-schema` canonical.
- Extend deterministic repository-owned generation to produce Go and
  TypeScript enums, limits, and wire types from those schemas.
- Keep generated artifacts committed and marked as generated.
- Make runtime validators consume generated enums and limits rather than
  repeating numeric bounds.
- Add a generation check that fails on an uncommitted artifact change.
- Validate checked-in fixtures against schemas and both language bindings.
- Preserve the existing public Go and TypeScript wire shape; this slice changes
  ownership, not the protocol.

Deletion target:

- Hand-maintained enum and limit lists that repeat canonical schema values.

Acceptance:

- Editing one schema and running one generator updates every binding.
- CI detects stale Go, TypeScript, and runtime-validation artifacts.
- Operator V1 and Agent V1 fixtures round-trip through Go and TypeScript.

### 2. Finish Git pkt-line Consolidation

Problem: `gitx` parses pkt-lines and receive-pack commands, while
`brokers/huggingface/internal/gitproxy/pktline` separately implements buffered
scanning and encoding for the same wire format.

Implementation:

- Add bounded buffered scanning, consumed offsets, frame kinds, and append
  helpers to `gitx`.
- Preserve trailing packfile bytes without copying them unnecessarily.
- Preserve SHA-1 and SHA-256 object-ID validation and provider error behavior.
- Convert HF Git and LFS/Xet handlers to the shared API.
- Keep HF ancestry, mirror, LFS/Xet, and refusal-response behavior local.

Deletion target:

- `brokers/huggingface/internal/gitproxy/pktline`.

Acceptance:

- HF and GH use `gitx` for Git framing and receive-pack parsing.
- Malformed framing, flush packets, trailing pack data, and maximum lengths have
  shared tests.
- Existing Git proxy integration tests remain unchanged in behavior.

### 3. Move HF Request Auditing onto the Shared Recorder

Problem: HF has `internal/audit`, while the other shared control-plane paths use
the root `audit` package.

Implementation:

- Add provider-neutral typed fields needed for request decisions, including
  matched rule categories and immutable plan correlation.
- Keep provider-specific values in bounded audit extensions.
- Migrate HF request, grant-use, inference, and agent-operation events to the
  shared recorder.
- Preserve the current no-secret and no-body guarantees.

Deletion target:

- `brokers/huggingface/internal/audit`.

Acceptance:

- All brokers emit the shared audit envelope.
- Existing HF audit field coverage is preserved.
- Tests prove tokens, authorization headers, request bodies, Git pack data,
  prompts, completions, and plan contents never enter audit output.

### 4. Finish Doctor and Isolation Consolidation

Problem: HF has large Linux and macOS isolation implementations that repeat
identity lookup, root-equivalent group checks, path traversal, mode and ACL
inspection, process checks, socket checks, status aggregation, and active probe
mechanics already partly owned by `doctor`.

Implementation:

- Move provider-neutral identity, process, path, ACL, socket, and active-probe
  mechanics into `doctor` behind typed, OS-specific interfaces.
- Put shared Unix logic in build-neutral files and keep only kernel adapters in
  `_linux.go`, `_darwin.go`, and unsupported-platform files.
- Let HF configure token environment names, token paths, process targets, and
  provider-specific findings through a thin adapter.
- Reuse the same primitives from GH where applicable.
- Share low-level ACL inspection with sudo only where its semantics are
  identical. Sudo's root-trusted executable and privileged-helper checks remain
  sudo-specific.

Deletion target:

- Provider-neutral portions of `brokers/huggingface/internal/isolation` and any
  identical broker-local ACL helpers.

Acceptance:

- Linux and macOS reports retain their current status, messages, and exit codes.
- Root-equivalent groups, symlink replacement, writable ancestors, ACLs,
  process credentials, capabilities, environment readability, and socket access
  retain fail-closed tests.
- HF isolation code contains only HF configuration and presentation adapters.

### 5. Standardize All Brokers on Agent Operations V1

Problem: `agentv1` is provider-neutral, but its durable implementation currently
lives in `brokers/huggingface/internal/hfoperation`. HF, GH, and sudo are all
intended to expose the same agent operation lifecycle, so leaving that runtime
inside HF would make every later adoption duplicate or depend on provider code.

Shared ownership:

- `agentv1` owns the wire types and states.
- A root `agentops` package owns durable persistence, transitions, idempotency,
  retention, wait signaling, restart recovery, and terminal-result handling.
- A root `agentapi` package owns discovery, submit, get, wait/event, bounded
  decoding, authentication hooks, and stable error mapping.
- A root `agentclient` package owns the provider-neutral client and wait loop.
- A root `agentconformance` package runs the black-box lifecycle contract
  against each real broker handler.

Provider ownership:

- operation registration and names;
- target and argument validation;
- policy request classification;
- approval presentation;
- immutable provider plans and activation checks;
- upstream credentials and execution;
- ambiguous-result classification; and
- safe provider result formatting.

Implementation sequence:

1. Move `hfoperation` persistence and lifecycle behavior into `agentops`, update
   HF to use it, and delete the HF-local package in the same slice.
2. Move the generic HF Agent V1 HTTP and client mechanics into `agentapi` and
   `agentclient`, update HF to use them, and leave `repo.create` classification
   and execution in HF.
3. Add `agentconformance` fixtures and run them against HF for discovery,
   submission, idempotent retry,
   status, waiting/events, approval transitions, restart recovery, terminal
   results, and error envelopes.
4. Migrate GH discrete approved operations to Agent V1 and delete replaced
   lifecycle routes, clients, stores, and response types in the same slice.
   Keep Git smart HTTP, read-only repository APIs, webhooks, and provider
   execution local.
5. Migrate sudo command requests and execution to one Agent V1 operation
   lifecycle backed by the existing exact immutable plan and privileged helper.
   Delete replaced lifecycle routes, clients, stores, and response types in the
   same slice.
6. Update setup, CLI, MCP, docs, examples, and conformance coverage to use only
   the Agent V1 operation surface.

Cutover rules:

- Do not retain aliases for replaced operation routes.
- Do not read or convert superseded operation state.
- Do not dual-write old and Agent V1 stores.
- Streaming Git traffic and ordinary read APIs do not become Agent V1
  operations.
- Agent V1 never becomes a generic arbitrary provider API or shell executor.
- Each broker remains independently deployed with its own operation store,
  credentials, plans, listener, and audit stream.

Deletion targets:

- `brokers/huggingface/internal/hfoperation`;
- generic Agent V1 HTTP/client lifecycle code currently embedded in HF; and
- GH and sudo operation lifecycle code replaced by their Agent V1 adapters.

Acceptance:

- HF, GH, and sudo pass the same Agent V1 lifecycle conformance suite.
- Identical submissions are idempotent across restarts.
- Invalid transitions and ambiguous executions fail closed.
- Each operation is bound to one immutable provider plan before approval can
  authorize execution.
- Sudo still crosses privilege only through its peer-authenticated helper and
  exact cataloged plan.
- Provider credentials, plans, classifiers, and execution code never enter the
  shared Agent V1 packages.

### 6. Decompose the HF HTTP Package

Problem: the HF HTTP package remains difficult to review because unrelated Git,
LFS/Xet, repository-read, grant, and routing behavior is concentrated in a
large server file.

Implementation:

- Split files by domain inside the existing `httpapi` package.
- Keep server construction and shared dependencies in one small assembly file.
- Keep route classification separate from provider execution.
- Do not add interfaces solely to reduce file length.
- Perform this after the Git, audit, and doctor extractions so code is moved
  only once.

Acceptance:

- No route or response changes.
- Existing package tests remain the behavioral contract.
- Each production file has one clear responsibility.

### 7. Extract Setup Helpers Only When Exact

HF and GH systemd commands share small mechanics such as loopback readiness
clients, URL rendering, root checks, and summaries. Sudo has a materially
different two-unit privileged design.

Extract only exact, security-equivalent helpers used by at least two brokers.
Do not create a callback-heavy setup framework. Provider credential validation,
managed file selection, environment rendering, service hardening, and summaries
remain local. Sudo's frontend/helper installation remains separate.

## Deliberate Non-Goals

The refactor must not combine:

- HF, GH, and sudo processes, listeners, credentials, state, or releases;
- provider operation registries or target vocabularies;
- provider request classification or upstream execution;
- HF and GH immutable plan schemas;
- sudo command catalogs, identity transitions, or privileged helper protocol;
- provider approval wording and safe presentation fields;
- direct and delegated OpenClaw trust modes; or
- agent and operator credentials or APIs.

## Quality Gates

Run for every slice:

```sh
go fmt ./...
go vet ./...
go test -race ./...
go test ./...
golangci-lint run
scripts/check-architecture.sh
slophammer-go dry .
slophammer-go check .
```

Also run each affected broker's Slophammer configuration and focused
integration tests. Protocol changes must run generation checks, fixture tests,
the OpenClaw plugin checks, packed-install test, and cross-browser tests.

Review each slice against these invariants:

- no provider import from a root package;
- no secret, body, plan content, or credential metadata in logs or errors;
- no compatibility route, old-state reader, converter, dual read, or dual
  write;
- no weakening of fail-closed behavior;
- no new shared abstraction without two concrete consumers or an existing
  duplicate root implementation; and
- provider-local code is deleted in the same slice that adopts the shared API.

Mutation testing remains disabled and non-blocking.

## Completion Criteria

The refactor is complete when:

- schemas drive protocol enums, limits, and bindings;
- HF and GH use one Git framing implementation;
- HF uses the shared audit recorder;
- HF isolation is a thin provider adapter over shared doctor primitives;
- HF, GH, and sudo use the shared Agent V1 lifecycle for discrete approved
  operations;
- the HF HTTP package is decomposed without behavior changes;
- all architecture, security, test, coverage, Slophammer, plugin, and CI gates
  pass; and
- no provider-specific credential, policy vocabulary, plan schema, or executor
  has moved into BrokerKit.
