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

### 1. Make the Quality Gate Honest

Problem: the HF Slophammer CRAP command currently accepts every exit status of
`1`. That can hide coverage or tool failures in addition to the known accepted
complexity finding.

Implementation:

- Remove the blanket shell-level exit-code exception.
- Represent any temporary complexity exception in checked-in Slophammer
  configuration, scoped to an exact file, function, metric, and documented
  reason.
- Keep coverage failures, command failures, malformed output, and newly
  discovered findings fatal.
- Delete each temporary exception in the slice that removes its target.

Acceptance:

- A known scoped finding is reported without failing CI.
- A synthetic new finding, coverage failure, or Slophammer command failure makes
  CI fail.
- CI and the documented local command run the same gate.

### 2. Standardize Strict Boundary Decoding and Bounded I/O

Problem: security-sensitive JSON decoding is inconsistent. Some paths reject
duplicate keys and trailing content while others decode permissively. GH pull
request creation and HF LFS classification inspect a body and then forward the
original bytes, allowing the broker and upstream to interpret malformed input
differently. Some HF receive-pack and LFS responses are also buffered without a
size limit.

Implementation:

- Extend `internal/strictjson` and `httpx` with one bounded decode operation that
  rejects duplicate keys, trailing JSON values, oversized bodies, and unknown
  fields when the endpoint has a closed request schema.
- Use the shared operation for every security-relevant client JSON boundary.
- For inspect-and-forward routes, either forward a canonical validated encoding
  or prove with tests that the exact forwarded bytes have one unambiguous parse.
- Add explicit limits to every buffered upstream response, including HF
  receive-pack reports and rewritten LFS batch responses.
- Keep streaming routes streaming. Enforce a byte budget while copying rather
  than buffering them solely to apply a limit.
- Return stable client and upstream error classes without including body
  contents.

Deletion targets:

- Endpoint-local combinations of `ReadLimited`, duplicate-key checking,
  `json.Decoder`, trailing-value checks, and size checks that the shared helper
  replaces.

Acceptance:

- Duplicate keys, unknown fields on closed schemas, trailing values, empty
  bodies, and oversized bodies have shared table-driven tests.
- Policy classification and upstream execution cannot observe different values
  from one request body.
- Oversized upstream receive-pack, LFS, API, and inference responses fail within
  configured memory bounds.
- Streaming proxy tests prove cancellation, backpressure, and bounded copying.

### 3. Make Time and Entropy Explicit Runtime Inputs

Problem: lifecycle and HTTP code calls `time.Now` and random generators directly,
and one correlation-ID path degrades to a timestamp if secure randomness fails.
This makes restart and expiry behavior harder to test and permits inconsistent
failure semantics.

Implementation:

- Define small clock and secure-ID function dependencies at shared service
  boundaries; do not introduce a general dependency-injection framework.
- Pass one UTC clock through grants, decisions, Agent operations, plan retention,
  and request correlation where those components must agree on time.
- Require cryptographically secure generation for tokens and security-relevant
  identifiers and return an error when entropy is unavailable.
- Permit a clearly labeled non-security fallback only for observability-only
  correlation values, or remove the fallback entirely when the caller can
  propagate an error.
- Use deterministic clocks and ID sources in lifecycle, restart, expiry, and
  idempotency tests.

Acceptance:

- Lifecycle tests contain no sleeps to cross expiry boundaries.
- Entropy failure cannot produce a token, grant ID, decision token, operation ID,
  or other authorization input.
- One request or transition uses one captured timestamp where consistency
  matters.

### 4. Move Durable State to SQLite

Problem: grant, operation, and helper stores use process-local mutexes and atomic
rename but have no cross-process ownership. Two broker processes can read the
same old state and overwrite each other. Atomic replacement prevents torn files;
it does not prevent lost updates. Separate grant, plan, operation, event, and
notification files also prevent one atomic lifecycle transaction.

Implementation:

- Use `database/sql` with the pure-Go `modernc.org/sqlite` driver so Linux and
  macOS releases remain CGO-free.
- Give each independently deployed broker one local `state.db`. Keep the sudo
  privileged helper's root-owned execution database separate from the
  unprivileged frontend database.
- Store grants, immutable plans, Agent operations, lifecycle events, decision
  records, notification outbox entries, idempotency records, and schema metadata
  in normalized tables with explicit foreign keys and unique constraints.
- Put plan binding, grant or operation creation, lifecycle event append, and
  notification outbox insertion in one SQL transaction.
- Enable foreign keys, WAL mode, a bounded busy timeout, and an explicitly
  documented synchronous policy during every database initialization. Use the
  stronger durability setting for authorization and execution state.
- Add ordered, checksummed schema migrations owned by BrokerKit. Do not use GORM
  or automatic schema migration for broker state.
- Acquire a small OS-level process-lifetime state-directory lease before opening
  the database, listeners, or approval transports. SQLite protects database
  writes; the lease prevents two broker processes from duplicating external side
  effects such as polling and notification delivery.
- Bound every text and blob column at ingress and reject unknown schema versions
  or invalid required state before serving traffic.
- Define restart recovery for reservations, pending notifications, retained
  executions, Agent operations, and outbox delivery, and test interruption at
  each durable transition.
- Provide integrity checking, consistent backup, and redacted JSON export for
  operators. The live database is not an operator-edited configuration surface.
- Require local-disk state. Network filesystems are unsupported unless their
  SQLite locking and durability behavior is separately proven.
- Cut over directly. Do not read, migrate, or dual-write the superseded JSON
  lifecycle stores.

Deletion targets:

- JSON lifecycle stores and their process-local transaction emulation;
- filesystem-backed immutable plan storage and orphan-plan garbage collection;
  and
- durable-state parsing paths that exist only for the replaced JSON formats.

Acceptance:

- A second process cannot open the same broker state directory.
- Crash-point tests prove a lifecycle transaction is entirely committed or
  entirely absent, including its immutable plan, event, and outbox entry.
- Foreign-key, idempotency, revision, and state-transition invariants are enforced
  under concurrent requests and across restarts.
- Corrupt databases, failed migrations, oversized values, and unknown schema
  versions fail closed without being overwritten.
- `PRAGMA integrity_check`, backup/restore, and redacted export have automated
  tests.
- Linux and macOS ownership behavior has focused tests.

### 5. Make Protocol Artifacts Single-Source

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

### 6. Finish Git pkt-line Consolidation

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

### 7. Move HF Request Auditing onto the Shared Recorder

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

### 8. Finish Doctor and Isolation Consolidation

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

### 9. Unify Immutable Plan and Grant Transactions

Problem: HF, GH, and sudo independently implement the same provider-neutral
sequence: locate an idempotent request, bind an immutable plan, create the
durable grant, and recover or clean up after partial failure. SQLite now permits
that sequence to become one transaction rather than coordinated filesystem and
JSON writes.

Shared ownership:

- A small root transaction service owns the ordering, idempotency, revision, and
  event/outbox contract across shared SQLite repositories.
- The coordinator accepts a narrow typed plan interface. It must not accept
  unstructured callbacks or know provider schemas.

Provider ownership:

- canonical plan construction and validation;
- plan schema names, metadata keys, and typed decoding;
- activation checks and execution; and
- provider-specific errors and presentation.

Implementation:

- Define the shared bind/request/replay contract from the three existing broker
  implementations and conformance tests before moving code.
- Persist canonical provider plan bytes and their digest in the same transaction
  that creates the grant or operation reference.
- Make replay a unique-key lookup that returns the original immutable plan and
  committed lifecycle record without rewriting timestamps.
- Adopt it in HF first, then GH and sudo, deleting each local implementation in
  the same change.
- Use the SQLite transaction and state-directory lease instead of introducing a
  second locking or orphan-reconciliation mechanism.

Acceptance:

- HF, GH, and sudo pass the same create, replay, cancellation, missing-plan,
  digest-mismatch, concurrent-request, rollback, and crash-recovery fixtures.
- An idempotent replay resolves to the original immutable plan and timestamp.
- Approval can never activate a missing, changed, or mismatched plan.
- No provider plan type or policy vocabulary enters a root package.

### 10. Standardize All Brokers on Agent Operations V1

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

### 11. Decompose the HF HTTP Package and Tests

Problem: the HF HTTP package remains difficult to review because unrelated Git,
LFS/Xet, repository-read, grant, and routing behavior is concentrated in a
large server file.

Implementation:

- Split files by domain inside the existing `httpapi` package.
- Keep server construction and shared dependencies in one small assembly file.
- Keep exactly one authoritative route table and one HTTP framework boundary;
  remove redundant hand-routing layers as behavior-preserving tests permit.
- Keep route classification separate from provider execution.
- Split the package's monolithic test file by the same domains while retaining
  shared black-box fixtures and helpers in dedicated test support files.
- Do not add interfaces solely to reduce file length.
- Perform this after the Git, audit, and doctor extractions so code is moved
  only once.

Acceptance:

- No route or response changes.
- Existing package tests remain the behavioral contract.
- Each production file has one clear responsibility.
- Each test file covers one domain, and route ownership can be determined from
  one table without tracing multiple dispatch layers.

### 12. Extract Setup Helpers Only When Exact

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
slophammer-go crap .
```

Also run each affected broker's Slophammer configuration and focused
integration tests. Protocol changes must run generation checks, fixture tests,
the OpenClaw plugin checks, packed-install test, and cross-browser tests. No
quality command may be wrapped in a blanket accepted exit code; temporary
exceptions must identify the exact finding in checked-in configuration.

Review each slice against these invariants:

- no provider import from a root package;
- no secret, body, plan content, or credential metadata in logs or errors;
- no compatibility route, old-state reader, converter, dual read, or dual
  write;
- no weakening of fail-closed behavior;
- no unbounded buffering at a client, upstream, state, or subprocess boundary;
- no permissive JSON decoding at an authorization or durable-state boundary;
- no second process able to mutate the same broker state directory;
- no direct wall-clock or entropy dependency hidden inside a shared lifecycle
  transition;
- no new shared abstraction without two concrete consumers or an existing
  duplicate root implementation; and
- provider-local code is deleted in the same slice that adopts the shared API.

Mutation testing remains disabled and non-blocking.

## Completion Criteria

The refactor is complete when:

- all security-relevant JSON and buffered I/O boundaries use shared strict,
  bounded mechanics;
- each broker exclusively owns and can recover its transactional SQLite state;
- lifecycle time and secure identifiers come from explicit, testable runtime
  dependencies;
- schemas drive protocol enums, limits, and bindings;
- HF and GH use one Git framing implementation;
- HF uses the shared audit recorder;
- HF isolation is a thin provider adapter over shared doctor primitives;
- HF, GH, and sudo use one provider-neutral immutable plan/grant SQL transaction
  contract while retaining provider plan schemas;
- HF, GH, and sudo use the shared Agent V1 lifecycle for discrete approved
  operations;
- the HF HTTP package and tests are decomposed around one routing layer without
  behavior changes;
- all architecture, security, test, coverage, Slophammer, plugin, and CI gates
  pass; and
- no provider-specific credential, policy vocabulary, plan schema, or executor
  has moved into BrokerKit.
