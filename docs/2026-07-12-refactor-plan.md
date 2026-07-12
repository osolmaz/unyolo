# BrokerKit Refactor Plan

Date: 2026-07-12

Last updated: 2026-07-13

Status: active

## Objective

Remove the remaining provider-neutral duplication without moving Hugging Face,
GitHub, or Unix behavior into BrokerKit. The result should have one shared
implementation for common protocol, Git framing, audit, and host-inspection
mechanics while each broker retains its own classification, credentials,
execution, plans, and user-facing wording.

Implement the plan on one branch as a single coordinated, fresh-state cutover.
Use coherent green commits to keep the work reviewable, but do not ship an
intermediate architecture, compatibility routes, state importers, dual reads,
or dual writes. The cutover preserves security semantics and provider
capabilities, but it does not preserve replaced routes or state formats.

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

## Dependency and Vendoring Policy

Prefer maintained upstream libraries for mature protocol, storage, and provider
behavior. Wrap them at BrokerKit ownership boundaries so external types do not
spread through policy, lifecycle, or provider execution code.

Libraries with fewer than 500 GitHub stars may be source-vendored when the
required surface is small and BrokerKit needs tighter security review,
refactoring, release control, or long-term maintenance. The star threshold makes
a library eligible for review; it is not sufficient by itself.

For a source-vendored library:

- require a permissive, compatible license and preserve its license, copyright,
  notices, and required attribution;
- place maintained source under a clearly named internal third-party boundary,
  not Go's generated `vendor/` directory;
- add an `UPSTREAM.md` recording repository URL, exact commit or release, import
  date, retained files, local changes, and the upstream comparison/update
  procedure;
- copy only the required behavior and upstream tests, then refactor it to
  BrokerKit's bounded I/O, clock, error-redaction, and ownership contracts;
- keep local changes reviewable as a patch against the recorded upstream
  revision and periodically audit upstream security and correctness fixes; and
- delete the module dependency and any unused upstream surface in the same
  change.

Do not source-vendor large established libraries merely to avoid dependencies.
Do not vendor code with unclear provenance, incompatible licensing, generated
source that cannot be reproduced, or security behavior BrokerKit cannot test.

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

The numbered sections are the implementation order within one cutover branch.
Each section must be green and committed before the next starts, but the branch
ships only after every required section and end-to-end gate passes.

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
- Give each independently deployed unprivileged broker one local `state.db`.
  Keep SQLite, sqlc, and Goose out of the sudo privileged helper. The helper
  stays stateless where possible and otherwise retains only the minimum bounded,
  root-owned atomic-file state needed to enforce an already authorized
  execution.
- Before defining the schema, extract the provider-neutral lifecycle from
  `brokers/huggingface/internal/hfoperation` into the final root `agentops`
  domain package. Define the plan/grant/operation transaction contract against
  domain types first, then implement it once in SQLite. Do not migrate an
  HF-local schema and move it again later.
- Store grants, immutable plans, Agent operations, lifecycle events, decision
  records, notification outbox entries, idempotency records, and schema metadata
  in normalized tables with explicit foreign keys and unique constraints.
- Keep schema and query SQL canonical. Use pinned
  [`sqlc`](https://github.com/sqlc-dev/sqlc) tooling to generate typed
  `database/sql` query code for SQLite; commit generated output and never edit it
  by hand.
- Keep generated sqlc row and parameter types inside the state repository.
  Convert them to BrokerKit domain types at that boundary so storage details do
  not leak into policy, grants, Agent V1, or provider packages.
- Put plan binding, grant or operation creation, lifecycle event append, and
  notification outbox insertion in one SQL transaction. Use the sqlc
  transaction binding rather than issuing related statements through the base
  connection.
- Make the root transaction service own provider-neutral ordering,
  idempotency, revision checks, replay, and event/outbox insertion. It accepts a
  narrow typed immutable-plan envelope and never imports provider schemas or
  executes provider callbacks.
- Keep canonical plan construction, schema validation, activation checks,
  execution, and provider-specific errors in each broker. Persist canonical
  provider plan bytes and their digest in the lifecycle transaction. An
  idempotent replay returns the original plan, event, and timestamp without a
  write.
- Enable foreign keys, WAL mode, a bounded busy timeout, and an explicitly
  documented synchronous policy during every database initialization. Use the
  stronger durability setting for authorization and execution state.
- Use pinned [`Goose`](https://github.com/pressly/goose) tooling and its library
  with embedded, ordered SQL migrations. Run migrations after acquiring the
  state lease and before opening listeners or approval transports.
- Keep applied migration history in SQLite and a repository-owned checksum
  manifest in CI so an applied migration can never be silently rewritten.
- The initial SQLite cutover starts from an empty database and does not import
  the superseded JSON state. Retain and test prior-schema migration fixtures
  only after a SQLite schema has shipped in a release; before then, replace the
  unreleased v1 schema in place.
- Do not use GORM, sqlx, `AutoMigrate`, or a second migration runner for broker
  state.
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
- HF, GH, and sudo pass the same create, replay, cancellation, missing-plan,
  digest-mismatch, concurrent-request, rollback, and crash-recovery fixtures.
- An idempotent replay returns the original immutable plan and timestamp, and
  approval can never activate a missing, changed, or mismatched plan.
- Foreign-key, idempotency, revision, and state-transition invariants are enforced
  under concurrent requests and across restarts.
- Corrupt databases, failed migrations, oversized values, and unknown schema
  versions fail closed without being overwritten.
- `sqlc generate` and `sqlc vet` pass and leave no repository diff; all
  handwritten SQL is covered by generated typed methods or an explicitly
  documented operational query.
- Embedded Goose migrations create an empty database, upgrade every retained
  released fixture schema when such fixtures exist, reject checksum drift, and
  fail startup before side effects on migration error.
- Architecture checks reject GORM and sqlx imports in BrokerKit state packages.
- `PRAGMA integrity_check`, backup/restore, and redacted export have automated
  tests.
- Linux and macOS ownership behavior has focused tests.

### 5. Make OpenAPI 3.1 the Sole Protocol Source

Problem: Operator V1 and Agent V1 are represented by OpenAPI documents,
standalone JSON Schemas, handwritten Go structs, generated TypeScript types, and
handwritten runtime validators. Multiple claimed sources of truth allow routes,
wire types, enums, and limits to drift.

Implementation:

- Make the Operator V1 and Agent V1 OpenAPI documents valid OpenAPI 3.1 and the
  sole canonical protocol sources. Define every payload under
  `components/schemas` and reference it from routes and responses.
- Pin an exact tested revision of
  [`oapi-codegen`](https://github.com/oapi-codegen/oapi-codegen) containing the
  required OpenAPI 3.1 support. Generate Go wire types and clients at the shared
  protocol boundary and Echo server interfaces at broker HTTP boundaries. Move
  to the first suitable tagged release without changing the generated contract.
- Pin the matching OpenAPI 3.1-capable
  [`kin-openapi`](https://github.com/getkin/kin-openapi) revision used by the
  generator and validate every document and reference in generation and CI. Do
  not maintain a downgraded OpenAPI 3.0 mirror or conversion pipeline.
- Generate TypeScript types with pinned `openapi-typescript`. Extract standalone
  JSON Schema 2020-12 artifacts directly from canonical OpenAPI components and
  compile runtime validators from those artifacts with Ajv 2020. Standalone
  schemas, validators, constants, and TypeScript types are generated consumer
  outputs, never independently edited inputs.
- Keep generated artifacts committed, marked as generated, deterministic, and
  verified by a clean-tree generation check.
- Keep `strictjson` before generated/schema validation for bounded reads,
  duplicate-key rejection, trailing-content rejection, and closed-object
  decoding. Schema validation does not resolve parser differentials.
- Adapt authentication, audit, provider presentation, decisions, and execution
  behind generated interfaces; do not put policy into generated code.
- Keep Echo as the one broker HTTP framework. Generate Echo-compatible route
  registration for bounded JSON endpoints. Keep explicit handwritten Echo
  handlers for Git smart HTTP, LFS/Xet, inference proxying, SSE, and other
  streaming paths where generated binding would change streaming, cancellation,
  backpressure, or byte-preservation semantics. Record that allowlist in CI.
- Keep domain services independent of `echo.Context` and generated wire types.
  Broker transport adapters translate generated request/response types to
  provider-neutral domain types.
- Preserve required security and provider semantics, but correct existing wire
  drift directly in canonical v1. Do not retain compatibility aliases for
  replaced handwritten shapes.

Deletion targets:

- Hand-maintained protocol wire structs, enums, and limit lists;
- standalone schema sources replaced by generated artifacts;
- handwritten Operator V1 and Agent V1 clients and JSON route bindings replaced
  by generated equivalents.

Acceptance:

- Editing one OpenAPI component and running one command updates Go, TypeScript,
  and standalone JSON Schema artifacts.
- CI fails on an invalid reference, stale artifact, duplicate operation ID,
  undocumented route, or uncommitted generation diff.
- Operator V1 and Agent V1 fixtures validate and round-trip through OpenAPI, Go,
  TypeScript, and standalone schemas.
- Generated clients and handlers pass the existing black-box protocol and
  cross-browser suites.
- Every broker has one authoritative Echo route-registration path after
  cutover, and CI rejects an unlisted handwritten JSON route.

### 6. Adopt go-git Behind the Bounded gitx Boundary

Problem: `gitx` parses pkt-lines and receive-pack commands, while
`brokers/huggingface/internal/gitproxy/pktline` separately implements buffered
scanning and encoding for the same wire format. HF also owns custom packfile and
delta parsing. Maintaining private implementations of mature Git formats creates
unnecessary protocol and security ownership.

Implementation:

- Adopt the latest suitable stable go-git v5 release. Import only the pkt-line,
  packfile, delta, object, and storage packages required behind `gitx`; do not
  spread go-git types into provider policy or HTTP packages and do not
  source-vendor the library.
- Build a checked-in corpus from current HF and GH tests covering valid and
  malformed pkt-lines, receive-pack commands, side-band reports, packfiles,
  thin packs, ofs/ref deltas, trailing pack data, SHA-1 packs, SHA-1/SHA-256
  command framing, size limits, object-count limits, cancellation, and current
  refusal behavior.
- Run that corpus and focused fuzzing against go-git through BrokerKit-owned
  readers, temporary storage, contexts, and observers that enforce compressed
  bytes, inflated bytes, object count, object size, delta depth, allocation,
  disk, and time limits before provider logic sees an object.
- Use go-git for stable SHA-1 pkt-line, packfile, object, and delta behavior.
  Keep the narrow receive-pack command framing needed to recognize both SHA-1
  and SHA-256 object IDs until a stable go-git release supports SHA-256 packs end
  to end. Do not claim that SHA-256 command recognition implies SHA-256 pack
  support.
- Preserve exact trailing bytes and side-band/report behavior where BrokerKit is
  a transparent proxy. Do not decode and re-encode a body unless conformance
  tests prove byte-preservation is unnecessary for that route.
- Convert HF and GH to the shared `gitx` adapter and delete every custom
  pkt-line, packfile, object, and delta implementation go-git replaces. Any
  retained custom framing must be narrow, documented by a concrete upstream
  gap, and covered by corpus and fuzz tests.
- If the stable library cannot enforce a required limit before allocation or
  decompression, add the limit in the BrokerKit adapter or contribute the
  necessary upstream hardening. Do not silently weaken the limit or restore a
  broad private parser.
- Keep HF ancestry, mirror, LFS/Xet, policy classification, refusal responses,
  and provider-specific error wording local.

Deletion targets:

- `brokers/huggingface/internal/gitproxy/pktline`; and
- custom packfile, object, delta, and receive-pack report parsing replaced by
  go-git, retaining only the documented SHA-256 command-framing or transparent
  proxy behavior that stable go-git cannot provide.

Acceptance:

- The implementation record explicitly covers thin packs and deltas, SHA-1
  packs, SHA-1/SHA-256 command framing, strict byte and object limits, trailing
  data preservation, cancellation, dependency cost, and current refusal/report
  behavior.
- HF and GH use one `gitx` boundary backed by go-git for supported formats.
- Malformed framing, flush packets, trailing pack data, compression bombs,
  excessive delta depth, and maximum lengths have shared tests and fuzz seeds.
- Existing Git proxy integration tests remain unchanged in behavior.

### 7. Keep Provider SDK Adoption Evidence-Based

The OpenAPI, state, and Git cutovers do not require a simultaneous rewrite of
the working GitHub integration. Keep GitHub App authentication and narrow REST
operations behind existing GH-owned interfaces during this refactor.

Use `google/go-github` later when a concrete capability needs substantial typed
resource coverage, pagination, webhook parsing, rate-limit handling, or API
error behavior that it implements better than the current bounded code. Use
`ghinstallation` when its token cache and refresh behavior removes more
security-sensitive code than it introduces. In either case, pin the upstream
module, wrap it with BrokerKit deadlines, bounds, redirect policy, base-URL
policy, redaction, and clocks, and delete the replaced implementation in the
same change.

Do not source-vendor either library based on star count. Source vendoring needs
a separate ownership or supply-chain justification under the repository policy;
an ordinary pinned module remains the default.

### 8. Move HF Request Auditing onto the Shared Recorder

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

### 9. Finish Doctor and Isolation Consolidation

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

1. Complete the `agentops` domain and SQLite repository started in section 4,
   update HF to use it, and delete the HF-local package in the same commit.
2. Move the generic HF Agent V1 HTTP and client mechanics into `agentapi` and
   `agentclient`, update HF to use them, and leave `repo.create` classification
   and execution in HF.
3. Add `agentconformance` fixtures and run them against HF for discovery,
   submission, idempotent retry,
   status, waiting/events, approval transitions, restart recovery, terminal
   results, and error envelopes.
4. Within the cutover branch, migrate GH discrete approved operations to Agent
   V1 and delete replaced
   lifecycle routes, clients, stores, and response types in the same slice.
   Keep Git smart HTTP, read-only repository APIs, webhooks, and provider
   execution local.
5. Within the same branch, migrate sudo command requests and execution to one
   Agent V1 operation
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
- Do not deploy HF, GH, or sudo from this branch until all three migrations and
  the cross-broker conformance suite are green.

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

It also does not require removing Echo, rewriting a working GitHub integration,
or source-vendoring provider SDKs. Those changes need separate evidence that
they remove more complexity or security ownership than they add.

## Quality Gates

Run for every slice:

```sh
go fmt ./...
go vet ./...
go test -race ./...
go test ./...
go generate ./...
govulncheck ./...
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

Dependency and vendoring changes must also verify:

- `go mod tidy` leaves no diff and generated code uses pinned tool versions;
- direct and transitive licenses are compatible with the repository;
- every source-vendored package has complete license and `UPSTREAM.md`
  provenance;
- the recorded upstream comparison produces only the documented local patch;
  and
- retained upstream tests plus BrokerKit boundary, redaction, limit, race, and
  supported-platform tests pass.

SQLite changes must also run pinned `sqlc generate` and `sqlc vet`, verify a
clean generated-code diff, apply embedded Goose migrations to an empty database
and any retained released prior-schema fixtures, and run
`PRAGMA integrity_check` on the result.

`scripts/check-architecture.sh` must gain a forbidden-import or forbidden-path
rule in the same slice as each cutover. Once a replacement lands, CI must reject:

- GORM, sqlx, alternate SQLite drivers, and alternate migration runners in the
  BrokerKit state layer;
- JSON lifecycle stores and filesystem plan stores after the SQLite cutover;
- handwritten Operator V1 or Agent V1 wire and route bindings after generation;
- a second HTTP framework beside Echo in broker HTTP packages;
- unlisted handwritten JSON routes outside generated Echo registration; and
- broker-local Git parsers superseded by go-git through `gitx`.

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
- no external provider or generated type leaking into policy, grant, plan, or
  executor ownership boundaries;
- no ORM, alternate SQL helper, or migration framework beside the selected
  SQLite stack in BrokerKit's state layer;
- no modified third-party source without recorded license, provenance, upstream
  revision, and comparison procedure;
- no new shared abstraction without two concrete consumers or an existing
  duplicate root implementation; and
- provider-local code is deleted in the same slice that adopts the shared API.

Mutation testing remains disabled and non-blocking.

## Completion Criteria

The refactor is complete when:

- all security-relevant JSON and buffered I/O boundaries use shared strict,
  bounded mechanics;
- each broker exclusively owns and can recover its transactional SQLite state;
- BrokerKit state uses only `modernc.org/sqlite`, `database/sql`, generated sqlc
  queries, and embedded Goose migrations, with storage types contained behind
  shared repositories;
- lifecycle time and secure identifiers come from explicit, testable runtime
  dependencies;
- OpenAPI 3.1 components are the sole protocol source and generate Go,
  TypeScript, runtime validators, standalone schemas, clients, and server
  interfaces;
- generated Operator V1 and Agent V1 Echo boundaries have replaced handwritten
  JSON route/client bindings while allowlisted streaming routes retain their
  explicit Echo handlers;
- stable go-git backs the shared `gitx` pkt-line, SHA-1 packfile, object, and
  delta implementation under BrokerKit resource bounds, with only documented
  unsupported framing retained;
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
- architecture checks reject every superseded store, parser, handwritten JSON
  binding, and duplicate HTTP framework after cutover;
- every source-vendored dependency is minimal, licensed, attributable,
  comparison-tested, and assigned an upstream update procedure;
- no provider-specific credential, policy vocabulary, plan schema, or executor
  has moved into BrokerKit.
