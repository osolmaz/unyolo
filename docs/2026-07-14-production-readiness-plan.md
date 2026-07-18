# Production-Readiness Implementation Plan

Date: 2026-07-14

Status: complete

## Implementation Result

Completed on 2026-07-15. The coordinated cutover delivered the endpoint and
policy-preset plans plus the remaining production hardening in this record.

- Runtime configuration now requires explicit endpoints, identities, trusted
  production paths, 32-byte credentials, and explicit audit wiring.
- Shared packages own HTTP profiles, operation lifecycles, bounded admission,
  state maintenance, credential lifecycle, observability, service setup, and
  cancellable background work.
- Linux systemd and macOS launchd paths, immutable installers and workflows,
  GitHub upstream drift checks, and provider-owned comprehensive operation
  catalogs are covered by CI fixtures.
- Current-format SQLite state supports check, backup, restore, and redacted
  export. Credential replacement, revocation, dependency diagnostics, failure
  drills, and bounded metrics are exercised by direct tests.
- Provider-local duplicate mechanics, fixed ports, personal defaults, stale
  compatibility fields, quality baselines, and direct CRAP/DRY exceptions were
  removed. Root and broker-local Slophammer gates enforce the resulting shape.

## Objective

Finish BrokerKit as a portable production platform rather than preserve the
assumptions of its first host. Remove machine-specific defaults, implicit
network behavior, permissive configuration fallbacks, duplicated runtime code,
temporary quality exceptions, incomplete operating-system support, and mutable
release inputs.

This is a coordinated pre-release cutover. Backward compatibility with
pre-release configuration, state, service units, client files, or deployment
conventions is not a requirement. Delete replaced code and configuration in
the same slice that introduces its successor. Do not merge a dual architecture
and do not publish a final release until every acceptance criterion in this
plan passes.

The detailed listener design remains in the
[listener endpoint architecture plan](2026-07-14-listener-endpoint-architecture-plan.md).
This plan is the umbrella execution and release gate for that design and all
other production-readiness work discovered with it.

## Required Outcomes

1. BrokerKit has no fixed production TCP ports.
2. BrokerKit has no defaults tied to a particular person's Unix or operator
   identity.
3. Credentials never traverse non-loopback plaintext HTTP.
4. Present-but-invalid configuration always fails closed.
5. Production paths and deployment mode are explicit.
6. Every HTTP server and client uses one reviewed timeout and streaming model.
7. Linux and macOS have complete native setup and lifecycle support.
8. All providers use the shared Agent operation lifecycle and policy-preset
   framework.
9. GH Broker provides a safe managed policy preset for its exhaustive operation
   catalog.
10. No checked-in CRAP exception exceeds the repository limit; temporary CRAP
    baseline files are empty and removed.
11. Installation and release flows verify immutable, attributable artifacts.
12. GitHub capability coverage has a durable upstream-drift process.
13. CI and release environments are pinned, reproducible, and cover supported
    operating systems.
14. Maintained documentation describes only the final architecture.
15. Current-format SQLite state can be checked, backed up, restored, and
    exported safely without legacy readers or schema conversion.
16. Authenticated clients cannot exhaust workers, state, approval channels, or
    operator attention with unbounded requests.
17. Every broker credential class has one atomic replacement and immediate
    revocation path.
18. Operators receive secret-safe health, metrics, and structured diagnostics.
19. Crash, storage, clock, notification, upstream, and partial-setup failures
    have deterministic fail-closed behavior.
20. Broker client and operator credentials share one minimum 32-byte secret
    requirement across setup and runtime authentication.
21. Every production control plane requires an explicit audit recorder; missing
    wiring cannot silently discard security evidence.
22. Every background poller, notification worker, and sweeper participates in
    one cancellable lifecycle and finishes before durable state closes.
23. Every broker's Slophammer configuration, including sudo's, is enforced in
    CI rather than excluded or treated as documentation.
24. Convenience installation never invokes `sudo` or otherwise escalates
    privilege implicitly.

## Current Problems To Remove

### Fixed and inconsistent listeners

Current source defaults include:

- HF agent and operator listeners on `8080` and `8081`;
- GH direct runtime listeners on `8080` and `8082`;
- GH systemd setup listeners on `8081` and `8082`;
- sudo agent and operator listeners on `8084` and `8085`; and
- earlier pre-release installation values in the `18080`-`18082` range.

The GH direct and installed defaults already disagree. Choosing a less popular
range would retain the same architectural failure. Remove all implicit TCP
ports and implement the deployment-owned endpoint model in the listener plan.

### Machine-specific identities

GH and sudo setup currently default the client to `bob`. HF, GH, and sudo setup
default the operator to `onur`. GH runtime configuration also defaults to those
identities. These values are installation data, not product defaults.

Require explicit client and operator identities whenever setup grants access or
creates credentials. An interactive helper may offer the invoking non-root
identity only after displaying it and requiring confirmation. Privileged and
non-interactive setup must not infer identity from `root`, `$HOME`, `SUDO_USER`,
or a compiled default.

Tests use neutral identities such as `agent-a` and `operator-a`. Documentation
may use clearly fictional examples but must not make them defaults.

### Plaintext credential transport

The shared client URL validator accepts plaintext HTTP for arbitrary hosts. HF
upstream validation also permits arbitrary HTTP origins while its clients send
the protected HF token. OpenClaw already applies the stronger rule and should
not remain the only safe caller.

Adopt one provider-neutral origin policy:

- HTTPS is required for network origins.
- Plain HTTP is accepted only for literal loopback addresses in an explicit
  development mode.
- `localhost` is resolved and connected with a loopback-only dial policy or is
  rejected in favor of literal loopback addresses.
- Redirects never forward broker or provider credentials.
- Unix and inherited listeners use the endpoint transport without pretending
  to be externally reachable HTTP origins.
- Provider test servers use injected transports or explicit development
  options, not production relaxations.

Apply the policy to client configuration, Agent and Operator clients, OpenClaw
direct sources, HF Hub and Router origins, GitHub API and web origins, setup,
doctor, and generated examples.

### Silent configuration fallback

GH duration and integer parsers currently replace malformed values with
defaults. That can turn an operator typo into a different running policy.

Replace provider-local environment parsing with one strict typed configuration
boundary. It distinguishes absent values from present empty or malformed
values, reports the exact setting without echoing secrets, and validates the
complete configuration before opening state or listeners. Defaults are allowed
only for documented non-security tuning values when the setting is absent.
There are no aliases or compatibility readers.

### Relative production paths and implicit mode

HF and GH runtime defaults currently include `scope.json` and `./state`. A
service started from a different working directory can silently read or create
different policy and state.

Production startup requires absolute, normalized policy, catalog, credential,
state, socket, and managed-file paths. It verifies ownership, type, mode, and
trusted ancestors before serving. Foreground development may use relative
paths only under an explicit development mode that is visible in startup and
doctor output. Development mode cannot bind externally or load production
credentials.

### Incomplete timeout model

HF servers currently configure only a header timeout, while GH and sudo have
separate timeout implementations. Some callers can preserve a zero HTTP client
timeout accidentally by supplying a custom client.

Add shared server profiles for bounded request/response APIs, Git and binary
streaming, long polling, and operator SSE. Each profile defines header, body,
read, write, idle, handler, shutdown, and upstream timeouts. Streaming uses
context deadlines, byte limits, progress/idle deadlines, and cancellation
instead of an unbounded blanket server timeout. Shared client constructors set
safe defaults even when a caller supplies a transport, while explicit stream
clients remain context-bounded.

### Inconsistent authentication and optional audit evidence

Shared client authentication currently accepts 16-byte secrets and operator
authentication accepts 24-byte secrets, while HF and GH configuration require
32 bytes. Sudo reaches the weaker shared defaults directly, and the shared
secret-file parser does not enforce the production floor. The compatibility
rationale for the weaker defaults conflicts with this fresh-state cutover.

Define one provider-neutral 32-byte minimum for both client and operator
secrets. Apply it in shared authentication, setup, secret-file loading, doctor,
and every broker runtime. Delete provider-local minimum constants and tests for
the weaker values. Generated secrets remain at least 256 bits, but runtime must
also reject hand-edited or externally provisioned credentials below the shared
floor.

The control-plane and provider constructors also currently replace a nil audit
recorder with `audit.New(io.Discard)`. That contradicts the maintained contract
that audit is required and can turn one assembly error into an unaudited
authorization and execution path.

Require an explicit audit recorder at every production constructor boundary and
fail startup when it is absent. Production code cannot select a discard sink;
tests that do not inspect audit output pass an explicit test-only recorder.
Preserve the existing post-commit behavior for external audit export failure:
surface the failure through bounded diagnostics and audit-export status without
rolling back an already committed decision or reporting it as uncommitted.

### Untracked notification workers

Some GH and sudo Telegram pollers and notification sweepers use the caller's
outer context and bypass the server worker wait group. Calling `Close` without
first cancelling that outer context can close SQLite while those goroutines are
still reading or updating notification state.

All background activity must derive from the server's owned lifecycle context,
register before starting, and signal completion exactly once. Shutdown cancels
that context, stops accepting work, waits for operation workers, pollers,
sweepers, and notification delivery, and only then closes stores and the
database. Tests must call `Close` while the original start context remains live
and prove that no worker touches state after closure or loses an accepted
decision callback.

## Platform Architecture

### Deployment-owned endpoints

Implement the listener plan in full:

- canonical `unix`, `tcp`, `activation`, and `fd` endpoint URIs;
- permission-separated agent and operator Unix sockets;
- systemd and launchd named listener activation;
- explicit TCP only when Git, remote clients, or deployment ingress require it;
- no wildcard or non-loopback exposure without explicit acknowledgement;
- one shared client dialer and server listener acquisition boundary; and
- no fallback from a failed local listener to TCP.

Provider binaries consume acquired `net.Listener` values. Provider code must
not parse endpoint URIs, concatenate host and port strings, clean stale sockets,
or implement activation.

### Linux

Extend the existing systemd installer with socket units, named activation,
permission-separated agent/operator access, and readiness against the acquired
listener. Preserve binary-only installation: `setup` owns accounts, files,
socket units, service units, activation, and generated client configuration.

### macOS

Implement the equivalent launchd path rather than treating Darwin builds as
complete platform support:

- typed LaunchDaemon and named-socket rendering;
- dedicated service accounts and groups;
- protected config, state, credential, and runtime paths;
- separate agent and operator socket permissions;
- atomic install, bootstrap, restart, readiness, and safe failure behavior;
- dry-run output matching the Linux setup contract; and
- tests on a real macOS CI runner.

Sudo Broker must validate the Darwin privilege boundary end to end, including
peer credentials, target identity switching, process groups, ACLs, cancellation,
and helper isolation. A binary that builds but cannot be safely installed does
not count as supported.

### Containers and Kubernetes

Images define no default port and no wildcard listener. Manifests explicitly
provide inherited descriptors, mounted Unix sockets, or TCP endpoints. Service,
Ingress, TLS, DNS, and NetworkPolicy remain deployment concerns. The operator
endpoint is never included in the agent Service or ingress.

## Shared Runtime Completion

### Agent lifecycle deduplication

HF, GH, and sudo use the shared `operationruntime` contract. The architecture
gate rejects provider-local lifecycle state transitions and has no temporary
provider allowlist. The shared runtime owns:

- submit and idempotent replay;
- policy classification and grant binding;
- immutable plan creation and validation;
- execution reservation and use budgets;
- worker start, recovery, cancellation, and terminal transitions;
- partial-result reconciliation;
- notification and operator-state transitions;
- lifecycle-owned Telegram polling, notification sweeping, and shutdown
  joining before state closure; and
- audit event sequencing.

Providers retain only target/argument decoding, provider preconditions,
credential selection, execution, reconciliation, and presentation. Sudo's
provider adapter additionally binds the exact reserved grant revision into its
privileged-helper protocol immediately before dispatch.

### Provider-neutral policy presets

Implement the existing provider-neutral preset plan now that GH has an
exhaustive catalog. The shared framework owns profile persistence, generated
artifact metadata, deterministic rendering, deny overrides, replacement rules,
drift detection, setup integration, doctor reporting, and architecture tests.
Providers own operation selection and security defaults.

GH Broker adds a managed `request-all-agent-operations` preset that:

- covers every current agent-facing catalog operation deterministically;
- causes operations to require approval rather than granting standing mutation
  authority;
- preserves exact-operation requirements for critical and explicit-only
  operations;
- keeps direct ref mutation and other GitHub-native workflow bypasses explicit;
- supports durable exact deny overrides;
- binds repository targets and selector attributes before approval;
- relies on GitHub rulesets as the final upstream enforcement layer; and
- makes missing or unverifiable default-branch protection fail setup or doctor
  according to the selected production profile.

Setup must never silently broaden an installed policy when the catalog grows.
A newly generated preset is previewed and requires an explicit managed update,
while a clean installation receives the complete current preset.

## Operational Resilience

### Current-format SQLite operations

The shared state package provides exact-format check, backup, restore, and
redacted export through the same `state` command on all brokers. The completed
implementation follows these constraints:

- `state check` runs bounded quick and full integrity checks and reports only
  operational metadata.
- `state backup` creates a transactionally consistent current-format snapshot,
  syncs it and its destination directory, records a checksum and format
  manifest, and never copies a live WAL/database pair independently.
- `state restore` is offline-only, requires the broker state lease to be free,
  accepts only the exact current format and schema, verifies integrity,
  checksum, ownership, mode, and size before atomically replacing state, and
  leaves the existing database untouched on validation failure.
- `state export` emits bounded, deterministic, redacted JSON for grants,
  operations, plans, notification state, and audit references without secrets,
  sealed payloads, credential outputs, raw arguments, or provider tokens.
- Backup and export destinations must be explicit absolute paths and cannot be
  inside the live state directory.
- Doctor reports integrity and capacity status without mutating state.

There are no legacy state importers, schema converters, dual reads, or
automatic startup restores. Existing pre-release state is discarded at the
cutover. Backup and restore support only the resulting current format.

Test disk exhaustion, read-only filesystems, interrupted backup, corrupt pages,
truncated files, checksum mismatch, unsafe ownership, concurrent open attempts,
and restoration into a clean state root. A failed state commit must prevent the
corresponding external side effect.

### Admission control and backpressure

Add one shared admission layer before durable operation creation and approval
notification. Configuration defines conservative bounded defaults and explicit
per-client overrides for:

- submitted requests per time window;
- concurrent non-terminal operations;
- pending approval requests;
- queued and executing provider operations;
- outstanding stream bytes and sealed payloads; and
- notification attempts and unresolved delivery failures.

Authentication, syntax validation, and cheap request-size rejection happen
before admission accounting. Accepted work receives a durable idempotency key;
replays do not consume a second quota. Rejected work returns a stable `429`
error with a bounded `Retry-After` where appropriate and creates no grant,
operation, audit-cardinality explosion, Telegram message, or operator inbox
entry.

Use bounded queues and explicit worker concurrency rather than one goroutine per
request. Reserve capacity for health, cancellation, revocation, and operator
decisions so overload cannot prevent recovery. Metrics labels and in-memory
accounting are bounded by configured client identities, never caller-supplied
operation arguments.

Implemented on the production-readiness branch: Agent V1 submissions use one
shared controller backed by SQLite occupancy counts and short-lived in-memory
reservations. HF, GH, and sudo use the same conservative defaults and strict
shared configuration format with exact per-client overrides; authenticated
idempotent replays bypass accounting, concurrent submissions cannot race past
capacity, and refusals return stable `429` codes with `Retry-After`. Cancellation,
operator decisions, health, and readiness bypass submission admission. Explicit
overload recovery-capacity drills remain.

Stream and sealed-payload stores now enforce both global and per-client
file/byte caps after expiry cleanup. Their idempotency lookup runs before
quota accounting, so exact upload replays remain available at capacity. The
remaining admission work is configuration overrides and explicit recovery
capacity tests.

The shared grant store also caps pending approvals per client and globally, so
direct grant APIs cannot bypass Agent V1 admission. Exact grant replays are
resolved before capacity checks. SQLite notification delivery stops automatic
retry after five ambiguous attempts while the durable request remains available
to the operator inbox. Direct Slophammer analysis for the shared grants package
now passes at the repository maximum score of 8.

### Credential replacement and revocation

Define one shared credential lifecycle for broker client secrets, operator
secrets, HF tokens, GitHub App keys and OAuth credentials, Telegram bot tokens,
and sealed credential-store encryption material where present.

- Setup stages and validates replacement material in protected files before
  changing service configuration.
- Activation performs one exact cutover and readiness check; it does not retain
  an old credential reader or an indefinite overlap window.
- Old credentials fail immediately after successful activation and provider
  credentials are revoked upstream when the provider supports revocation.
- A failed activation keeps the previous installed configuration active without
  partially exposing replacement material.
- Generated local client configuration is replaced atomically and never prints
  either credential.
- Doctor reports credential source, age, expiry, and rotation need without
  reading values into reports.
- Audit records actor, credential class, old/new non-secret identifiers,
  outcome, and time.

A short controlled restart is acceptable for this fresh-state architecture;
dual-secret compatibility is not. Test interrupted staging, failed readiness,
stale clients, immediate old-secret rejection, provider revocation failure, and
Telegram replacement.

Implemented on the production-readiness branch: the shared systemd and launchd
installers snapshot the bounded managed-file set before an exact replacement.
Write, activation, and readiness failures restore the previous credentials and
service definition, then reactivate the previous installation when one
existed. Successful readiness retires obsolete files, and rollback copies are
cleared before setup exits. Broker and client readers still accept only one
current secret. Native setup now audits created, rotated, and retired material
with non-secret identifiers. Doctor reports source, installed age, expiry
state, rotation need, and revocation mode without reading protected values.
GitHub user OAuth and discarded installation credentials use supported
upstream revocation APIs with audited failures; static GitHub App material,
Hugging Face user tokens, and Telegram bot tokens expose explicit manual
upstream retirement because no suitably scoped supported API is available to
the broker.

### Observability contract

Audit is evidence of security decisions, not a substitute for operational
telemetry. Add provider-neutral structured diagnostics with a single ownership
boundary:

- liveness means the process event loop is responsive;
- readiness means configuration, listeners, state lease, database, workers,
  and required local privilege boundaries are usable;
- upstream and notification outages appear as explicit degraded dependencies
  without leaking credentials or making an unsafe broker ready;
- metrics cover admitted/rejected work, queue depth, pending approvals,
  decision and execution latency, retries, upstream failures/rate limits,
  notification failures, database health, and worker saturation; and
- logs carry stable event names, correlation IDs, provider, operation class,
  and redacted error category.

Metrics are exposed only through an explicitly configured operator or platform
endpoint. Labels must not include reasons, repository names, target users,
paths, command arguments, URLs, tokens, free-form upstream errors, or unbounded
caller input. Logging, metrics, audit, and API error redaction share tested
helpers rather than separate deny lists.

Implemented on the production-readiness branch: each control plane creates an
isolated Prometheus registry and exposes it only through the authenticated
operator listener. Shared admission, operation lifecycle, decision, and
notification code records bounded outcome counters and execution latency. The
only identity label is the setup-controlled broker name; all other labels use
closed enums and unknown values collapse to `other`. Scrapes also report a
bounded database-health probe and durable queue-depth gauges for approvals,
operations, execution, and notification delivery. The shared runtime also
reports last-observed provider and notification health, dependency outcomes by
closed error category, notification retries, active workers, and configured
worker capacity. The same boundary emits JSON diagnostics with stable events,
opaque correlation IDs, provider, catalog risk class, closed outcome, and
closed error category; it never logs targets, reasons, operation names, URLs,
commands, credentials, or raw errors.

### Failure drills

Add deterministic automated drills for:

- disk full, read-only state, corrupt SQLite, and failed synchronization;
- backward and forward wall-clock movement around request, approval, expiry,
  reservation, and notification leases;
- Telegram outage, duplicate callbacks, delayed delivery, and recovery;
- provider timeout, connection reset, `429`, `5xx`, malformed response, and
  ambiguous mutation completion;
- termination before plan commit, after reservation, during provider execution,
  during reconciliation, and during audit/outbox completion;
- listener loss, socket permission change, service-manager restart, and stale
  inherited descriptors;
- interrupted setup, credential replacement, and partial file installation;
  and
- overload while cancellation, revocation, health, and operator decisions must
  remain available.

Every drill asserts the final durable state, external-side-effect count,
notification state, audit sequence, readiness result, and restart behavior. No
failure may broaden policy, switch transport, regenerate credentials silently,
discard an ambiguous operation, or report success without durable evidence.

Implemented on the production-readiness branch: the maintained drill matrix is
documented in `docs/FAILURE_DRILLS.md`. Shared tests cover SQLite corruption and
failed writes, clock movement, Telegram retry and duplicate callbacks,
ambiguous provider completion, crash recovery, listener/setup rollback,
live-context shutdown, and overload while cancellation and approval remain
available. Clean-host disk exhaustion and service-manager restart drills remain
part of final CI qualification.

## Quality Debt Elimination

CRAP non-regression baselines were acceptable during the exhaustive provider
cutovers, but they are not the final architecture. Current baselines contain
103 HF exceptions with scores up to `48.0` and 68 GH exceptions with scores up
to `132.7`.

Eliminate every exception before the production release:

1. Start with security and orchestration functions, then MCP/CLI dispatch,
   provider HTTP execution, generated-surface validation, and setup.
2. Reduce real complexity by separating parsing, validation, authorization,
   execution, and rendering responsibilities. Do not split functions merely to
   manipulate the metric.
3. Add focused branch and failure-path coverage where the structure is already
   appropriate.
4. Preserve bounded I/O, cancellation, credential redaction, immutable plans,
   and atomic state transitions while refactoring.
5. Keep each cleanup commit behavior-preserving and green against provider
   conformance tests.
6. Reject new exceptions and lower the exact baseline monotonically after every
   coherent commit.
7. Run each broker's complete local Slophammer configuration in CI. The sudo
   configuration's `max_score: 8` gate must execute rather than being bypassed
   by a root exclusion and a DRY-only broker invocation.
8. Remove the HF and GH CRAP baseline files, wrapper scripts, and root
   exclusions for broker code when the normal `max_score: 8` gate passes
   directly for the entire repository, including sudo.

Mutation tooling remains checked in, disabled, and non-blocking. It is not a
completion gate unless separately requested.

## Installation And Supply Chain

### Immutable installer

Thin broker installer wrappers currently fetch the shared installer from
mutable `main`. Replace that with a release-owned bootstrap:

- selecting a release version also selects the exact installer revision;
- the default latest lookup resolves once to an immutable tag and commit;
- checksums and archives are fetched from the same immutable release;
- the installer verifies the expected repository, tag, asset name, and digest;
- GitHub artifact provenance is verified with a pinned verifier and expected
  workflow identity before installation;
- offline installation accepts an explicitly supplied verified bundle; and
- setup remains separate from binary installation.

The installer never invokes `sudo` automatically. Its unprivileged default is
an explicit user-writable destination such as `$HOME/.local/bin`. A production
or system-wide install requires an explicit absolute destination and an
operator-initiated privileged invocation; if the selected destination is not
writable, installation fails with a concrete rerun command rather than
escalating. This also prevents a piped bootstrap from unexpectedly consuming a
privilege prompt.

Release documentation must distinguish convenience installation from a pinned,
reproducible production installation.

### Reproducible release workflows

Pin third-party GitHub Actions by full commit SHA with update automation. Pin
Go, Node, pnpm, npm, generators, linters, vulnerability scanners, and release
tools. Remove `npm@latest` from the release path. Use the same supported Node
major in CI, package tests, and release unless a declared matrix proves more
than one major. Add package `engines` metadata matching that matrix.

Implemented on the production-readiness branch: every workflow action is pinned
to a full commit SHA, Go and pnpm remain exact, CI and npm publication use exact
Node 24.18.0, package engines require that Node 24 line, and the release uses
Node's bundled npm 11.16.0 instead of installing `npm@latest`. The architecture
gate rejects mutable action refs, major-only Node selectors, and `npm@latest`.
The canonical installer now defaults to `$HOME/.local/bin`, never invokes
`sudo`, and fails with explicit privileged-shell guidance for an unwritable
operator-selected destination. Broker wrappers no longer fetch `main`: they
resolve the selected component release tag through GitHub's ref API, peel an
annotated tag when necessary, require an exact 40-character commit SHA, and
fetch the canonical installer from that commit. The installer uses a pinned,
checksum-verified GitHub CLI to validate archive and checksum attestations
against the BrokerKit release workflow and selected tag. The release workflow
then re-downloads the published assets through the same verify-only path, so
publication is not successful until digest, provenance, archive shape, and
source identity all pass.

Build release artifacts from a clean checkout, verify generated artifacts and
module integrity, produce SBOMs and provenance, smoke-test the packed artifacts,
and verify the published artifact after release.

## Upstream Capability Maintenance

The checked-in GitHub API and GraphQL snapshots remain immutable review inputs,
but exhaustive coverage needs a durable drift process.

Add a scheduled, non-mutating upstream monitor that:

- fetches official GitHub REST, GraphQL, permission, and API-version metadata;
- verifies source identity and records digests and retrieval time;
- compares it with the pinned snapshots;
- classifies added, removed, and changed operations, schemas, permissions,
  authentication modes, and deprecations;
- opens or updates one actionable maintenance issue when drift exists; and
- never regenerates or merges capability changes automatically.

Refreshing snapshots remains a reviewed change that regenerates all catalogs,
bindings, schemas, CLI/MCP surfaces, documentation, and conformance fixtures in
one commit series. CI continues to reject generated drift.

## CI And Test Matrix

Required CI covers:

- Linux and macOS builds, unit tests, race tests where supported, setup dry-runs,
  and native service-manager fixtures;
- protocol and generated-artifact checks;
- Agent V1 and Operator V1 conformance for HF, GH, and sudo;
- endpoint conformance over Unix, activation, inherited descriptor, loopback
  TCP, and explicit ingress;
- unauthorized local-user and operator-separation tests;
- malformed configuration, unsafe path, plaintext origin, wildcard bind,
  symlink, stale socket, and descriptor-confusion tests;
- state check, current-format backup/restore, redacted export, corruption,
  disk-full, and read-only-filesystem tests;
- per-client and global admission limits, bounded queues, idempotent replay
  accounting, operator capacity reservation, and notification-spam tests;
- atomic credential replacement and immediate old-credential rejection for
  every broker credential class;
- liveness, readiness, degraded dependency, bounded metrics-cardinality, and
  cross-surface redaction tests;
- deterministic crash, clock movement, notification outage, upstream failure,
  listener loss, partial setup, and overload drills;
- HF and GH Git clone, fetch, push, LFS, streaming, and cancellation;
- exhaustive HF and GH operation construction plus representative live sandbox
  tests behind explicit credentials;
- GitHub default-branch and ruleset behavior for Git and direct ref operations;
- OpenClaw direct and delegated-web flows in the supported Node/browser matrix;
- clean packed installation and immutable installer verification;
- coverage at or above the repository threshold with direct CRAP `max_score: 8`;
- `go vet`, `golangci-lint`, Slophammer DRY/structural/copy gates,
  `govulncheck`, secret scanning, dependency licenses, and reproducible builds;
  and
- clean-host end-to-end installation on current Linux and macOS runners.

CI must not depend on existing host services, credentials, fixed ports,
working-directory state, mutable tool versions, or unbounded external calls.

## Documentation And Repository Hygiene

Keep Active Work limited to unfinished plans. Move implemented plans to
implementation records or date-stamped archive material. When this cutover
ships, replace plan language in maintained docs with the final contract and
date-stamp this plan as an implementation record.

Remove:

- documentation for fixed ports, bind/port pairs, relative production paths,
  personal identities, mutable installer revisions, and Linux-only claims
  presented as cross-platform support;
- stale examples that use permissive HTTP or broad policy without explaining
  approval and ruleset enforcement;
- obsolete branches and worktree metadata after verifying they contain no
  unique changes;
- completed-plan links from Active Work; and
- temporary architecture allowlists, CRAP wrappers, and quality exceptions
  after their code is removed.

Add architecture gates that reject personal identity defaults, fixed listener
ports, provider-local endpoint parsing, remote plaintext origins, relative
production state defaults, provider-local lifecycle orchestration, mutable
installer revisions, and unpinned release tools.

## Implementation Sequence

Use one coordinated cutover branch with conventional commits for coherent green
slices. The order is dependency-driven, not a permission to stop after an early
slice.

### 1. Lock the inventory and gates

- Add failing architecture tests for every prohibited default and duplicate.
- Record the exact endpoint, identity, config, lifecycle, quality, platform,
  installer, workflow, and documentation inventory.
- Expand clean-host fixtures before changing runtime behavior.

### 2. Cut over endpoints and secure configuration

- Implement shared endpoint types, listeners, dialers, and strict origin rules.
- Implement strict typed configuration and explicit development mode.
- Require absolute production paths and explicit identities.
- Replace the 16-byte and 24-byte authentication defaults with one shared
  32-byte runtime and setup requirement.
- Make audit recorders mandatory constructor dependencies and delete production
  discard fallbacks.
- Add shared HTTP server/client profiles.
- Migrate every broker and delete old fields, defaults, and transports.

### 3. Complete native deployment support

- Add systemd socket activation and update Linux setup.
- Add launchd activation and complete macOS setup.
- Add container, Kubernetes, ingress, and generated client fixtures.
- Prove simultaneous multi-broker installation without collisions.

### 4. Finish shared runtime ownership

- Move GH and sudo Agent lifecycle orchestration into shared packages.
- Put Telegram pollers, notification sweepers, and all other background workers
  under the owned lifecycle context and wait for them before closing state.
- Delete provider-local copies and the temporary architecture allowlist.
- Run all provider and OpenClaw conformance suites.

### 5. Complete policy-preset parity

- Implement the provider-neutral preset framework.
- Migrate HF without a compatibility path.
- Add the GH request-all managed preset and ruleset/default-branch checks.
- Delete provider-local preset lifecycle duplication.

### 6. Complete operational resilience

- Add current-format state check, backup, restore, and redacted export.
- Add shared admission control, bounded queues, and recovery capacity.
- Add atomic credential replacement and revocation for every credential class.
- Add the shared liveness, readiness, metrics, logging, and redaction contract.
- Run all deterministic failure drills and fix every non-fail-closed outcome.

### 7. Eliminate quality baselines

- Refactor every HF and GH CRAP exception through small green commits.
- Add missing failure-path tests.
- Enforce sudo's complete local Slophammer configuration in CI immediately.
- Remove baseline files, wrapper scripts, and broker exclusions once direct
  root and broker-local gates pass.

### 8. Harden installation and release

- Make installer selection and verification immutable.
- Remove implicit `sudo`; require a writable user destination or an explicit
  operator-initiated privileged installation.
- Pin workflow actions and tools.
- Align Node and Go matrices and verify release artifacts after publication.

### 9. Add upstream drift operations

- Add the scheduled non-mutating GitHub metadata monitor.
- Document and test the reviewed snapshot-refresh workflow.

### 10. Clean documentation and local metadata

- Update maintained contracts and examples to the final architecture.
- Move completed plans out of Active Work.
- Remove verified stale worktrees, branches, allowlists, and generated leftovers.

### 11. End-to-end release qualification

- Install all brokers from packed immutable artifacts on clean Linux and macOS
  hosts.
- Configure neutral agent and operator identities.
- Exercise Agent V1, Operator V1, Telegram, OpenClaw direct/delegated web, HF
  operations and Git/LFS, GH operations and Git, and sudo exact commands.
- Verify unauthorized access, expiry, cancellation, restart recovery, audit,
  rulesets, and secret isolation.
- Publish only after all required CI and release-verification checks are green.

## Acceptance Criteria

The cutover is complete only when:

1. No production code, setup path, image, manifest, or maintained example
   assigns a broker TCP port implicitly.
2. No runtime or setup default contains `bob`, `onur`, or another real-person
   identity.
3. Remote plaintext HTTP is rejected consistently before credentials are read
   or requests are sent.
4. Every present malformed setting aborts startup with a redacted actionable
   error.
5. Production startup requires explicit endpoints, identities, and absolute
   trusted paths.
6. All HTTP traffic uses a shared bounded profile appropriate to its streaming
   behavior.
7. Linux systemd and macOS launchd setup pass clean-host end-to-end tests.
8. HF, GH, and sudo share endpoint, lifecycle, policy-preset, setup, doctor,
   and client infrastructure at the intended ownership boundaries.
9. GH has a generated managed preset covering every agent-facing operation
   without standing broad mutation authority.
10. GitHub ruleset/default-branch enforcement is tested for both Git transport
    and generated direct-ref operations.
11. State check, current-format backup/restore, and bounded redacted export work
    across Linux and macOS, and invalid backups never modify live state.
12. Admission limits bound client, worker, state, stream, approval, and
    notification load while preserving cancellation, revocation, health, and
    operator decisions.
13. Every credential class has a tested atomic replacement path and old
    credentials fail immediately after successful activation.
14. Liveness, readiness, degraded dependencies, structured logs, and bounded
    metrics are secret-safe and operationally distinct from audit evidence.
15. Storage, clock, notification, upstream, process, listener, setup, rotation,
    and overload drills produce deterministic fail-closed outcomes.
16. Direct Slophammer CRAP analysis passes at `max_score: 8` with no baseline
    exceptions or wrapper acceptance logic.
17. Installers verify immutable release assets and provenance, and release
    workflows contain no mutable action or tool selection.
18. Scheduled GitHub drift detection reports upstream changes without mutating
    generated artifacts.
19. Linux, macOS, OpenClaw, provider conformance, race, coverage, lint,
    vulnerability, secret, license, architecture, and reproducibility gates are
    green.
20. Active documentation describes only the final supported architecture and
    the repository contains no obsolete worktree metadata or completed work
    mislabeled as active.
21. Client and operator authentication, secret files, setup, and doctor reject
    every secret shorter than the shared 32-byte minimum across HF, GH, and
    sudo.
22. A production broker cannot start without an explicit audit recorder, no
    production path substitutes a discard sink, and audit-export failures are
    visible without misreporting committed decisions.
23. CI executes sudo's complete Slophammer configuration and direct CRAP limit;
    no root exclusion or DRY-only invocation can bypass that gate.
24. The installer never invokes `sudo` or another privilege escalator
    implicitly, and unwritable destinations fail with explicit remediation.
25. Server shutdown cancels and joins every poller, notification worker,
    sweeper, and operation worker before closing SQLite or another shared
    store, even when the original start context is still live.
