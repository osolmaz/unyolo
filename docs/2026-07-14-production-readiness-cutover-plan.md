# Production-Readiness Cutover Plan

Date: 2026-07-14

Status: ready to implement

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
- atomic install, bootstrap, restart, readiness, and rollback behavior;
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

HF already uses the shared `operationruntime` contract. GH and sudo retain
provider-local orchestration behind a temporary architecture-check allowlist.
Move their remaining lifecycle mechanics into shared packages:

- submit and idempotent replay;
- policy classification and grant binding;
- immutable plan creation and validation;
- execution reservation and use budgets;
- worker start, recovery, cancellation, and terminal transitions;
- partial-result reconciliation;
- notification and operator-state transitions; and
- audit event sequencing.

Providers retain only target/argument decoding, provider preconditions,
credential selection, execution, reconciliation, and presentation. Delete the
temporary allowlist and provider-local lifecycle implementations in the same
slice.

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
7. Remove the HF and GH CRAP baseline files and wrapper scripts when the normal
   `max_score: 8` gate passes directly for the entire repository.

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

Release documentation must distinguish convenience installation from a pinned,
reproducible production installation.

### Reproducible release workflows

Pin third-party GitHub Actions by full commit SHA with update automation. Pin
Go, Node, pnpm, npm, generators, linters, vulnerability scanners, and release
tools. Remove `npm@latest` from the release path. Use the same supported Node
major in CI, package tests, and release unless a declared matrix proves more
than one major. Add package `engines` metadata matching that matrix.

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
- Add shared HTTP server/client profiles.
- Migrate every broker and delete old fields, defaults, and transports.

### 3. Complete native deployment support

- Add systemd socket activation and update Linux setup.
- Add launchd activation and complete macOS setup.
- Add container, Kubernetes, ingress, and generated client fixtures.
- Prove simultaneous multi-broker installation without collisions.

### 4. Finish shared runtime ownership

- Move GH and sudo Agent lifecycle orchestration into shared packages.
- Delete provider-local copies and the temporary architecture allowlist.
- Run all provider and OpenClaw conformance suites.

### 5. Complete policy-preset parity

- Implement the provider-neutral preset framework.
- Migrate HF without a compatibility path.
- Add the GH request-all managed preset and ruleset/default-branch checks.
- Delete provider-local preset lifecycle duplication.

### 6. Eliminate quality baselines

- Refactor every HF and GH CRAP exception through small green commits.
- Add missing failure-path tests.
- Remove baseline files and wrapper scripts once direct gates pass.

### 7. Harden installation and release

- Make installer selection and verification immutable.
- Pin workflow actions and tools.
- Align Node and Go matrices and verify release artifacts after publication.

### 8. Add upstream drift operations

- Add the scheduled non-mutating GitHub metadata monitor.
- Document and test the reviewed snapshot-refresh workflow.

### 9. Clean documentation and local metadata

- Update maintained contracts and examples to the final architecture.
- Move completed plans out of Active Work.
- Remove verified stale worktrees, branches, allowlists, and generated leftovers.

### 10. End-to-end release qualification

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
11. Direct Slophammer CRAP analysis passes at `max_score: 8` with no baseline
    exceptions or wrapper acceptance logic.
12. Installers verify immutable release assets and provenance, and release
    workflows contain no mutable action or tool selection.
13. Scheduled GitHub drift detection reports upstream changes without mutating
    generated artifacts.
14. Linux, macOS, OpenClaw, provider conformance, race, coverage, lint,
    vulnerability, secret, license, architecture, and reproducibility gates are
    green.
15. Active documentation describes only the final supported architecture and
    the repository contains no obsolete worktree metadata or completed work
    mislabeled as active.
