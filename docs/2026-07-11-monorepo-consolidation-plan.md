# BrokerKit Monorepo Consolidation Plan

Date: 2026-07-11

Status: implementation, coordinated cutover, and installed-system verification
complete; final review, source-repository archival, and publication pending

Target repository: `github.com/osolmaz/brokerkit`

Source repositories:

- `github.com/osolmaz/brokerkit` at `43e1a0b`
- `github.com/osolmaz/hf-broker` at `2f3844b`
- `github.com/osolmaz/gh-broker` at `7b7f5f1`
- `sudo-broker`, implemented as a new component rather than imported
- `openclaw-brokerkit`, implemented as a new component rather than created as
  a fourth repository

This document plans the consolidation. It does not authorize archiving source
repositories, changing published module paths, releasing artifacts, or moving
production state by itself.

## Decision

Consolidate the BrokerKit protocol/runtime, Hugging Face broker, GitHub broker,
future sudo broker, and OpenClaw plugin into the existing `brokerkit`
repository. Keep MLClaw and upstream OpenClaw outside the monorepo.

The monorepo is one source and integration boundary, not one runtime process,
one privilege boundary, or one release train. Each broker remains a separate
executable with its own credentials, policy, state, deployment, and audit
trail. The OpenClaw plugin remains an unprivileged trusted-host integration and
never links provider executors into the Gateway.

The target boundary is:

```text
brokerkit repository
  protocol and shared Go runtime
       |           |           |
       v           v           v
  hf-broker    gh-broker   sudo-broker       separate processes
       \           |           /
        \          |          /
         BrokerKit operator V1
                   |
                   v
          openclaw-brokerkit                  unprivileged plugin
                   |
                   v
       Gateway UI and existing channels
```

## Why Consolidate Now

All current Go repositories are at `v0.1.0`, already depend on the same
BrokerKit runtime, and are about to change together for the stable operator V1
contract. Keeping them separate would require coordinated pull requests,
temporary replace directives or pre-releases, duplicated fixtures, and
cross-repository coordination for changes that should be atomic.

The monorepo provides:

- one review that changes a protocol, all affected brokers, generated bindings,
  and conformance tests together;
- one source of truth for schemas, examples, security invariants, and test
  fixtures;
- direct cross-broker integration tests without publishing intermediate Go
  modules;
- a natural home for the OpenClaw plugin without coupling it to MLClaw;
- preserved provider ownership through directories and dependency rules; and
- independent releases from a shared, tested commit.

The monorepo must not become a reason to share provider operations, credentials,
execution plans, or privileged runtime state.

## Scope

### Included

- BrokerKit's provider-neutral Go packages and operator V1 artifacts.
- The complete `hf-broker` source history and deployable binary.
- The complete `gh-broker` source history and deployable binary.
- A new `sudo-broker` implementation built on BrokerKit from its first commit.
- A new OpenClaw plugin that aggregates conforming brokers through the existing
  public plugin UI, command, service, HTTP-route, and outbound-channel APIs.
- Shared conformance, integration, generation, CI, release, and
  security tooling.
- Existing broker documentation, release notes, and consolidation provenance.

### Excluded

- MLClaw code, Hugging Face Space deployment logic, and MLClaw state.
- Upstream OpenClaw source or contributions; OpenClaw is only a pinned package
  dependency and public API integration-test target.
- Provider credentials, operator secrets, client secrets, production policy,
  production grant state, audit logs, or copied configuration.
- A universal agent-facing provider API.
- In-process loading of brokers by the OpenClaw plugin.
- A single combined broker daemon or shared credential store.
- An npm organization or placeholder provider packages.

## Target Repository Layout

```text
brokerkit/
  AGENTS.md
  README.md
  go.mod
  go.sum
  package.json                  # private workspace metadata only
  pnpm-lock.yaml
  pnpm-workspace.yaml

  approval/                     # existing provider-neutral Go packages
  audit/
  auth/
  conformance/
  controlplane/
  grants/
  operatorapi/
  operatorclient/
  policy/
  ...

  protocol/
    openapi/
      operator-v1.yaml         # canonical HTTP/SSE contract
    schema/
      *.schema.json
    examples/
    fixtures/
    README.md

  brokers/
    huggingface/
      cmd/hf-broker/
      internal/
      docs/
      scope.example.json
    github/
      cmd/gh-broker/
      internal/
      docs/
      scope.example.json
    sudo/
      cmd/sudo-broker/
      internal/
      docs/
      catalog.example.json

  plugins/
    openclaw/
      package.json              # publishes openclaw-brokerkit
      openclaw.plugin.json
      src/
      test/
      ui/

  integration/
    conformance/
    fixtures/
    openclaw/
    scripts/

  docs/
    adr/
    cutover/
    security/

  .github/
    workflows/
```

The existing provider-neutral Go packages stay at their current import paths
under `github.com/osolmaz/brokerkit`. Moving them merely to make the tree look
more symmetrical would create churn without improving the boundary.

Provider executables use the root Go module after consolidation. Their internal
packages move under:

- `github.com/osolmaz/brokerkit/brokers/huggingface/internal/...`
- `github.com/osolmaz/brokerkit/brokers/github/internal/...`
- `github.com/osolmaz/brokerkit/brokers/sudo/internal/...`

No public Go API is promised from provider directories. Consumers integrate
through the BrokerKit wire protocol, not by importing a broker implementation.

The root JavaScript workspace is private. Initially it contains only the
OpenClaw plugin and schema-generation tooling. Do not publish separate
`brokerkit`, `@brokerkit/protocol`, or provider adapter npm packages until an
independent consumer proves that they are useful.

## Ownership And Dependency Rules

### Shared root packages may

- define provider-neutral authentication, policy, grant, decision, event,
  presentation, storage, audit, and operator-protocol primitives;
- expose small interfaces implemented by provider brokers;
- own canonical schemas and conformance fixtures; and
- depend only on provider-neutral libraries.

### Provider directories may

- import shared root packages;
- own provider credentials, operation vocabularies, classifiers, canonical
  plans, presenters, executors, upstream retries, and provider audit fields;
- share code with another provider only after that code has a provider-neutral
  contract and at least two real consumers; and
- produce separate binaries and release archives.

### The OpenClaw plugin may

- consume the versioned operator protocol and generated TypeScript bindings;
- register configured broker endpoints and SecretRefs;
- persist cursors, opaque handles, generic subscriptions, and delivery
  bookkeeping in plugin-owned SQLite under the supplied service state path;
- render a compact Approvals tab through a public Control UI descriptor;
- register authenticated `/brokerkit` commands; and
- use generic public outbound adapters for any channel supporting text.

It must not import Go broker code, hold upstream provider credentials, accept a
browser-supplied endpoint or operator secret, duplicate channel-specific
delivery code, access OpenClaw private state/approval APIs, or treat plugin
state as broker authority.

### Enforced dependency direction

```text
protocol artifacts -> generated bindings
shared Go runtime  -> provider-neutral only
provider brokers   -> shared Go runtime
OpenClaw plugin    -> protocol bindings and OpenClaw SDK
MLClaw             -> released artifacts/configuration only
```

Add an automated architecture check that fails if shared root packages import
anything under `brokers/`, if one provider imports another, or if plugin code
contains provider execution logic. Directory ownership should be documented in
`CODEOWNERS` if more maintainers join; it is not a substitute for these checks.

## Runtime And Security Boundaries

Consolidation must preserve separate processes:

| Component | Credential/authority | Network boundary | Must never contain |
| --- | --- | --- | --- |
| `hf-broker` | Hugging Face token | Its own listener and state | GitHub or sudo credentials |
| `gh-broker` | GitHub App/token | Its own listener and state | HF or sudo credentials |
| `sudo-broker` | Narrow local privilege transition | Prefer local socket or tightly bound listener | Provider/cloud credentials |
| OpenClaw plugin | Broker operator SecretRefs | Gateway plugin boundary | Upstream credentials or executable plans |

`sudo-broker` must not make BrokerKit, OpenClaw, or any other broker privileged.
It must execute canonical structured plans, not arbitrary shell strings. The
initial safe command path uses exact executable plus argument structure,
bounded environment and working directory, short expiry, and one-shot grants.
Interactive shells, if ever supported, are explicitly identity grants and need
a separate threat model and operator presentation.

Repository-wide tests and development commands must use fake credentials.
Secrets are never copied during consolidation. Add secret scanning before the
first history import and scan the imported histories as well as the resulting
tree before pushing.

## Git History Preservation

History must be retained without squashing. The import procedure is:

1. Freeze each source repository at a recorded commit and ensure its required
   checks pass there.
2. Record source commit, source `v0.1.0` tag, release assets, open issues, and
   default-branch protection in a import ledger.
3. Scan each source tree and history for secrets before importing it.
4. Add each source as a temporary remote and fetch its default branch with
   `--no-tags`; all three repositories currently have a conflicting `v0.1.0`
   tag name.
5. Import with a no-squash subtree merge into `brokers/huggingface` and
   `brokers/github`. Equivalent filtered-history merges are acceptable only if
   author, timestamp, parentage, and source commit reachability are verified.
6. Add provenance files containing the source URL, frozen commit, source tag,
   import commit, and verification commands.
7. Verify representative source commits with `git log --follow` and
   `git merge-base --is-ancestor` before restructuring.
8. Remove temporary remotes after verification.

Illustrative commands, to be executed on a dedicated consolidation branch after
fresh backups and dry runs:

```sh
git remote add hf-broker https://github.com/osolmaz/hf-broker.git
git fetch --no-tags hf-broker main
git subtree add --prefix=brokers/huggingface hf-broker main

git remote add gh-broker https://github.com/osolmaz/gh-broker.git
git fetch --no-tags gh-broker main
git subtree add --prefix=brokers/github gh-broker main
```

Do not reuse the ambiguous imported `v0.1.0` tag names. Record them in the
ledger and use component-qualified tags for future executable/plugin releases.
The existing root `v0.1.0` remains the historical BrokerKit library tag.

## Source Repository Cutover

Freeze `hf-broker` and `gh-broker` when the consolidation branch starts. Do
not merge new feature work into the source repositories after the recorded
tips. At the single cutover, publish the complete monorepo release, redirect
issue and development links, disable source workflows, and archive both source
repositories read-only in the same coordinated operation.

Before the cutover:

- migrate or close open issues with explicit destination links;
- update repository descriptions and README headers;
- preserve historical releases and checksums;
- update documentation, installers, automation, and dependency links;
- transfer security advisories privately if any exist;
- confirm historical tagged source and release artifacts remain readable; and
- archive rather than delete the repositories.

Historical module versions such as `github.com/osolmaz/hf-broker@v0.1.0`
remain obtainable from the archived repositories, but they are not supported
by the new system. New code uses monorepo import paths. Canonical executable
names remain `hf-broker`, `gh-broker`, and `sudo-broker`.

## Go Module Cutover

Use dependency-ordered commits on the one cutover branch so history import and
code movement remain independently reviewable without creating an intermediate
supported deployment.

### Import commits

Keep each imported source tree intact, including its nested `go.mod`, tests,
docs, and workflows. Add a temporary root `go.work` only on the consolidation
branch if needed to run all three modules together. Do not publish from this
intermediate layout.

### Convergence commits

- Move broker commands and internal packages into their target directories.
- Merge required dependencies into the root `go.mod` and `go.sum`.
- Rewrite provider-local imports to monorepo paths.
- Delete nested `go.mod` and `go.sum` only after each provider builds and tests
  against the root module.
- Standardize on `go 1.25.0` with the `go1.26.5` toolchain initially, unless a
  verified language feature requires raising the module language version.
- Run `go mod tidy` and verify the result contains no local `replace`
  directives.
- Build exact commands from `./brokers/huggingface/cmd/hf-broker`,
  `./brokers/github/cmd/gh-broker`, and eventually
  `./brokers/sudo/cmd/sudo-broker`.

The root BrokerKit library keeps semantic versions. Because the provider Go
packages are internal implementation details, their binary release versions do
not require nested Go modules.

## Protocol And Generated Artifacts

The stable source of truth is the versioned OpenAPI/JSON Schema material under
`protocol/`, not Go storage structs and not TypeScript UI models.

- Go wire types implement the schema without exposing durable internal state.
- TypeScript bindings used by the OpenClaw plugin are generated from the same
  source.
- Generated outputs are committed only when that makes plugin installation and
  review deterministic; CI regenerates and fails on drift.
- Request/response fixtures are shared across Go and TypeScript tests.
- Provider-specific plans never enter the common schema.
- Unknown response fields are tolerated and dropped; unknown command fields
  are rejected.
- Wire API versions remain independent of repository and artifact versions.

The universal platform plan in
`docs/2026-07-11-universal-broker-platform-plan.md` remains normative for the
operator contract. This plan changes repository topology, not its authority or
security model.

## OpenClaw Plugin Packaging

The plugin lives at `plugins/openclaw` and is independently publishable as
`openclaw-brokerkit`. The name returned npm registry 404 on 2026-07-11; claim it
during the coordinated release and stop rather than silently rename if it is no
longer available. Do not create an npm organization solely for this plugin.

The plugin package includes:

- OpenClaw manifest and minimum-host metadata;
- configuration schema for a list of BrokerKit sources;
- SecretRef declarations for operator credentials;
- broker list/watch/decision client and reconciliation loop;
- a compact Approvals tab registered through the public Control UI descriptor;
- authenticated channel commands and generic outbound-adapter delivery;
- plugin-owned SQLite for cursors, opaque handles, subscriptions, and delivery
  bookkeeping; and
- tests with the BrokerKit fake server and conformance fixtures.

Keep all BrokerKit-specific behavior in this repository. The plugin must run on
an unmodified released OpenClaw package using only public plugin APIs. It does
not use private imports, OpenClaw state tables, the internal approval manager,
or an upstream UI patch. The production UI is the public plugin tab described
in the companion plugin plan.

The plugin is released through npm and/or ClawHub only after its exact package
name, manifest contract, minimum host range, provenance, and install flow
are validated against a pinned OpenClaw version.

## Configuration And State Cutover

This is a clean pre-1.0 break. The monorepo release supports only its new
configuration and V1 state schemas.

- Keep the executable product names `hf-broker`, `gh-broker`, and
  `sudo-broker`; all module, installer, release, and repository URLs switch to
  the monorepo.
- Do not parse old config keys, operator routes, cursors, grants, notification
  records, or provider-plan files.
- Do not add aliases, conversion commands, dual reads, dual writes, or state
  backfills.
- Before cutover, revoke or allow all existing authority to expire, stop the
  old brokers, archive their state/audit directories for forensic retention,
  and initialize fresh V1 state.
- Validate new configuration offline before stopping the old deployment.
- If any readiness or smoke check fails, do not expose the new listeners.
  Repair the complete new deployment and rerun the cutover.
- Never run an old binary against new state or a new binary against old state.

Release archives and installer URLs switch directly to qualified monorepo
artifacts with checksum verification. Documentation gives one clean install
procedure, not an old/new URL matrix.

The OpenClaw plugin stores only cursors, opaque handles, routing coordinates,
and delivery bookkeeping in its own SQLite database. Broker credentials remain
SecretRefs resolved server-side. The browser never receives them.

## CI Design

One required top-level CI workflow provides the authoritative result. It may
fan out into path-aware jobs for speed, but shared/protocol changes always run
every broker and plugin contract test.

### Required jobs

1. **Repository policy**
   - formatting, generated-file drift, dependency direction, secret scanning,
     license/header policy, and clean-tree checks;
2. **Shared Go runtime**
   - `go fmt`, `go vet`, race tests, coverage, lint,
     vulnerability scan, and Slophammer checks;
3. **HF broker**
   - unit/race tests, build, provider security fixtures, installer test, and
     BrokerKit operator conformance;
4. **GH broker**
   - unit/race tests, build, provider security fixtures, installer test, and
     BrokerKit operator conformance;
5. **sudo broker**
   - build/unit tests on supported Unix targets, privilege-boundary tests in an
     isolated runner, command-plan adversarial tests, and conformance;
6. **OpenClaw plugin**
   - pinned package install, formatting, lint, typecheck, unit tests, UI tests,
     manifest validation, and generated-binding drift;
7. **Cross-component integration**
   - start fake or ephemeral brokers, list/watch/decide/revoke through the
     plugin, exercise restart/cursor/idempotency behavior, and prove one failed
     source does not affect another;
8. **Release reproducibility**
   - build all selected artifacts twice where practical, verify checksums and
     SBOM/provenance inputs, and ensure no credential or local path is embedded.

Mutation scripts and configuration remain in the repository, but mutation
testing is disabled and non-blocking for this cutover. CI may retain an opt-in
hook such as `RUN_MUTATION=true`; the default required workflow must skip it.

Use path filters only to skip leaf jobs for unrelated leaf changes. Changes to
root Go packages, `protocol/`, generation, integration fixtures, shared CI, or
release tooling trigger the complete matrix.

## Release Model

Artifacts release independently from the same tested commit:

| Artifact | Tag pattern | Published form |
| --- | --- | --- |
| BrokerKit Go library | `vX.Y.Z` | Go module tag |
| HF broker | `hf-broker/vX.Y.Z` | GitHub release archives/images |
| GH broker | `gh-broker/vX.Y.Z` | GitHub release archives/images |
| sudo broker | `sudo-broker/vX.Y.Z` | GitHub release archives/images |
| OpenClaw plugin | `openclaw-brokerkit/vX.Y.Z` | npm/ClawHub package |

A component tag must point to a commit where the full required matrix is green.
Release workflows dispatch only for the matching qualified tag and build from
fixed paths. Every release includes checksums, source commit, supported
API/host versions, cutover notes, and generated provenance. Privileged or
provider credentials are never available to ordinary build jobs.

Do not force all artifacts to share a version. Maintain a generated artifact
table that identifies the one supported operator wire version and minimum
OpenClaw host for the complete cutover release.

## Documentation Consolidation

- Keep the root README short and user-oriented, with links to each component.
- Retain imported provider docs under their provider directories first; dedupe
  only after provenance is verified.
- Move shared architecture, protocol, security, cutover, and conformance
  documents to root `docs/`.
- Replace contradictory copies with small redirect documents rather than
  silently deleting historical decisions.
- Update root `AGENTS.md` so “keep BrokerKit small” applies to shared packages,
  while provider-specific code is explicitly allowed only under its broker
  directory.
- Merge the strictest relevant repository checks into scoped instructions for
  each provider and the plugin.
- Record topology, dependency direction, runtime isolation, schema ownership,
  and release naming as ADRs before implementation diverges.

## Implementation Order For The Single Cutover

The following are dependency-ordered commits on one branch and one coordinated
release. They are not supported intermediate deployments:

1. approve topology and companion plans; freeze source SHAs; record the import
   ledger, issues, releases, workflows, docs, module paths, and deployments;
2. back up Git refs, run source checks/secret scans, and add destination ADRs,
   ownership rules, CI skeleton, and dependency-direction checks;
3. import HF and GH histories sequentially without squashing and verify
   reachability, blame, file counts, tags, and intact source tests;
4. rehome commands/internal packages, merge the root Go module, normalize the
   toolchain, delete nested modules, and remove duplicated common runtime code;
5. implement the complete V1 protocol/runtime plus HF/GH canonical plans and
   provider conformance;
6. implement the independent plugin against the pinned released OpenClaw
   public API without changing OpenClaw;
7. implement the exact-command sudo broker and isolated privilege tests;
8. build fresh configs/state, run the full Go/TypeScript/browser/channel/live
   matrix, and produce all qualified artifacts from the same green commit;
9. revoke/expire existing authority, stop old deployments, archive old state,
   install and verify the complete new system, then expose listeners; and
10. redirect development/issues and archive HF/GH source repositories.

If any required check fails before listeners are exposed, abort the cutover and
keep the old deployment stopped or isolated while the complete new system is
repaired. Do not deploy a partial monorepo, mix old/new state, or add temporary
bridges.

## Principal Risks And Mitigations

| Risk | Mitigation |
| --- | --- |
| Provider logic leaks into shared runtime | Dependency checks, scoped instructions, provider-neutral conformance fake |
| Monorepo mistaken for one security boundary | Separate binaries, credentials, state, listeners, threat models, and deploy tests |
| Git history or tags lost | No-squash imports, import ledger, ancestry/blame verification, archived sources |
| Root Go module increases coupling | Internal provider packages, protocol boundary for consumers, path-aware releases |
| Shared change breaks every broker | Full matrix on shared/protocol changes and component release gates |
| Plugin becomes a second authority store | Broker-authoritative reconciliation and no independent timeout denial |
| OpenClaw internals copied into plugin | Use only pinned public plugin APIs and stop if the plan cannot be met without a host edit |
| npm naming creates premature structure | One exact unscoped plugin package; no organization or placeholders |
| Sudo privileges spread to other components | Separate process/build/deploy, exact plans, minimal socket access, isolated tests |
| Old deployment leaks into the new system | Fresh V1 state, no parsers/aliases/dual writes, stopped old listeners |
| Consolidation mixes refactor with import | Separate import commits inside the single branch and exact verification gates |

## Acceptance Criteria

Consolidation is complete only when:

- original HF and GH source tips remain reachable in BrokerKit history;
- old `v0.1.0` releases remain downloadable from archived source repositories;
- one root Go module builds and tests BrokerKit, HF, and GH without local
  `replace` directives;
- shared packages contain no Hugging Face, GitHub, or sudo execution branches;
- each broker remains a separate process with separate credentials and state;
- canonical binary names remain while only new configuration/state is loaded;
- common changes run conformance against every broker;
- provider-only changes can release only that provider artifact;
- the OpenClaw plugin is independently installable and contains no
  channel-specific or provider-execution code;
- browser and channel decisions reach the same broker activation validator;
- disabling the plugin does not change broker authority;
- sudo execution cannot be reached from another broker or plugin process;
- release tags, checksums, provenance, supported-version, and cutover
  documentation are generated and verified; and
- source repositories are archived as the final action of the successful
  coordinated cutover.

## Commit Order Inside The Cutover Branch

Keep coherent commits ordered inside the one implementation branch:

1. ADRs, import ledger, monorepo instructions, and import safety checks.
2. No-squash HF history import, unchanged under its prefix.
3. No-squash GH history import, unchanged under its prefix.
4. Root Go module convergence and HF build/test cutover.
5. GH build/test cutover and unified conformance matrix.
6. Qualified component release workflows and clean-install tests.
7. Canonical protocol artifacts and generated TypeScript fixtures.
8. OpenClaw plugin scaffold and fake-broker integration.
9. Broker reconciliation, authenticated channel commands/delivery, and compact
   Approvals tab.
10. Sudo threat model and structured-command MVP.

The complete branch is reviewed and cut over as one program. Source-repository
archival happens only after every commit's combined result passes the final
gate.

## Explicit Decisions

- Use the existing `brokerkit` repository as the monorepo.
- Include HF, GH, sudo, and the OpenClaw plugin; exclude MLClaw and OpenClaw.
- Preserve imported histories without squashing.
- Converge Go code into one root module after intact imports.
- Keep provider packages internal and provider executors out of shared code.
- Keep every broker as a separate deployed security boundary.
- Use one private JavaScript workspace and one independently released plugin.
- Use the unscoped name `openclaw-brokerkit`; do not create an
  npm organization merely for package symmetry.
- Use component-qualified tags for binaries/plugins and the root `vX.Y.Z` tags
  for the BrokerKit Go module.
- Retain and later archive source repositories; never delete them.
- Preserve canonical executable product names, but initialize only fresh V1
  state.
- Require one fresh-state coordinated cutover; no partial or mixed deployment
  is supported.
