# BrokerKit Monorepo Consolidation Plan

Date: 2026-07-11

Status: proposed

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
temporary replace directives or pre-releases, duplicated fixtures, and a
compatibility matrix for changes that should be atomic.

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
- A new OpenClaw plugin that aggregates conforming brokers and uses OpenClaw's
  existing approval and channel infrastructure.
- Shared conformance, compatibility, integration, generation, CI, release, and
  security tooling.
- Existing broker documentation, release notes, and migration records.

### Excluded

- MLClaw code, Hugging Face Space deployment logic, and MLClaw state.
- Upstream OpenClaw source, except for ordinary development dependencies and
  narrowly scoped upstream SDK contributions.
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
    compatibility/
    fixtures/
    openclaw/
    scripts/

  docs/
    adr/
    migration/
    security/

  .github/
    workflows/
```

The existing provider-neutral Go packages stay at their current import paths
under `github.com/osolmaz/brokerkit`. Moving them merely to make the tree look
more symmetrical would create churn without improving the boundary.

Provider executables use the root Go module after migration. Their internal
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
- persist safe source mappings, event cursors, and delivery reconciliation
  state in OpenClaw's supported plugin storage;
- project broker requests into OpenClaw's provider-neutral approval system;
- render the compact Gateway approvals UI; and
- use OpenClaw channel capabilities for Discord, Telegram, Slack, Matrix, and
  future channels.

It must not import Go broker code, hold upstream provider credentials, accept a
browser-supplied endpoint or operator secret, duplicate channel-specific
delivery code, or treat OpenClaw approval state as broker authority.

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
   default-branch protection in a migration ledger.
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

Illustrative commands, to be executed on a dedicated migration branch after
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

## Source Repository Retirement

Do not archive `hf-broker` or `gh-broker` immediately after import. Use a
two-stage retirement:

1. During a validation window, make the monorepo authoritative, disable source
   repo release workflows, and add prominent moved-development notices while
   retaining issue access and existing release downloads.
2. After the first successful monorepo release and rollback exercise, archive
   the source repositories read-only.

Before archiving:

- migrate or close open issues with explicit destination links;
- update repository descriptions and README headers;
- preserve historical releases and checksums;
- update documentation, installers, automation, and dependency links;
- transfer security advisories privately if any exist;
- confirm Go consumers can still fetch old tagged module versions; and
- protect or archive rather than delete the repositories.

Old module versions such as `github.com/osolmaz/hf-broker@v0.1.0` remain
available from the archived repositories. New code uses monorepo import paths,
but binary and configuration names remain stable.

## Go Module Migration

Use a staged transition so history import and code movement are independently
reviewable.

### Import stage

Keep each imported source tree intact, including its nested `go.mod`, tests,
docs, and workflows. Add a temporary root `go.work` only on the migration
branch if needed to run all three modules together. Do not publish from this
intermediate layout.

### Convergence stage

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

The plugin lives at `plugins/openclaw` and is independently publishable. The
working package name is `openclaw-brokerkit`, subject to a final live registry
and OpenClaw ecosystem check immediately before first publication. Do not
create an npm organization solely for this plugin.

The plugin package includes:

- OpenClaw manifest and compatibility metadata;
- configuration schema for a list of BrokerKit sources;
- SecretRef declarations for operator credentials;
- broker list/watch/decision client and reconciliation loop;
- the compact settings-triggered approval interface;
- portable approval projections for existing OpenClaw channel delivery; and
- tests with the BrokerKit fake server and conformance fixtures.

If OpenClaw still lacks a provider-neutral background approval SDK method, make
one narrow upstream contribution such as `api.runtime.approvals.request(...)`
that feeds its existing approval manager. Keep all BrokerKit-specific behavior
in this repository. The plugin may use an existing tab surface until a generic
settings-popover host seam exists, but the target UX remains a compact element
tied to Settings rather than a permanent full-height side panel.

The plugin is released through npm and/or ClawHub only after its exact package
name, manifest contract, host compatibility range, provenance, and install flow
are validated against a pinned OpenClaw version.

## Configuration And State Compatibility

Consolidation must not force deployed users to rename binaries, services,
configuration directories, environment variables, or state directories.

Preserve:

- binary names `hf-broker`, `gh-broker`, and `sudo-broker`;
- existing service names and executable flags unless separately deprecated;
- existing `~/.config/<broker>` and system configuration paths;
- existing scope, secret, grant, audit, and notification state formats;
- existing health endpoints and authenticated route behavior; and
- legacy operator routes during the documented V1 compatibility window.

Release archives and installer URLs will change repository ownership. Provide a
versioned installer migration with checksum verification, an explicit old/new
URL matrix, and a rollback command. An upgrade must stop only its target broker,
preserve its state, replace its binary atomically, run readiness checks, and
restore the previous binary on failure.

The OpenClaw plugin stores only safe mappings, cursors, and reconciliation
state. Broker credentials remain SecretRefs resolved server-side. The browser
never receives them.

## CI Design

One required top-level CI workflow provides the authoritative result. It may
fan out into path-aware jobs for speed, but shared/protocol changes always run
every broker and plugin contract test.

### Required jobs

1. **Repository policy**
   - formatting, generated-file drift, dependency direction, secret scanning,
     license/header policy, and clean-tree checks;
2. **Shared Go runtime**
   - `go fmt`, `go vet`, race tests, coverage, mutation tests, lint,
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
fixed paths. Every release includes checksums, source commit, protocol
compatibility, upgrade/rollback notes, and generated provenance. Privileged or
provider credentials are never available to ordinary build jobs.

Do not force all artifacts to share a version. Maintain a generated
compatibility table that states which operator wire versions and OpenClaw host
ranges each artifact supports.

## Documentation Consolidation

- Keep the root README short and user-oriented, with links to each component.
- Retain imported provider docs under their provider directories first; dedupe
  only after provenance is verified.
- Move shared architecture, protocol, security, migration, and conformance
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

## Migration Phases

### Phase 0: approve and inventory

- Approve this topology and the universal platform plan.
- Freeze source SHAs and create the migration ledger.
- Inventory open issues, releases, workflows, branch rules, docs, module paths,
  installers, deployment references, and external consumers.
- Run all current repository checks and record known failures without fixing
  unrelated behavior during import.
- Back up Git refs and verify each repository can be reconstructed.

Exit gate: scope, target layout, source SHAs, history method, release names,
and rollback owner are explicit.

### Phase 1: prepare the destination

- Create a dedicated consolidation branch from BrokerKit main.
- Add ADRs, migration ledger, target CI skeleton, ownership rules, and temporary
  compatibility scripts.
- Update root instructions for monorepo-scoped provider code without weakening
  secret or fail-closed requirements.
- Add secret and dependency-direction checks before importing history.

Exit gate: destination controls can detect the main risks introduced by import.

### Phase 2: import histories unchanged

- Import HF and GH sequentially with no-squash history merges.
- Commit each import as an independently reviewable slice.
- Verify commit reachability, file counts, representative blame history,
  source tags in the ledger, and source test commands.
- Do not mix source refactoring into history-import commits.

Exit gate: both original tips are reachable and their intact trees test as they
did before import.

### Phase 3: converge the Go workspace

- Rehome commands/internal packages and update imports.
- Merge modules into the root module and normalize toolchain/dependencies.
- Centralize common CI and release scripts without weakening provider checks.
- Keep binary/config/state compatibility and add migration tests.
- Delete duplicated generic runtime code only when shared BrokerKit equivalents
  pass provider tests.

Exit gate: one root `go.mod`, no local replaces, all three current Go suites and
cross-broker conformance pass, and HF/GH binaries are behaviorally compatible.

### Phase 4: stabilize protocol V1

- Implement the universal platform plan's schema, handler, client, lifecycle,
  presenter, idempotency, cursor, and conformance work.
- Cut over HF and GH in the same commits as contract changes.
- Add generated TypeScript bindings and mixed-version fixtures.

Exit gate: both brokers expose identical common operator behavior while keeping
different canonical provider plans and executors.

### Phase 5: add the OpenClaw plugin

- Create the private root JS workspace and plugin package.
- Add source registration, SecretRefs, cursor persistence, reconciliation, UI,
  and OpenClaw approval projection.
- Make any required provider-neutral OpenClaw SDK contribution separately.
- Test Gateway UI and multiple native channels without channel-specific code in
  the plugin.

Exit gate: a configured HF or GH request can be decided from the compact Gateway
UI and at least one existing OpenClaw channel, with the broker remaining
authoritative after restarts and lost responses.

### Phase 6: add sudo broker

- Turn the existing sudo model into a threat model and narrow V1 product scope.
- Implement structured command catalog and exact execution plans first.
- Add isolated privilege-transition tests and fail-closed host diagnostics.
- Defer interactive shells until their stronger identity-grant semantics have
  separate approval and audit acceptance criteria.

Exit gate: `sudo-broker` is a separate least-privileged process, passes common
conformance, cannot execute an unregistered or modified plan, and cannot expose
privilege to other monorepo artifacts.

### Phase 7: release and retire source repositories

- Produce release candidates for HF and GH from the monorepo.
- Exercise upgrade and rollback on representative existing state.
- Publish qualified component releases and verify install paths/checksums.
- Redirect development, migrate issues, observe the validation window, then
  archive old repositories.

Exit gate: production artifacts come from the monorepo, rollback has been
tested, old releases remain obtainable, and no active automation points to the
retired source repositories.

## Rollback Strategy

Every phase has a repository rollback and a deployment rollback.

- Before source repos are archived, repository rollback resumes development at
  the frozen source tips and discards the consolidation branch.
- After merge but before monorepo releases, revert topology commits without
  changing deployed artifacts.
- After a monorepo broker release, deployment rollback restores the last
  source-repo binary while retaining compatible state; migration tests must
  prove this before publication.
- Additive state fields must round-trip safely through old binaries or degrade
  by revoking/denying unsupported authority rather than granting it.
- The OpenClaw plugin can be disabled independently; disabling it does not
  mutate broker grants or delete broker state.
- `sudo-broker` has no migration rollback until it exists; its first release is
  additive and independently removable.

Do not archive source repositories, remove legacy release assets, or publish
irreversible state migrations until the validation window passes.

## Principal Risks And Mitigations

| Risk | Mitigation |
| --- | --- |
| Provider logic leaks into shared runtime | Dependency checks, scoped instructions, provider-neutral conformance fake |
| Monorepo mistaken for one security boundary | Separate binaries, credentials, state, listeners, threat models, and deploy tests |
| Git history or tags lost | No-squash imports, migration ledger, ancestry/blame verification, archived sources |
| Root Go module increases coupling | Internal provider packages, protocol boundary for consumers, path-aware releases |
| Shared change breaks every broker | Full matrix on shared/protocol changes and component release gates |
| Plugin becomes a second authority store | Broker-authoritative reconciliation and no independent timeout denial |
| OpenClaw internals copied into plugin | Use public plugin APIs; contribute one provider-neutral seam upstream if required |
| npm naming creates premature structure | One provisional unscoped plugin package; no organization or placeholders |
| Sudo privileges spread to other components | Separate process/build/deploy, exact plans, minimal socket access, isolated tests |
| Old installs stop updating | Stable binary/config names, installer URL migration, retained releases, rollback |
| Consolidation mixes refactor with import | Separate import commits and explicit phase gates |

## Acceptance Criteria

Consolidation is complete only when:

- original HF and GH source tips remain reachable in BrokerKit history;
- old `v0.1.0` releases remain downloadable from archived source repositories;
- one root Go module builds and tests BrokerKit, HF, and GH without local
  `replace` directives;
- shared packages contain no Hugging Face, GitHub, or sudo execution branches;
- each broker remains a separate process with separate credentials and state;
- binary names and supported configuration/state paths remain compatible;
- common changes run conformance against every broker;
- provider-only changes can release only that provider artifact;
- the OpenClaw plugin is independently installable and contains no
  channel-specific or provider-execution code;
- browser and channel decisions reach the same broker activation validator;
- the plugin can be disabled or rolled back without changing broker authority;
- sudo execution cannot be reached from another broker or plugin process;
- release tags, checksums, provenance, compatibility, upgrade, and rollback
  documentation are generated and verified; and
- source repositories are archived only after a successful monorepo release
  and exercised rollback.

## First Implementation Pull Requests

Keep early reviews small and ordered:

1. ADRs, migration ledger, monorepo instructions, and import safety checks.
2. No-squash HF history import, unchanged under its prefix.
3. No-squash GH history import, unchanged under its prefix.
4. Root Go module convergence and HF build/test cutover.
5. GH build/test cutover and unified conformance matrix.
6. Qualified component release workflows and installer migration tests.
7. Canonical protocol artifacts and generated TypeScript fixtures.
8. OpenClaw plugin scaffold and fake-broker integration.
9. Broker-to-OpenClaw approval projection, reconciliation, and compact UI.
10. Sudo threat model and structured-command MVP.

Do not combine history import, module convergence, protocol V1 behavior, plugin
implementation, and source-repository archival into one pull request.

## Explicit Decisions

- Use the existing `brokerkit` repository as the monorepo.
- Include HF, GH, sudo, and the OpenClaw plugin; exclude MLClaw and OpenClaw.
- Preserve imported histories without squashing.
- Converge Go code into one root module after intact imports.
- Keep provider packages internal and provider executors out of shared code.
- Keep every broker as a separate deployed security boundary.
- Use one private JavaScript workspace and one independently released plugin.
- Start with the unscoped working name `openclaw-brokerkit`; do not create an
  npm organization merely for package symmetry.
- Use component-qualified tags for binaries/plugins and the root `vX.Y.Z` tags
  for the BrokerKit Go module.
- Retain and later archive source repositories; never delete them.
- Preserve runtime names and state paths through consolidation.
- Require staged, reversible migration with an exercised rollback before
  retiring old release paths.
