# BrokerKit Implementation Handoff

Date: 2026-07-11

Status: approved planning package for one coordinated implementation and
cutover

## Start Here

This file is the entry point for an agent implementing the complete BrokerKit
platform without relying on the conversation that produced the plans.

Read these files in order:

1. `docs/2026-07-11-implementation-handoff.md`
2. `docs/2026-07-11-monorepo-consolidation-plan.md`
3. `docs/2026-07-11-universal-broker-platform-plan.md`
4. `docs/components/2026-07-11-huggingface-broker-adoption-plan.md`
5. `docs/components/2026-07-11-github-broker-adoption-plan.md`
6. `docs/components/2026-07-11-sudo-broker-implementation-plan.md`
7. `docs/2026-07-11-openclaw-host-seams-plan.md`
8. `docs/2026-07-11-openclaw-plugin-implementation-plan.md`

Together they are the implementation specification. Existing BrokerKit design
documents remain useful codebase background, but they do not override this
package. If an older document conflicts, this dated package wins and the
implementation must update or remove the conflicting text.

## Objective

Deliver one focused `brokerkit` monorepo containing:

- the provider-neutral Go runtime and Operator V1 protocol;
- `hf-broker` with Hugging Face-specific plans and execution;
- `gh-broker` with GitHub-specific plans and execution;
- a new exact-command `sudo-broker` with a separate privileged helper; and
- the independent `openclaw-brokerkit` plugin with compact Gateway UI and
  OpenClaw-native approval/channel delivery.

MLClaw and upstream OpenClaw remain separate repositories. The implementation
may contribute only the three generic host seams specified in the OpenClaw
plan; no BrokerKit/provider id enters OpenClaw core.

The project is complete only as one coordinated clean cutover. Ordered commits
and dependency gates are for engineering control, not supported intermediate
deployments.

## Frozen Baselines

Re-verify these before the first implementation commit:

| Component | Repository | Reviewed tip |
| --- | --- | --- |
| BrokerKit | `github.com/osolmaz/brokerkit` | `b4e59bad8c5ac5555f030141debc85752adc281b` plus this planning commit |
| HF broker | `github.com/osolmaz/hf-broker` | `2f3844b` |
| GH broker | `github.com/osolmaz/gh-broker` | `7b7f5f1` |
| OpenClaw API audit | `github.com/openclaw/openclaw` | `fe261b0f59aa1582e8e4a7dc8e372eb82c8eb0cd` |

If a source tip has moved, freeze the new tip, rerun its required checks, and
record it in the import ledger. Do not silently drop commits. If an audited
OpenClaw seam changed, map the plan to the new public API and update the host
plan before coding; do not use private imports as a shortcut.

## Locked Decisions

The implementing agent does not need to choose these:

- existing `brokerkit` becomes the monorepo;
- HF and GH history is imported without squashing;
- Go converges to one root module;
- shared root packages stay provider-neutral;
- every broker is a separate process, listener, credential domain, state, and
  release artifact;
- sudo uses an unprivileged frontend and a minimal local privileged helper;
- Operator V1 is the only operator wire contract;
- fresh V1 config/state is used at cutover; no old-format parser, alias,
  converter, dual route, dual read, or dual write is added;
- all old authority is revoked or allowed to expire before cutover;
- BrokerKit brokers remain authoritative for requests, revisions, decisions,
  activation validation, grants, execution plans, and audit;
- OpenClaw is a trusted UI/delivery host, not a second authority store;
- plugin id is `brokerkit`;
- npm package is `openclaw-brokerkit` (registry 404 observed 2026-07-11);
- plugin config key is `brokers` and the secret field is
  `operatorCredential`;
- operator credentials are structured SecretRefs in source config and resolved
  strings only in the server runtime;
- the plugin UI uses React/TypeScript/Vite/Tailwind/shadcn inside a sandboxed
  iframe; it does not add React to OpenClaw's Lit UI;
- the UI appears in a compact Settings popover/bottom sheet, never a permanent
  side panel;
- channel delivery goes through existing `approvals.plugin` and channel
  capabilities; the plugin contains no channel-specific code;
- channel approval offers only `allow-once` and `deny`;
- OpenClaw timeout/restart/cancel never changes broker authority;
- browser decisions are revision-bound, idempotent, and server-attributed;
- provider-specific behavior remains in its broker directory;
- no npm organization or placeholder provider packages are created; and
- source repositories are archived, not deleted, at the successful cutover.

## Repository Topology

```text
~/repos/brokerkit                 authoritative monorepo
~/repos/hf-broker                 frozen import source
~/repos/gh-broker                 frozen import source
~/oc/openclaw                     separate upstream host work
~/repos/mlclaw                    separate deployment product
```

OpenClaw work uses a normal worktree next to `~/oc/openclaw` under
`~/oc/openclaw-worktrees/<task>`. Do not develop an OpenClaw pull request on the
main checkout. OpenClaw commits/pull requests must use the main author account,
never `dutifulbob`, and must follow the repository contribution instructions.

## Authority And Data Flow

```text
agent request
  -> provider broker authentication/classification/policy
  -> immutable provider-owned canonical plan
  -> BrokerKit pending request and Operator V1
  -> OpenClaw plugin safe source projection
       -> compact Gateway Settings popover
       -> existing OpenClaw approval/channel system
  -> revision-bound decision returns to the same broker
  -> broker activation validator checks the stored plan
  -> provider broker executes and audits
```

No upstream credential or executable plan crosses into BrokerKit wire,
OpenClaw, browser, channel text, plugin state, or another broker.

## One-Cutover Execution Checklist

Work in this dependency order on one implementation program:

1. freeze source refs, import ledger, issue/release inventory, backups, and
   secret scans;
2. update monorepo instructions/ADRs, ownership rules, CI skeleton, and
   dependency-direction checks;
3. import HF and GH histories without squashing and verify ancestry/blame/tests;
4. converge one Go module and root quality/release tooling;
5. implement the complete Operator V1 schema, runtime, decision service,
   persistence, client/fake, and conformance suite;
6. implement HF and GH plan binding/hardening against V1;
7. implement sudo catalog, plans, helper, host checks, settlement, and isolated
   privilege tests;
8. implement and release the three generic OpenClaw host seams;
9. implement the independent plugin runtime, state, reconciliation, Gateway
   methods, static UI route, iframe bridge client, and compact UI;
10. run the complete unit/race/fuzz/security/restart/browser/channel/
    provider/live matrix from fresh state;
11. build reproducible signed/checksummed/provenance artifacts from one green
    commit and claim/publish `openclaw-brokerkit`;
12. revoke/expire existing authority, stop old deployments, archive old state,
    install and validate the complete new system, expose listeners, redirect
    development/issues, and archive source repositories.

Do not expose production traffic after any proper subset of this checklist.

## Required Commit Discipline

Use Conventional Commits. Keep coherent imports/refactors/features/tests in
separate commits so review can verify history and security boundaries, but keep
them on the same cutover branch/program. Never squash imported source history.

OpenClaw pull-request branch commits must be frequent and working because that
repository explicitly requires coherent slices. The final BrokerKit release
still waits for the full system.

## Required Quality Gates

At minimum, the finished monorepo runs:

```sh
go mod tidy
git diff --exit-code -- go.mod go.sum
go mod verify
gofmt -l .
go vet ./...
go test -race ./...
golangci-lint run
govulncheck ./...
slophammer-go dry .
slophammer-go crap .
slophammer-go check .
```

It also runs the existing BrokerKit coverage script, strict TypeScript
formatting/lint/typecheck/unit tests, generated-schema drift,
package/manifest validation, browser tests in Chromium/Firefox/WebKit,
OpenClaw integration/channel tests, secret scanning, reproducibility, SBOM,
checksum, and provenance checks defined in the component plans.

Mutation tooling and its CI declaration remain checked in, but mutation testing
is disabled and is not a required or blocking gate for this cutover. The CI hook
must remain opt-in, for example through `RUN_MUTATION=true`, and must not run in
the default required workflow. Re-enabling mutation testing requires a later
explicit decision and is not implementation latitude.

HF/GH checks imported from their current `AGENTS.md` remain mandatory unless
the consolidated instruction file replaces them with a strictly stronger
equivalent. Sudo privilege tests run only in disposable isolated runners.

## Cutover Safety Gate

Before stopping old deployments:

- every old pending/active grant is denied, revoked, consumed, or expired;
- audit/state directories are snapshotted read-only for forensic retention;
- new configs validate without starting listeners;
- new secrets resolve without being printed;
- broker/operator listeners bind only intended addresses/sockets;
- the plugin's minimum OpenClaw host and public SDK seams are present;
- all fresh-state readiness and end-to-end probes pass in isolation;
- release artifacts/checksums match the tested commit; and
- an operator explicitly authorizes the production traffic switch.

If the new system fails before traffic is exposed, keep it isolated, repair it,
and rerun the complete gate. Never make old/new binaries share state or add a
temporary adapter.

## No Hidden Decisions

The following are intentionally out of scope rather than undecided:

- multi-party/quorum approval;
- provider-typed generic UI forms/extensions;
- dynamic broker discovery;
- arbitrary provider API proxying;
- browser-held broker credentials;
- universal agent API;
- sudo shells, TTY sessions, stdin, arbitrary argv/env, and background daemons;
- custom broker TLS CA/client certificate/proxy/header config;
- npm scopes/organizations and provider adapter packages; and
- any old route/config/state support.

Adding one requires a new explicit design decision; it is not implementation
latitude.

## Definition Of Done

The handoff is implemented only when:

- the monorepo history and one-module structure are verified;
- all four broker/runtime components obey the dependency and process boundary;
- only Operator V1 and fresh state exist in supported artifacts;
- HF, GH, and sudo pass the same common conformance while retaining distinct
  plans/executors;
- the independent plugin registers all brokers without provider branches;
- compact Gateway and existing channel decisions settle through the same
  broker activation validator;
- restart, expiry, stale revision, lost response, one source down, and one
  channel down all fail closed without invented authority;
- no credential, plan, unsafe provider payload, or privileged capability leaks
  across a boundary;
- the complete quality/cutover gates pass; and
- the coordinated release is installed before old source repositories are
  archived.
