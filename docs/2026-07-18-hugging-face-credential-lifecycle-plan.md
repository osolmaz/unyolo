# Hugging Face Credential Lifecycle Implementation Plan

Date: 2026-07-18

Status: planned

## Objective

Replace the manual Hugging Face token-file repair procedure and the current
complete-permissions credential profile with one production-ready BrokerKit
credential lifecycle. A user must be able to repair an installed HF Broker by
running:

```sh
hf-broker credential repair
```

The command opens Hugging Face's generic fine-grained token form, lets the
user choose permissions and resource or organization scope in Hugging Face,
accepts the resulting token through a hidden prompt, verifies it, installs it
transactionally, activates it, and proves the installed credential works.

This is a hard cutover. Do not retain permission-prefilled token URLs, a
complete-permissions acceptance requirement, OAuth device-token fallback,
legacy read or write-token fallback, parallel repair implementations, direct
secret-file overwrite instructions, or mixed old and new credential state.

## Confirmed Failure

The local system deployment accepted an OAuth device-login access token as its
static provider credential. After the broker binary was upgraded and the
service restarted, a real MCP repository-list operation submitted by `bob`
entered Agent Operations V1 and reached Hugging Face, then failed with:

```text
operation_upstream_authentication_failed
OAuth token signature verification failed: signature verification failed
```

The protected file was well formed and isolated, but its credential kind was
wrong for a long-running broker. The current setup and doctor flows verify
local file safety without proving that Hugging Face accepts the credential or
that it is a fine-grained user token. The failure therefore appeared only when
an operation executed.

## Decisions

- A normal HF Broker deployment uses one dedicated fine-grained Hugging Face
  user access token per broker installation.
- The token-creation form is not permission-prefilled. BrokerKit supplies only
  the fine-grained token type; the user selects permissions, resources, and
  organizations in Hugging Face.
- BrokerKit accepts any valid fine-grained token. It does not require the token
  to cover the entire HF operation catalog.
- The inspected token scope is an upstream credential ceiling, not BrokerKit
  authorization policy.
- MCP exposure is the intersection of implementation, client exposure,
  policy, and the active credential ceiling.
- Browser OAuth and `hf auth login` remain user-session authentication. They
  are never copied into a static broker credential file.
- Legacy `read` and `write` tokens are rejected. There is no automatic
  fallback when a fine-grained token is unavailable.
- Credential acquisition runs as the invoking user. Only exact installation
  and activation run with deployment-owner privileges.
- Candidate and active credentials are never active together. Rotation keeps
  BrokerKit's existing exact-replacement contract.
- The user's HF CLI login, token cache, and Git credential configuration are
  never read, modified, logged out, or replaced.
- Upstream retirement of the previous Hugging Face token remains manual until
  Hugging Face exposes a documented API suitable for that credential.

## Non-Goals

This cutover does not:

- create Hugging Face tokens through an undocumented API;
- choose permissions or organizations on the user's behalf;
- prove write permissions by mutating a real Hugging Face resource;
- store provider credentials in policy, Agent V1, MCP, audit, or conversation
  state;
- add a second privileged daemon solely for credential repair;
- make an agent or ordinary broker client an operator;
- require a Team or Enterprise Hugging Face plan;
- implement Enterprise OAuth Token Exchange or service accounts now; or
- change GitHub App, sudo, or Telegram credential acquisition in this slice.

The shared lifecycle must leave explicit extension points for service-account,
token-exchange, and external-secret providers without embedding Hugging Face
branches in shared packages.

## Existing Contract Alignment

`docs/CREDENTIAL_LIFECYCLE.md` already defines exact replacement, bounded
rollback snapshots, secret-safe lifecycle audit events, readiness before
retirement, and manual upstream retirement for Hugging Face tokens. Preserve
those rules.

This plan extends that contract with a focused provider-credential rotation
path. It does not introduce a dual-active credential window. A candidate may
exist in protected staging memory or a protected staging file while the old
credential remains active, but the candidate cannot serve operations until
the exact replacement point. After replacement, the old credential may exist
only in the bounded rollback snapshot and cannot be loaded by the broker.

`docs/SYSTEMD_INSTALL_RUNTIME.md` remains authoritative for privileged account,
path, file, unit, activation, readiness, and rollback behavior. Focused
credential repair must reuse the same path validation, ownership, atomic
write, sync, service activation, and fake-runner test infrastructure instead
of invoking `systemctl` or editing protected files in HF-specific code.

Implementation must update the maintained credential lifecycle, unified
broker contract, architecture, HF README, service setup guide, doctor guide,
and MLClaw-facing integration documentation. Do not leave the old manual
replacement flow or complete-permissions requirement described as current.

## User Experience

### Interactive repair

The normal path is:

```sh
hf-broker credential repair
```

Behavior:

1. discover one unambiguous installed HF Broker deployment;
2. open `https://huggingface.co/settings/tokens/new?tokenType=fineGrained`;
3. when browser opening is unavailable, print the exact URL on its own
   unwrapped line;
4. print short instructions telling the user to select the desired permission
   and resource ceiling in Hugging Face;
5. prompt for the token through a no-echo terminal input;
6. inspect and verify the candidate without changing the active credential;
7. display the discovered Hugging Face identity and a secret-free capability
   summary;
8. elevate only for protected installation and activation;
9. activate, verify, and commit the replacement; and
10. print the active identity, capability summary, and doctor result.

The command asks no account, organization, resource, or permission questions.
Hugging Face owns those choices. The only interactive secret input is the
token paste, plus any operating-system privilege prompt required by the host.

### Headless and automation repair

Support:

```sh
hf-broker credential repair --no-open --token-stdin
hf-broker credential repair --no-open --token-stdin --json
```

Rules:

- `--token-stdin` reads exactly one bounded token and rejects trailing data;
- the token is never accepted as a flag, positional argument, environment
  variable, URL parameter, or JSON field;
- `--json` reports state and errors without including the token, protected
  paths, raw upstream bodies, or provider targets;
- non-interactive mode never invokes `sudo` implicitly; it fails with a clear
  privilege requirement unless already authorized by deployment policy; and
- machine-readable output uses stable error codes and a versioned schema.

### Status and inspection

Add:

```sh
hf-broker credential status [--json]
hf-broker credential inspect --token-stdin [--json]
```

`status` reads only active, secret-free credential metadata from broker state.
It does not open the protected token file as the invoking user.

`inspect` validates a candidate without installing it. It is the single
provider-owned verification entry point for trusted automation and host
integrations. The text form is human-readable; the JSON form is stable and
bounded.

## Target Architecture

```text
invoking operator
        |
        v
hf-broker credential repair
        |
        +-- open generic HF fine-grained token form
        |
        +-- hidden token input
        |
        v
HF credential adapter
        |
        +-- whoami-v2 identity and token-kind verification
        +-- capability inspection
        +-- candidate fingerprint
        |
        v
shared exact-replacement lifecycle
        |
        +-- protected stage
        +-- quiesce bounded new work
        +-- atomic file replacement
        +-- activate or reload
        +-- readiness and credential probe
        |
        +-- success --> commit and clear rollback material
        |
        `-- failure --> restore old file and previous process state
```

No upstream token crosses Agent V1, MCP, the operator inbox, Telegram,
delegated web hosting, OpenClaw, or an untrusted browser parent.

## Package Boundaries

### Shared credential lifecycle

Add a provider-neutral package, named for example `credentiallifecycle`, that
owns only transactional lifecycle mechanics:

- bounded candidate input;
- secret-memory ownership and clearing;
- credential fingerprinting with truncated display identifiers;
- candidate, activation, probe, commit, and rollback state transitions;
- exact-replacement invariants;
- lifecycle audit event construction;
- platform activation adapters;
- stable status and error codes; and
- test seams for clocks, process activation, and protected storage.

The package receives provider verification and probing functions. It must not
import Hugging Face, GitHub, sudo, Telegram, OpenClaw, MLClaw, browser-opening,
or provider operation catalogs.

Do not create a broad plugin framework. Use concrete lifecycle types and small
functions for provider inspection and platform activation.

### Hugging Face credential adapter

Add an HF-owned package under `brokers/huggingface/internal` that owns:

- the generic fine-grained token-form URL;
- token syntax and byte bounds;
- `whoami-v2` request and strict bounded response parsing;
- rejection of OAuth, legacy read, legacy write, organization, malformed, and
  unverifiable tokens;
- account identity normalization;
- fine-grained global, personal, organization, and resource capability
  extraction;
- mapping inspected capabilities to HF operation requirements;
- HF-specific active probes and upstream error classification; and
- secret-free credential metadata.

The adapter must use the existing bounded Hub client transport and redaction
rules. Do not add a second generic HTTP client or parse raw response strings.

### CLI orchestration

The HF CLI command owns:

- deployment discovery;
- browser opening on Linux and macOS;
- unwrapped URL fallback;
- hidden TTY input;
- human and JSON rendering;
- explicit automation flags;
- privilege transition into the trusted install phase; and
- final live status reporting.

The command must not implement provider verification, protected-file writes,
systemd or launchd operations, rollback, or capability matching itself.

### Privileged installation

Add a narrow internal install phase callable only through the public repair
workflow. It receives the token on stdin after the invoking user has inspected
it. The privileged phase:

1. rediscovers and validates the installed deployment;
2. independently re-inspects the candidate;
3. verifies that the active binary and every trusted ancestor are safe;
4. stages the candidate beside the active protected file with exact ownership
   and mode;
5. invokes the shared exact-replacement lifecycle;
6. activates and probes the broker;
7. commits or rolls back; and
8. clears candidate and rollback material.

The unprivileged process must not write a plaintext token to a user-owned
temporary file. Pass the candidate through an inherited pipe. The token must
not appear in `ps`, `/proc/*/cmdline`, inherited environment, shell history,
crash output, or command logs.

### Host-neutral integration

BrokerKit must not know about MLClaw or any delegated host. Trusted hosts may
invoke `credential inspect --token-stdin --json` and a separately authorized
activation path, or use a future protected Credential V1 protocol with the
same lifecycle state machine.

If a protected protocol is added during implementation, it must be
provider-neutral, operator-authenticated, secret-write-only, and use sealed
candidate references rather than plaintext credential fields. Do not make a
network credential endpoint mandatory for the local CLI cutover.

## Credential Model

Store only the active token in the configured protected credential source.
Store the following secret-free metadata in broker state:

```text
schema_version
credential_class
provider
identity
token_kind
fingerprint_sha256
installed_at
verified_at
verification_state
capability_digest
capability_summary
source_kind
rotation_state
revocation_mode
```

The full fingerprint may remain in protected state for exact identity checks;
human and audit output uses a short identifier. Capability metadata must be
bounded, normalized, deterministic, and safe to disclose to the operator. It
must not include raw token claims or provider response bodies.

Never infer token kind from length, prefix, or JWT punctuation alone. Those
checks may reject obviously unsafe input early, but acceptance requires a
successful Hugging Face identity response that explicitly identifies a
fine-grained token and exposes an inspectable permission model.

## Capability-Aware Operation Exposure

The user chooses the upstream ceiling, so every HF operation binding must
declare its required upstream capabilities. Generate this mapping with the HF
operation catalog and validate complete coverage at build and startup.

For one operation to be advertised, all of these must hold:

1. the operation is agent-facing;
2. the client exposure profile permits it;
3. policy recognizes it;
4. a runtime implementation is registered; and
5. the active credential ceiling covers its upstream requirements.

Apply the same check during direct submission. Discovery filtering is not an
authorization boundary.

When capability coverage is missing:

- omit the ordinary operation tool from `tools/list`;
- emit `tools/list_changed` after credential replacement changes exposure;
- reject direct submissions before any upstream request;
- return `operation_credential_capability_missing` with bounded missing
  capability names; and
- do not create an approval request, because operator approval cannot expand
  the provider credential ceiling.

`credential status` reports the number and classes of available operations,
not a claim that every possible provider mutation has been tested.

## Activation And Concurrency

Preserve exact replacement without a dual-active period:

1. inspect the candidate while the old credential remains active;
2. stop admitting new provider operations;
3. allow bounded in-flight operations to finish;
4. fail activation if the drain deadline expires;
5. atomically switch the protected credential source;
6. reload or restart the broker so only the new credential is loaded;
7. wait for local readiness and candidate identity verification;
8. run a non-mutating provider probe;
9. resume admission and commit on success; or
10. restore the old credential and previous process state before resuming on
    failure.

Do not let one operation begin with one credential generation and continue
with another. Plans and audit records carry only a secret-free credential
generation identifier.

A transient Hugging Face network failure before replacement is inconclusive
and leaves the old credential active. A definitive candidate authentication
failure rejects the candidate. A network failure after replacement triggers
bounded retry; if confidence cannot be established, restore the old local
credential rather than committing an unverified replacement.

## Readiness And Doctor

Keep process health separate from credential readiness:

- liveness means the process and listeners are functioning;
- readiness means configuration is valid and the active provider credential
  passed its required verification;
- credential status reports valid, invalid, unavailable, or inconclusive; and
- operation execution fails closed when credential readiness is not valid.

Extend HF doctor with an explicit active credential check. It must distinguish:

- invalid or revoked token;
- wrong token kind;
- permission ceiling that excludes configured operations;
- organization token pending, denied, or revoked state where Hugging Face
  reports it;
- provider outage or timeout;
- local token-file isolation failure; and
- stale credential metadata.

Doctor must never print the token, token path in public JSON, raw provider
response, or an authorization header. Passive isolation checks remain usable
offline. Active provider checks are bounded and clearly marked as networked.

## Failure Semantics

Use stable errors:

```text
credential_input_invalid
credential_kind_unsupported
credential_authentication_failed
credential_capability_missing
credential_provider_unavailable
credential_installation_unsafe
credential_activation_failed
credential_probe_failed
credential_rollback_failed
credential_deployment_ambiguous
```

Provider raw messages are diagnostic input, not public contract text. Logs and
Agent V1 errors use bounded, redacted categories.

If rollback itself fails, keep operation admission closed, preserve all
recoverable protected material, report a critical doctor failure, and require
operator intervention. Never guess which credential is active.

## Deployment Discovery

The interactive command asks no deployment questions. Detect one supported
installation deterministically:

- Linux system installation from the existing root-owned HF Broker systemd
  unit and environment contract;
- macOS system installation from the existing LaunchDaemon contract; or
- an explicit development credential target supplied by a development-only
  flag.

Reject zero or multiple candidates with `credential_deployment_ambiguous` and
print exact remediation commands. Do not search arbitrary home directories,
parse shell startup files, inspect HF CLI caches, or infer a deployment from a
running process command line.

## Audit And Observability

Emit one `credential.lifecycle` event for candidate rejection, successful
rotation, rollback, and rollback failure. Include only:

- actor;
- credential class;
- old and new short fingerprints;
- old and new capability digests;
- lifecycle outcome;
- stable error category;
- activation duration; and
- provider probe result.

Add bounded metrics for repair attempts, candidate rejection categories,
activation, rollback, credential readiness, capability-driven tool exposure,
and active-probe latency. Do not label metrics with account, organization,
repository, token name, fingerprint, or operation target.

## Replacement Migration

Replace the current credential surface in one merge:

1. add shared lifecycle and HF inspection packages;
2. add repair, inspect, and status commands;
3. add capability requirements to every HF operation binding;
4. make HF operation exposure and submission credential-aware;
5. add active readiness and doctor checks;
6. migrate systemd and launchd setup to the shared focused-rotation primitive;
7. migrate trusted host integrations to the new inspection contract;
8. remove permission-prefilled token URL generation;
9. remove the complete-permissions acceptance profile;
10. remove OAuth and legacy-token acceptance paths;
11. replace direct token-file overwrite documentation; and
12. regenerate capability and compatibility artifacts.

Replace `hf-broker credential requirements` with the new status and inspection
surface. Do not keep it as an alias. If a machine-readable operation-to-HF
capability document remains useful, name and document it as a capability map,
not as permissions every token must possess.

Existing installed OAuth, read, or write tokens are not migrated. Doctor marks
them unsupported, and the operator runs `hf-broker credential repair` once.
No broker operation silently falls back to the user's HF CLI login.

## Test Strategy

### Unit tests

- generic browser URL contains no permission, resource, organization, token
  name, or credential value parameters;
- strict bounded parsing for valid fine-grained identity responses;
- rejection of OAuth, legacy read, legacy write, organization, malformed,
  oversized, and ambiguous token responses;
- capability normalization and deterministic digesting;
- complete operation-to-capability mapping coverage;
- exact exposure intersection and stable missing-capability errors;
- no token in text, JSON, errors, logs, audit, or metrics; and
- lifecycle transition and rollback invariants.

### Privileged lifecycle tests

- token enters the privileged process only through stdin;
- candidate is independently verified after privilege transition;
- exact ownership, mode, ancestor, symlink, and regular-file checks;
- atomic write, sync, rename, activation, readiness, and cleanup ordering;
- successful systemd and launchd activation through fake runners;
- definitive candidate failure leaves the old credential active;
- readiness or probe failure restores the old file and process state;
- rollback failure closes admission and preserves recovery material;
- process interruption at every durable step recovers deterministically; and
- candidate and old credentials are never simultaneously loadable.

### Local end-to-end tests

Run real compiled processes against a fake Hugging Face server:

1. start HF Broker with an accepted old fine-grained token;
2. invoke `credential repair --token-stdin` with a new candidate;
3. verify hidden or piped input never appears in process metadata;
4. verify candidate identity and capabilities;
5. activate the candidate;
6. run `hf_repo_list` through the real stdio MCP server as a broker client;
7. wait through the real Agent V1 lifecycle;
8. assert the returned repository list came from the fake provider;
9. rotate to a limited read-only candidate and assert tool exposure changes;
10. inject invalid, unavailable, and probe-failure candidates and prove
    rollback; and
11. restart the broker and prove metadata and capability exposure persist.

### Live manual validation

After merge and local installation:

1. run `hf-broker credential repair` as the human operator;
2. create a fine-grained token in Hugging Face with deliberately selected
   permissions and resources;
3. verify the installed identity and capability summary;
4. run a harmless `hf_repo_list` MCP call as `bob`;
5. wait for the operation and inspect the bounded result;
6. verify an operation outside the selected ceiling is not advertised;
7. verify Bob cannot read the provider token or operator credential;
8. run active and passive doctor checks; and
9. confirm the user's `hf auth whoami` session is unchanged.

Do not create, delete, modify, or change visibility of a real Hugging Face
resource during this validation.

## Quality Gates

- generated artifacts are current and reproducible;
- Go formatting, vet, race tests, aggregate coverage, lint, vulnerability,
  secret scanning, and Slophammer gates pass;
- HF, GitHub, sudo, Telegram, and OpenClaw package tests remain green;
- Linux systemd and macOS launchd credential paths pass platform CI;
- the packed OpenClaw plugin remains installable;
- Codex review reports no P0 or P1 findings;
- CI is green before merge; and
- the merged commit passes the live non-mutating Bob MCP validation before a
  release is published.

Mutation tooling remains available but disabled and non-blocking.

## Release And Rollout

1. merge the hard cutover with all dependent trusted-host changes ready;
2. install the merged development binaries locally;
3. repair the local HF Broker credential through the new flow;
4. complete the Bob MCP and doctor validation;
5. publish the HF Broker and any shared BrokerKit artifacts from one immutable
   commit;
6. update trusted hosts to that immutable BrokerKit release;
7. build the dependent MLClaw runtime image without adding MLClaw knowledge to
   BrokerKit;
8. deploy the test environment;
9. repeat credential status, MCP repository read, approval, and UI smoke tests;
10. deploy GoePT only after the test environment is green; and
11. archive the implementation plan after maintained documentation reflects
    the shipped contract.

## Completion Criteria

The cutover is complete only when:

- `hf-broker credential repair` performs the complete interactive lifecycle;
- no CLI question duplicates account, organization, resource, or permission
  selection from Hugging Face;
- only valid fine-grained tokens are accepted;
- limited tokens produce an explicit capability ceiling instead of an
  installation failure;
- credential-aware MCP discovery and submission are enforced;
- activation is exact, transactional, auditable, and rollback-safe;
- repair candidates never enter argv, environment, logs, audit, MCP, Agent V1,
  or ordinary user storage;
- systemd, launchd, headless, and trusted-host paths use one lifecycle model;
- the old requirements profile and manual overwrite path are removed;
- Bob completes a real repository-list operation through MCP;
- all local and remote quality gates pass;
- immutable releases are published; and
- GoePT is redeployed and validated from the released artifacts.
