# Provider Credential Lifecycle Implementation Plan

Date: 2026-07-18

Status: implemented

## Objective

Build one provider-neutral BrokerKit credential framework and use it for every
broker integration. The framework owns inspection orchestration, protected
replacement, rollback, status, audit, capability enforcement, and test
contracts. Provider packages own only enrollment instructions, upstream
inspection, capability normalization, provider probes, and mappings from
broker operations to provider permissions.

Implement the framework with the Hugging Face adapter first. Add the GitHub
App adapter immediately afterward through the same contracts. Do not copy the
HF command or lifecycle implementation into the GitHub broker.

The provider credential ceiling and BrokerKit policy remain separate:

```text
effective operation authority
    = implemented operation
    AND client exposure
    AND provider credential coverage
    AND BrokerKit policy or active grant
```

An approval may narrow authority inside the credential ceiling. It can never
expand the provider credential.

## Decisions

- BrokerKit owns one credential domain model and lifecycle state machine.
- Shared code never imports a provider package or branches on provider names.
- Each provider implements a small explicit adapter contract. Do not build a
  runtime plugin loader or a second broker framework.
- Provider capabilities are typed by permission, access level, resource
  domain, and resource selector. Do not flatten them into unscoped strings.
- Operation requirements support both all-of and any-of clauses because some
  provider endpoints require multiple permissions or accept alternatives.
- Every implemented provider operation has one validated requirement entry.
  Missing entries fail generation, tests, and startup.
- Tool discovery is conservative, but discovery is not an authorization
  boundary. Exact target coverage is checked at submission and execution.
- Immutable operation plans bind a credential generation and capability
  digest. A grant cannot outlive or exceed a changed credential ceiling.
- Provider status distinguishes invalid, unavailable, inconclusive, expired,
  and valid. A network failure is not reported as an invalid credential.
- Shared storage contains the active secret and bounded secret-free metadata.
  Provider responses, claims, and raw permission payloads are not persisted.
- Hugging Face uses a dedicated fine-grained user token.
- GitHub uses a GitHub App installation. Fine-grained and classic personal
  access tokens are not supported unless a later concrete requirement is
  approved.
- BrokerKit stores GitHub App identity, installation selection, and the App
  private key. It does not persist one-hour installation access tokens.
- Existing OAuth, legacy token, and manual overwrite paths are removed when
  their provider adapter ships. Do not retain aliases or parallel readers.

## Non-Goals

This work does not:

- create provider credentials through undocumented APIs;
- choose provider permissions or resources on the user's behalf;
- prove write access by mutating a real provider resource;
- put provider secrets in Agent V1, MCP, policy, audit, Telegram, or browser
  state;
- add a privileged daemon solely for credential repair;
- make ordinary broker clients credential operators;
- implement GitHub OAuth Apps or personal access tokens;
- require MLClaw, OpenClaw, or a particular delegated host; or
- make provider credential scope replace BrokerKit authorization policy.

## Architecture

```text
provider binary CLI
        |
        v
shared credential command orchestration
        |
        +-- provider enrollment description
        +-- hidden or stdin candidate input
        +-- provider candidate inspection
        +-- secret-free preview
        |
        v
shared protected lifecycle
        |
        +-- deployment discovery
        +-- independent privileged reinspection
        +-- admission drain
        +-- atomic exact replacement
        +-- service activation
        +-- local readiness and provider probe
        +-- commit or rollback
        |
        v
credential snapshot and generation
        |
        +-- authenticated capability summary
        +-- MCP tool intersection
        +-- submission target check
        `-- execution-time recheck
```

Provider secrets never cross the agent, operator inbox, approval notification,
delegated web, or MCP boundaries.

## Shared Package Boundaries

### Provider credential model

Add a provider-neutral package such as `providercredential`. It owns the
canonical types and validation for:

```text
CredentialSnapshot
  schema_version
  provider
  credential_kind
  subject
  fingerprint_sha256
  generation
  verified_at
  expires_at
  verification_state
  capabilities[]
  capability_digest

Capability
  domain
  permission
  access_level
  resource_kind
  resource_selector

Requirement
  all_of[]
    any_of[]
      domain
      permission
      minimum_access_level
      target_binding
```

`target_binding` identifies which canonical operation target field selects the
provider resource. Selectors are structured values, not path globs assembled
from user input. Normalize, sort, deduplicate, bound, and digest all
capabilities deterministically.

The package owns requirement evaluation and stable missing-capability results.
It does not know HF or GitHub permission names.

### Provider adapter contract

Define a small compile-time contract equivalent to:

```go
type Adapter interface {
    Provider() string
    Enrollment(context.Context) (Enrollment, error)
    Inspect(context.Context, Secret) (CredentialSnapshot, error)
    Requirement(operation string) (Requirement, bool)
    Probe(context.Context, CredentialSnapshot) (ProbeResult, error)
}
```

The concrete API may separate secret-bearing and secret-free methods further.
The important boundary is that the adapter never writes host files, restarts a
service, renders generic CLI output, filters MCP itself, or decides BrokerKit
policy.

`Enrollment` may contain a constant browser URL and bounded instructions, but
never a credential. `Secret` is an owned bounded buffer with explicit clearing.
`ProbeResult` uses closed provider-neutral states and redacted diagnostics.

### Command orchestration

Add shared command helpers used by provider binaries for:

```text
credential inspect --token-stdin [--json]
credential repair [--no-open] [--token-stdin] [--json]
credential status [--json]
```

Adapters supply provider wording, enrollment, inspection, and deployment
metadata. Shared command code owns flag semantics, hidden input, stdin bounds,
browser fallback, privilege transition, output schemas, and stable errors.

Tokens and keys are never accepted in argv, environment variables, URLs, JSON
arguments, or user-owned temporary files. The unprivileged process passes an
inspected candidate to the protected phase through an inherited pipe. The
protected phase rediscovers the deployment and independently reinspects it.

### Protected lifecycle

Extend the existing `credentiallifecycle` and `service` packages instead of
creating provider-specific installers. They own:

- safe deployment and trusted-path discovery;
- bounded rollback snapshots;
- atomic writes with exact owner, group, and mode;
- admission drain and credential generation changes;
- systemd and launchd activation adapters;
- local readiness, provider probe, commit, and rollback;
- interruption recovery and rollback-failure lockout; and
- secret-safe lifecycle events.

The full service setup path and focused credential replacement path must use
the same managed-file validation and transaction primitives.

### Runtime capability service

Expose one internal provider-neutral capability service to broker runtimes.
It owns the active immutable snapshot and answers:

- whether an operation may be advertised for at least one reachable target;
- whether one exact operation target is covered;
- which bounded requirements are missing;
- whether a stored plan's generation and digest remain current; and
- whether credential readiness permits execution.

Update the active snapshot atomically only after successful activation. Emit a
tool-list change notification when the advertised set changes.

## Provider Adapters

### Hugging Face

The HF adapter owns:

- the generic fine-grained-token form URL;
- strict bounded `whoami-v2` parsing;
- rejection of OAuth and legacy read or write tokens;
- user, organization, repository, and resource capability normalization;
- HF operation requirement data; and
- non-mutating HF identity and access probes.

The complete HF behavior and validation matrix remains in
`2026-07-18-hugging-face-credential-lifecycle-plan.md`.

### GitHub

The GitHub adapter uses the existing GitHub App integration and
`ghinstallation` transport. It owns:

- App identity and private-key inspection;
- installation discovery and exact installation selection;
- installation account, repository selection, suspension, and permission
  normalization;
- GitHub repository, organization, and account permission requirements;
- installation and repository access probes; and
- installation-token refresh metadata.

Installation access tokens are generated in memory, cached by the authenticated
transport, refreshed before expiry, and never written as active credentials.
Credential generation changes when the App identity, installation, repository
selection, or effective permissions change, not when an equivalent one-hour
token refreshes.

GitHub documents that installation tokens expire after one hour and cannot
exceed the installation's repositories or permissions:
<https://docs.github.com/en/apps/creating-github-apps/authenticating-with-a-github-app/generating-an-installation-access-token-for-a-github-app>

GitHub operation requirements must be generated from the canonical operation
catalog and checked against GitHub's repository, organization, and account
permission classes:
<https://docs.github.com/en/apps/creating-github-apps/registering-a-github-app/choosing-permissions-for-a-github-app>

Do not treat `X-Accepted-GitHub-Permissions` from a failed live request as the
source of truth. It may support diagnostics and fixture maintenance, but the
checked-in generated requirement map is authoritative at runtime.

## Runtime Enforcement

### Discovery

Advertise an ordinary operation tool only when:

1. the operation is implemented and agent-facing;
2. the client exposure profile permits it;
3. policy recognizes it;
4. a provider requirement exists; and
5. the active credential can satisfy that requirement for at least one
   reachable resource.

Always retain provider-neutral lifecycle utilities needed to inspect pending
operations and grants. Do not advertise a mutation merely because a read
permission exists.

### Submission

Before policy evaluation, approval creation, sealed payload allocation, or an
upstream request:

1. canonicalize the operation target;
2. resolve its provider requirement;
3. bind target fields to the structured resource selector;
4. evaluate all-of and any-of clauses against the active snapshot; and
5. reject uncovered requests with
   `operation_credential_capability_missing`.

The error includes only bounded canonical permission names. It never includes
provider responses, repository lists, installation secrets, or tokens.

### Approval and execution

Bind the credential generation and capability digest into the immutable plan.
Immediately before execution, re-evaluate the exact target against the current
snapshot. If authority was removed, fail closed without consuming an upstream
mutation. A credential expansion does not automatically widen an already
approved plan; resubmission is required.

Ephemeral GitHub installation-token refresh does not invalidate a plan when
the effective capability snapshot is unchanged.

## Status And APIs

Provide two authenticated secret-free views:

- the agent endpoint returns readiness and the operation names available to
  that authenticated client, sufficient for MCP discovery;
- the operator endpoint returns identity, credential kind, generation,
  verification state, expiry, capability summary, and missing configured
  requirements.

Neither endpoint returns raw capabilities that reveal inaccessible private
resource names to an unauthorized client. JSON responses are versioned,
bounded, cache-controlled, and generated from the same immutable snapshot used
for enforcement.

`credential status` uses the operator view or protected local metadata. It
does not open the active secret as the invoking user.

## Failure Semantics

Use the shared stable categories:

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

Provider adapters map upstream responses into these categories. Raw upstream
messages remain redacted diagnostics. Invalid, unavailable, and inconclusive
must remain distinct.

## Implementation Order

### Slice 1: shared framework and Hugging Face

1. add the shared credential model, requirement evaluator, command helpers,
   runtime snapshot service, and adapter contract;
2. extend the existing service transaction for focused exact replacement;
3. implement the HF adapter and complete HF operation requirement map;
4. wire HF discovery, submission, approval binding, and execution rechecks;
5. replace the HF requirements profile and manual repair path;
6. add shared contract, lifecycle, process, and HF end-to-end tests; and
7. complete the local non-mutating Bob MCP validation.

Do not merge a nominally generic framework that only HF can exercise. Shared
contract tests and an in-memory fake adapter must prove provider independence.

### Slice 2: GitHub App

1. implement the GitHub App adapter over the shared contract;
2. generate complete GitHub operation permission requirements;
3. normalize installation repository selection and permissions;
4. bind GitHub plans to the effective installation generation and digest;
5. replace any duplicate GitHub credential status or repair code;
6. add App permission-change, repository-selection, suspension, refresh, and
   rollback tests; and
7. complete a non-mutating GitHub MCP read plus an approved test operation.

The second slice adds no new lifecycle state machine, generic CLI parser,
protected installer, metadata schema, or MCP filtering implementation.

## Test Strategy

### Shared contract suite

Run the same adapter tests against a fake provider, HF, and GitHub:

- bounded candidate acceptance and rejection;
- deterministic capability normalization and digesting;
- all-of and any-of requirement evaluation;
- exact resource selector matching;
- complete operation requirement coverage;
- secret-free output, errors, audit, and metrics;
- invalid, unavailable, inconclusive, expired, and valid states;
- generation binding and execution-time revocation;
- atomic activation, readiness, rollback, and interruption recovery; and
- stable text and JSON command behavior.

### Provider tests

HF uses a fake `whoami-v2` and non-mutating repository access fixtures. GitHub
uses fake App JWT, installation, permission, repository-selection, suspension,
and installation-token responses. Tests use official SDK transports where
production does; do not maintain a second mock-only HTTP implementation.

### Local process tests

Run compiled broker and stdio MCP processes against fake upstream servers.
Prove tool-list changes, pre-upstream refusal, plan binding, successful
rotation, rollback, restart persistence, and that candidate secrets never
appear in process metadata.

Live validation is non-mutating unless the human explicitly authorizes a
disposable test resource.

## Quality Gates

- generated operation requirements are current and reproducible;
- no implemented provider operation lacks a requirement;
- Go formatting, vet, race, aggregate coverage, lint, vulnerability, secret,
  and Slophammer gates pass;
- Linux systemd and macOS launchd lifecycle tests pass;
- HF and GitHub adapter contract suites pass;
- packed OpenClaw integration remains installable;
- Codex review has no P0 or P1 findings; and
- CI and local non-mutating provider smoke tests are green before release.

Mutation tooling remains available but disabled and non-blocking.

## Completion Criteria

The work is complete when:

- one shared framework owns credential commands, lifecycle, metadata,
  capability evaluation, enforcement, and tests;
- HF and GitHub contain only provider-specific credential behavior;
- HF accepts deliberately limited fine-grained tokens as explicit ceilings;
- GitHub uses App installation authority and never persists installation
  access tokens;
- every implemented operation has a validated provider requirement;
- discovery, submission, stored plans, and execution use the same snapshot;
- exact replacement and rollback work on Linux and macOS;
- old provider-specific lifecycle and manual overwrite paths are removed;
- Bob can complete the non-mutating HF MCP validation;
- GitHub MCP validation proves installation repository scoping; and
- maintained documentation describes the shipped contract instead of these
  implementation records.
