# Universal reusable grants implementation plan

Status: planned.

This plan implements [ADR 0002](adr/0002-universal-reusable-grants.md) and the
[reusable grants specification](REUSABLE_GRANTS_SPEC.md). Execution mode
remains part of the contract and remains exact and single-use.

## Outcome

Every grantable GitHub, Hugging Face, and sudo operation defaults to window
mode and supports both window and execution grants. An approved window grant
can authorize repeated matching Agent V1 or native protocol requests until its
time or use budget ends. An execution grant authorizes one exact immutable plan
once.

The implementation is complete only when one approved window grant is reused
for multiple real operations in each provider's target environment, with
correct use accounting, denial, expiry and revocation. Cancellation, audit and
restart recovery must also remain correct.

## Current state

The checked-in catalogs currently classify 926 operations with a one-use
execution ceiling:

| Provider | Single-use operations | Agent-facing |
| --- | ---: | ---: |
| GitHub | 786 | 519 |
| Hugging Face | 139 | 139 |
| sudo | 1 | 1 |

The shared policy registry already models one default grant mode plus a bounded
set of allowed modes. Hugging Face projects both modes into part of its core
registry, but its catalog defaults, capability validation, provider plan
preparation, and active-grant reuse still force execution behavior. GitHub
projects only the catalog's single mode. sudo registers execution only.

The shared grant store already has finite and unlimited budgets. It can reserve
and commit a use, or release or retain it. Its aggregate reservation state does
not identify which concurrent operation owns each reusable reservation, so
restart recovery must be made operation-specific.

## Boundaries

This work changes approval reuse. It does not:

- make a requestable operation statically allowed
- turn operator-only, internal, blocked or default-deny operations into
  agent-facing operations
- alter execution mode, which remains exact and single-use
- weaken exact execution-plan approval
- weaken deny precedence, explicit-only matching or sealed input handling
- weaken credential checks, provider preconditions or audit redaction
- add generic provider proxying or arbitrary sudo command execution
- add compatibility readers, aliases, dual writes or state migrations

Mutation tooling remains disabled unless explicitly requested.

## Contract changes

### Capability descriptor

Replace the singular effective-mode declaration with:

```json
{
  "default_authorization_mode": "window",
  "authorization_modes": ["window", "execution"],
  "max_uses": 1000000
}
```

`max_uses` is the finite window ceiling. Execution remains universally fixed at
one use. Non-grantable operations declare neither modes nor grant bounds.

Keep risk, default policy effect, explicit-only, sealed, internal,
agent-facing, schemas, executor binding, reconciliation binding, and lifecycle
TTLs independent of grant mode.

### Policy

Keep `grant_policy.mode`. When omitted, it resolves to the operation's default
mode. Every grantable operation defaults to window and allows both values.

Window policies accept finite or unlimited use ceilings within provider
bounds. Execution policies require both default and maximum uses to equal one.

Request rules containing several operations remain valid only when every
operation supports the selected mode and the remaining rule schema applies to
every operation.

### Runtime

Keep one Agent V1 lifecycle. Authorization order remains:

```text
deny > active grant > allow > request > no_match
```

Adapters that require approval must check for a matching active window grant
before creating another approval. The same rule applies to explicit-only and
sealed adapters. Direct static allow remains unavailable where provider safety
requires approval.

Every window-authorized invocation gets a new immutable plan. Execution-mode
approval remains bound to its original immutable plan.

## Workstream 1: Shared capability and policy core

1. Extend `operation/capability.Descriptor` with a default mode and allowed-mode
   list. Replace the singular catalog field in place.
2. Validate that every grantable descriptor defaults to `window`, allows
   exactly `window` and `execution`, and has a finite window ceiling of at least
   two.
3. Preserve validation that execution grants have exactly one use.
4. Remove validation that sealed operations must be execution-only.
5. Keep explicit-only operations incompatible with family globs.
6. Project descriptor mode lists and window ceilings into
   `authorization/policy.OperationSpec`.
7. Keep policy normalization and overlap checks mode-aware.
8. Add catalog-wide tests that fail when any grantable operation lacks either
   mode or defaults to execution.
9. Update capability schemas, projections, generated documentation, and
   compatibility manifests from the source definitions.

## Workstream 2: Durable use identity

1. Add a normalized grant-use record keyed by grant ID and operation or native
   request ID.
2. Store reservation state and revision with timestamps plus terminal
   settlement, without provider payloads.
3. Make reservation creation atomic with the grant budget check.
4. Make repeated reservation of the same request identity idempotent.
5. Reject the same identity when it is presented for a different grant or
   operation.
6. Commit and release, or retain, by use identity instead of decrementing an
   anonymous aggregate reservation.
7. Keep aggregate used and reserved counts transactionally consistent for
   status and operator presentation.
8. Recover each executing operation through its own reservation record. Never
   infer its settlement from another operation's used count.
9. Prevent new reservations after expiry or revocation while allowing existing
   reservations to settle.
10. Suspend unsafe further use when an ambiguous provider result requires
    review, without losing the retained reservation.

The state schema is replaced in V1 with fresh grant and plan state. The previous
state is archived for rollback with the previous binary.

## Workstream 3: Agent runtime

1. Consolidate submission authorization so active grant matching happens before
   a new approval request for every adapter.
2. Treat `RequiresApproval` as preventing direct static execution, not as
   preventing active window-grant reuse.
3. Prepare a fresh plan for each use and prove its authorization projection
   fits the active window grant.
4. Bind the grant-use identity and immutable plan to the operation before
   dispatch.
5. Keep execution-mode plans bound to the one pending approval that created
   them.
6. Make operation cancellation mode-aware:
   - cancel a pending approval when no active grant exists
   - release an undispatched window reservation
   - never revoke a reusable window grant merely because one operation is
     canceled.
7. Keep grant revocation as a separate explicit action.
8. Preserve stable idempotency, no-blind-retry behavior, and provider-specific
   ambiguity reconciliation.

## Workstream 4: Hugging Face

1. Change every grantable catalog entry to default window and allow both modes.
2. Give every requestable operation a reusable window ceiling. Preserve lower
   reviewed defaults where desired, but no default may be one.
3. Keep execution mode available in explicit policy.
4. Remove the sealed-implies-execution restriction from catalog validation.
5. Permit active window-grant reuse in provider preparation for Jobs,
   scheduled Jobs, endpoints, Sandboxes and Spaces. Cover repositories,
   buckets, collections, organizations and provisioning. Cover SCIM and
   service accounts plus webhooks.
6. Audit each operation's policy projection. Every public field that changes
   authority or cost must appear in its target or attrs or be visibly marked
   unconstrained.
7. For `job.run` and `job.uv.run`, cover hardware, runtime, namespace, mounts,
   secret names, and other public launch constraints without exposing sealed
   values.
8. Preserve one sealed payload and one immutable plan per Job invocation.
9. Update `request-all-agent-operations` so every requestable operation gets a
   reusable window default and policy can still choose execution.
10. Regenerate capabilities and MCP compatibility, policy manifests and skills,
    plus user documentation.

## Workstream 5: GitHub

1. Change the source generator so every grantable operation defaults to window
   and allows both modes.
2. Do not hand-edit the 1,436-entry generated catalog.
3. Preserve generated risk, explicit-only, sealed and target metadata. Preserve
   credential and binding metadata plus the default policy effect.
4. Give every requestable operation a reusable window ceiling greater than one.
5. Keep exact execution mode for precondition-bound actions such as an exact
   administrative merge when policy selects it.
6. Audit target and attr projection for operations previously protected by
   execution-only classification.
7. Regenerate the operation catalog, capability reference, MCP compatibility,
   target registry outputs, policy manifests, and drift fixtures.

## Workstream 6: sudo

1. Change `exec.command` to default window and allow both modes.
2. Keep matching bound to one exact command ID, target user, and approved typed
   argument constraints.
3. Create one immutable privileged-helper plan and execution ID for every use.
4. Keep helper-side replay protection and trusted-path revalidation.
5. Verify that cancellation, timeout, helper rejection, and ambiguous helper
   disconnect settle only the corresponding reservation.
6. Update the sudo README, operation model and threat model. Update its examples
   and skill as well.

## Workstream 7: Approval and client surfaces

1. Show grant mode prominently in Operator V1 and Telegram presentation.
2. Describe window authority through its duration and use count, operation and
   scope.
3. Describe execution authority as one exact action.
4. Show intentionally unconstrained attrs instead of silently omitting them.
5. Keep operator constraint reduction for duration and use count.
6. Keep execution use count immutable at one.
7. Ensure CLI and MCP schemas describe `max_uses` for every operation capable of
   window grants.
8. Keep explicit grant lifecycle tools optional for ordinary Agent V1 calls.
   Submitting a requestable operation may create the default window approval.

## Verification

### Shared conformance

Test these cases in provider-neutral packages:

- every grantable descriptor defaults to window and allows both modes
- execution rejects a use count other than one
- window accepts one-use and finite reusable budgets plus allowed unlimited
  budgets
- deny overrides an active grant
- exact client and operation plus target and attr scope is preserved
- concurrent reservations stop at the finite budget
- same request identity does not consume twice
- conflicting identity reuse fails
- crash recovery settles the owning reservation
- expiry and revocation prevent new uses
- ambiguous execution retains authority without blind retry
- canceling one operation leaves its reusable window grant active

### Provider tests

Hugging Face must prove:

- one approved `job.run` window grant launches two distinct matching Jobs
- one explicit execution grant launches only its exact Job once
- a different hardware, namespace, mount or secret-name scope is refused
- sealed values never enter grant, operation, presentation, audit or logs

GitHub must prove:

- representative routine and administrative operations reuse one matching
  window grant, including explicit-only, sealed and destructive operations
- exact execution mode still enforces immutable-plan preconditions
- generated output contains both modes and window defaults for every grantable
  operation

sudo must prove:

- one approved window grant runs the same harmless catalog command twice
- a different command, target user or disallowed argument is refused
- one execution grant runs its exact command once
- helper restart and ambiguous disconnect preserve correct use accounting

### Real acceptance

Use disposable real provider resources and harmless operations. Paid Hugging
Face compute requires the repository's paid-compute approval process before a
real Job launch. Mocks, unit tests and builds support the result. Health checks
also help, but none replace the real agent-visible workflows.

Run the repository checks before completion:

```sh
go fmt ./...
go vet ./...
go test ./...
golangci-lint run
slophammer-go check .
```

Also run generated-artifact drift checks, web documentation checks, component
release checks, secret-scanning tests, state restart tests, and disposable-host
systemd acceptance.

## Delivery order

1. Land the shared contract and conformance tests.
2. Land operation-bound use accounting and runtime reuse.
3. Convert Hugging Face and verify Job behavior.
4. Convert GitHub generation and regenerate all artifacts.
5. Convert sudo and verify the privileged helper path.
6. Update every maintained specification and website page, provider README and
   skill, plus each example and generated capability reference.
7. Deploy a complete signed bundle to a disposable host and run real Agent V1
   approval/reuse workflows.
8. Release each affected component normally.
9. Activate the signed bundle locally only after explicit deployment approval.

## Completion criteria

The work is complete when:

- no grantable operation defaults to execution
- every grantable operation advertises both modes
- execution mode remains exact and one-use
- every requestable operation has a reusable window default
- one approved window grant is reused successfully in real Hugging Face and
  GitHub workflows plus a real sudo workflow
- all use accounting survives retry and concurrency, including ambiguity and
  restart
- generated artifacts and maintained documentation agree with runtime behavior
- full repository checks pass
- no compatibility path or stale execution-only catalog classification remains
