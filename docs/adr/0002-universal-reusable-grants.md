# ADR 0002: Make window grants available for every operation

- Status: Accepted
- Date: 2026-07-29

## Context

unYOLO supports two grant modes. A `window` grant authorizes matching requests
for a bounded duration and use budget. An `execution` grant authorizes one
exact immutable operation plan and is always single-use.

Provider catalogs currently assign one default mode to each operation. Hundreds
of GitHub and Hugging Face operations, plus sudo-broker's `exec.command`, are
classified as execution-only in their effective capability metadata. Agents
therefore need another approval for every matching Job launch, workflow action,
repository administration request, or cataloged command.

The shared policy registry already has separate fields for an operation's
default grant mode and allowed grant modes. That is the right model: default
behavior and supported behavior are different decisions.

## Decision

Every grantable operation will:

- default to `window` mode
- allow both `window` and `execution` modes
- retain its existing operation identity, risk, sealing, explicit-only status,
  target schema, attrs, provider executor and reconciliation behavior

Execution mode is not removed or weakened. It continues to approve one exact
provider-built plan and requires `max_uses: 1`.

Window mode provides reusable authority. Its use budget has these meanings:

- `max_uses: 1` permits one matching request within the window
- a finite value greater than one permits that many matching requests
- `max_uses: null` permits unlimited matching requests until expiry when policy
  allows an unlimited budget

Provider presets will use reusable window defaults for requestable operations.
A policy author may explicitly choose execution mode, choose a one-use window,
reduce the duration or use budget, or deny the operation.

Risk, sealing, explicit naming, and reuse remain separate concerns:

- `risk` controls presentation and reviewed policy defaults
- `sealed` keeps protected invocation input out of grants and logs, as well as
  approval messages
- `explicit_only` requires an exact operation name and prevents family-glob
  expansion
- grant mode controls whether approval covers a matching scope or one exact
  immutable plan

A matching active window grant must be considered before creating another
approval, including for sealed and explicit-only operations. Every invocation
still receives its own operation ID, idempotency key and immutable plan with a
separate use reservation. It also receives its own result and audit record.

Each reusable use reservation must be durably associated with its operation or
native protocol request identity. This makes concurrent use, restart recovery,
and ambiguous-result retention exact.

## Consequences

Agents can ask once for bounded repeated authority over any requestable
operation. Operators still choose the client, operation, target and attrs plus
the duration and use budget they are willing to delegate.

Execution mode remains available when approval must bind to one resolved plan
or one set of preconditions. Window mode becomes the ordinary default when an
operator is delegating a capability for a period of time.

The runtime must stop treating approval-required, explicit-only, or sealed
operations as requiring a fresh approval when an exact active window grant
matches. It must continue to fail closed when a plan falls outside grant scope,
a deny rule matches, a grant expires, or a use budget is exhausted.

GitHub generation, the Hugging Face catalog, and sudo's in-code descriptor must
publish both allowed modes and window as the default. Generated capability,
policy-manifest, MCP compatibility, and documentation artifacts must be
regenerated from those sources.

The pre-release V1 contracts will be replaced in place. Any state-format change
needed for operation-bound use reservations uses the repository's coordinated
fresh-state replacement. No compatibility reader, alias, dual-write path, or
migration remains afterward.
