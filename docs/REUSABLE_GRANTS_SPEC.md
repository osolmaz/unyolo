# Reusable grants specification

Status: accepted and implemented in this source tree.

This specification defines the grant-mode contract accepted in
[ADR 0002](adr/0002-universal-reusable-grants.md). Release artifacts published
before this change retain their earlier provider classifications.

## Minimal request policy

A request rule may omit `mode`. Every grantable operation defaults to a reusable
window grant:

```json
{
  "id": "agent-can-request-job-runs",
  "effect": "request",
  "clients": ["agent"],
  "operations": ["job.run"],
  "targets": [{"kind": "job", "owner": "osolmaz", "name": "*"}],
  "grant_policy": {
    "default_minutes": 60,
    "max_minutes": 10080,
    "request_ttl_minutes": 15,
    "default_max_uses": 25,
    "max_uses": 1000000
  }
}
```

The rule permits the agent to ask for a grant. It does not authorize a Job
until policy allows the operation directly or an operator approves a matching
grant.

A policy that requires one exact action selects execution mode explicitly:

```json
{
  "id": "agent-can-request-one-exact-job",
  "effect": "request",
  "clients": ["agent"],
  "operations": ["job.run"],
  "targets": [{"kind": "job", "owner": "osolmaz", "name": "*"}],
  "grant_policy": {
    "mode": "execution",
    "default_minutes": 5,
    "max_minutes": 5,
    "request_ttl_minutes": 15,
    "default_max_uses": 1,
    "max_uses": 1
  }
}
```

## Grant modes

Every grantable operation supports both modes.

- `window` authorizes matching classified requests until expiry. Each request
  gets its own immutable plan. Its budget may be one, finite reusable, or
  unlimited until expiry.
- `execution` authorizes one exact provider-built immutable plan. Its budget is
  exactly one.

`window` is the default. `execution` remains available through explicit policy.
The modes are authorization choices, not labels for whether the provider call
mutates state.

## Grant scope

A window grant binds temporary authority to this tuple:

```text
client
operation
target
attrs
expires_at
max_uses
```

The durable grant also records its identifier, mode, status, request identity,
reason, approval identity, timestamps, use accounting, and safe notification
metadata. It must not contain provider credentials, raw decision tokens, sealed
payloads, operation bodies, command output, or provider responses.

An execution grant additionally binds the approved immutable plan digest and
its preconditions.

## Use budgets

For window grants, `max_uses` has these meanings:

| Value | Meaning |
| --- | --- |
| `1` | One matching use during the window. |
| `2` through `1000000` | A finite reusable budget. |
| `null` | Unlimited matching uses until expiry, when policy permits it. |

An unlimited budget never removes expiry. The global finite ceiling remains
1,000,000 uses. Provider policy may impose a lower duration or use ceiling for
a deployment, target, client, or operation.

Provider presets must give requestable operations a finite reusable window
default greater than one. A policy author, caller, or operator may reduce the
approved budget to one.

Execution grants always use `max_uses: 1`. Policy parsing and authorization
validation must reject any other execution budget.

## Policy fields

`grant_policy` has these fields:

| Field | Required | Type | Meaning |
| --- | --- | --- | --- |
| `mode` | No | `window` or `execution` | Defaults to the operation's default mode, which is `window`. |
| `default_minutes` | No | positive integer | Duration used when a request omits `minutes`. |
| `max_minutes` | No | positive integer | Maximum duration a caller may request. |
| `request_ttl_minutes` | No | positive integer | Time available for the pending operator decision. |
| `default_max_uses` | No | positive integer | Finite budget used when a request omits `max_uses`. |
| `max_uses` | No | integer or `null` | Maximum budget. `null` permits an unlimited window request. |

Unknown fields are validation errors. `default_minutes` must not exceed
`max_minutes`. A finite `default_max_uses` must not exceed a finite
`max_uses`. Defaults and maxima must fit every operation ceiling in the rule.

A request rule may list several operations only when every listed operation
supports the selected mode. Its clients and targets, as well as its attrs and
grant bounds, must be valid for all listed operations. Under this contract
every grantable operation supports both modes.

## Capability descriptors

A provider capability descriptor declares:

- operation identity and revision
- target kind and attrs plus the applicable schemas
- risk and default policy effect
- explicit-only and sealed flags
- default grant mode and allowed grant modes
- request and approval time ceilings
- maximum finite window uses
- implementation and agent-facing status
- provider executor and reconciliation bindings

The normalized capability shape is:

```json
{
  "default_authorization_mode": "window",
  "authorization_modes": ["window", "execution"],
  "max_uses": 1000000
}
```

Every grantable operation must default to `window`, allow exactly `window` and
`execution`, and have a finite window ceiling of at least two. Non-grantable
operations do not declare grant modes or grant bounds.

Execution mode remains universally capped at one use. `max_uses` in a
capability descriptor is the window ceiling.

## Authorization order

The decision order remains:

```text
deny > active generated grant > allow > request > no_match
```

An active window grant matches only when all of these conditions hold:

- the authenticated client is exact
- the operation is exact
- the target fits the approved target matcher
- every classified attr fits the approved attr constraint
- the grant is active and unexpired
- the use budget has capacity
- no deny rule matches
- the current credential still covers the operation target
- provider preconditions for the invocation remain valid

`explicit_only` prevents operation-family matching. It does not prevent reuse
of an exact active window grant. `sealed` protects invocation input. It does
not force execution mode or a new approval when the public authorization tuple
matches an active window grant.

## Invocation lifecycle

A window-authorized invocation follows this lifecycle:

1. Authenticate the client.
2. Validate and classify the typed request.
3. Resolve a new immutable provider operation plan.
4. Apply deny, active-grant, allow, request, and no-match precedence.
5. Durably bind a matching grant use to the operation or native request ID.
6. Reserve authority before crossing the provider dispatch boundary.
7. Execute once and reconcile ambiguous results without blind retry.
8. Commit, release, or retain the reservation.
9. Persist the operation result and audit record.

A window grant never reuses an operation plan. It authorizes a classified
scope. Each invocation receives its own plan and preconditions.

An execution request resolves and stores its exact plan before approval. Only
that plan may execute after approval, and its one use cannot authorize a later
matching request.

## Use accounting

A reusable use reservation has a stable identity derived from the grant and
operation or native protocol request. Repeating the same request identity
returns the existing reservation. Conflicting reuse fails closed.

The store must apply these transitions atomically:

```text
available -> reserved -> committed
                      -> released
                      -> retained
```

A proven failure before provider dispatch releases the use. Crossing the
provider dispatch boundary consumes the use even when the provider reports a
failure. An unknown result retains the use and prevents unsafe automatic
retry. Recovery settles the same reservation. It must not infer ownership from
aggregate counters alone.

Concurrent reservations must never exceed the finite use budget. Expiry or
revocation prevents new reservations but does not erase reservations that may
already have crossed the provider boundary.

## Cancellation and revocation

Canceling a pending operation cancels its pending approval when no active grant
exists.

Canceling one operation using an active window grant releases only that
operation's reservation when dispatch has not begun. It does not revoke the
window grant. Grant revocation is a separate explicit client or operator
action.

Canceling the only operation bound to a pending execution grant may cancel that
one approval request.

## Sealed and explicit-only operations

Sealed operations support both grant modes. A reusable window grant contains
only the public authorization scope. Each invocation supplies and validates
its own sealed payload.

Every public fact that changes delegated authority or cost must be represented
in the target or attrs. When policy intentionally leaves a field unconstrained,
the approval presentation must say so.

Explicit-only operations must be named exactly in policy and grant requests.
They cannot enter through operation-family globs. An exact active window grant
may authorize repeated uses.

## Approval presentation

An approval must state the mode and authority being delegated.

A window presentation uses wording such as:

> Allow agent to launch up to 25 matching Jobs during the next 24 hours.

An execution presentation uses wording such as:

> Allow this exact Job launch once.

At minimum, approval shows the client, mode, operation and target. It also
shows constrained attrs, duration, maximum uses, risk and warnings, the reason
and pending decision expiry. It must identify intentionally unconstrained
authority.

For a Job launch, provider presentation should also show bounded public facts
such as hardware and runtime, namespace and mounts, plus secret names. Secret
values and sealed payloads remain excluded. Credentials and raw commands that
may contain secrets remain excluded as well.

## Provider requirements

GitHub generation must default every grantable operation to window and publish
both allowed modes. Generated capability and MCP compatibility artifacts must
preserve execution support.

Hugging Face must permit both modes for all grantable operations. This covers
Jobs, scheduled Jobs, endpoints, Sandboxes and Spaces. It also covers
repository, bucket and organization operations. Sealed Job and credential
operations keep sealed payload handling on every invocation.

sudo-broker must permit both modes for `exec.command` and default to window.
Window matching remains bound to the exact catalog command ID, target user,
and approved typed argument constraints. The privileged helper receives one
immutable execution plan per invocation and keeps replay protection.

## Validation

Validation must reject:

- a request rule without `grant_policy`
- `grant_policy` on an `allow` or `deny` rule
- an unsupported mode
- an execution budget other than one
- zero, negative or excessive finite window budgets
- defaults above policy or operation maxima
- reusable scope wider than its request rule
- wildcard clients on generated grants
- family expansion of an explicit-only operation
- an operation plan outside an active window grant scope
- more reservations than the approved budget
- reservation identity reuse for a different operation
- unknown fields in policy and capability records, grant records or reservation
  records

Catalog-wide validation must prove that every grantable operation defaults to
window and supports both window and execution.

## State and versioning

The replacement keeps existing V1 identifiers and changes them in place.
Any reservation schema change uses fresh grant and plan state under the host's
state-replacement process. No dual reader, converter, mode alias, or
compatibility path is allowed.

## Boundaries

Execution mode remains part of this contract. The change does not make any
operation statically allowed, weaken deny precedence, expose credentials,
retry ambiguous mutations, or let grants widen provider vocabulary. It makes
reusable window grants available by default for every grantable operation.
