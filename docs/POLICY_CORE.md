# Policy Core

This document defines BrokerKit's shared policy model.
Provider-specific brokers register their own operations, target kinds, attrs,
and validation rules. Brokers use this core directly and do not keep local
compatibility policy engines. See [OWNERSHIP.md](OWNERSHIP.md) for the broader
BrokerKit versus broker boundary.

## Minimal Policy File

```json
{
  "rules": [
    {
      "id": "agent-a-can-run-restart",
      "effect": "allow",
      "clients": ["agent-a"],
      "operations": ["exec.command"],
      "targets": [{"kind": "user", "name": "deploy"}],
      "attrs": {
        "command_ids": ["restart-myapp"]
      }
    }
  ]
}
```

The policy file contains one top-level `rules` array. Each rule says which
client may perform which operation on which target with which attrs.

## Request Model

Every broker request is classified before policy evaluation:

```text
client
operation
target
attrs
```

The policy core does not inspect HTTP requests, Git packets, GitHub payloads,
or Unix command lines. The consuming broker must classify those inputs first.

## Effects

| Effect | Meaning |
| --- | --- |
| `allow` | The request may run without human approval. |
| `request` | The request may create a pending grant. It may not run yet. |
| `deny` | The request is refused. |

The decision engine may return `no_match` when no rule matches.

## Decision Order

Decision order is fixed:

```text
deny > active generated grant > allow > request > no_match
```

This means:

- deny rules override static allow rules
- deny rules override active grants
- active grants can allow a request only when no deny rule matches
- request rules do not allow execution
- no matching rule means deny by default

## Rule Fields

| Field | Required | Type | Meaning |
| --- | --- | --- | --- |
| `id` | Yes | string | Stable human-readable rule id. |
| `effect` | Yes | string | `allow`, `request`, or `deny`. |
| `clients` | Yes | string array | Client names or client globs. |
| `operations` | Yes | string array | Registered operation names. |
| `targets` | Yes | object array | Registered target matchers. |
| `attrs` | No | object | Attr constraints for request details. |
| `grant_policy` | Required for `request` | object | Grant bounds for requestable access. |
| `description` | No | string | Operator-facing explanation. |

Unknown fields are validation errors.

## Provider Registry

The provider registry defines:

- valid operation names
- valid target kinds
- required target fields per target kind
- valid attr names
- each operation's supported attrs
- which operations may be grantable
- the grant mode for each grantable operation
- the match semantics for each target field and attr

The core evaluator should not hard-code provider vocabulary.

Example registry shape:

```go
type Registry struct {
    Operations map[string]OperationSpec
    Targets    map[string]TargetSpec
    Attrs      map[string]AttrSpec
}
```

The initial Go API is implemented in `brokerkit/policy`. Brokers own the
registry values they pass into that package.

The registry is the only place provider vocabulary belongs. The shared policy
core must not ship built-in Hugging Face, GitHub, or Unix operation semantics.

## Targets

Targets are objects with a required `kind` field.

Common target fields may include:

- `owner`
- `name`
- `type`
- `host`

The provider registry decides which fields are valid and required.
Some target kinds may be identified by `kind` alone and have no fields.

Examples:

```json
{"kind": "repo", "type": "dataset", "owner": "osolmaz", "name": "news"}
```

```json
{"kind": "repo", "owner": "osolmaz", "name": "gh-broker"}
```

```json
{"kind": "user", "name": "deploy"}
```

## Attrs

Attrs describe the request details that matter for policy.

Examples:

```json
{"refs": ["refs/heads/main"]}
```

```json
{"paths": ["README.md", "docs/*"]}
```

```json
{"command_ids": ["restart-myapp"]}
```

The policy core uses canonical string lists at its boundary. Singleton fields
still contain a one-element list. Multi-value provider fields such as Git refs,
repository paths and provider keys stay as lists instead of being joined into an
ambiguous delimiter-based string. For `allow` and `request` rules, every
concrete value must satisfy the rule's constraint. For `deny` rules, any
matching concrete value denies the batch so a forbidden ref or path cannot be
hidden beside an allowed one. An empty list never matches. The provider
registry declares how each target field and attr is interpreted:

List values are sets for exact grant and idempotency comparisons: ordering and
duplicates do not change the classified authorization unit. Durable grants are
written as sorted, duplicate-free arrays. The grant store accepts the earlier
scalar representation when loading and rewrites it to the canonical array
schema.

- `glob` uses segment-safe glob matching; `*` does not cross `/`
- `any_glob` uses the same syntax but accepts a list when any value matches
- `path_glob` additionally accepts a complete `**` path segment
- `recursive_path_glob` accepts `**` anywhere in a relative path pattern and
  lets it cross `/`
- `path_outside_prefix` accepts concrete paths only when they remain outside
  every configured relative prefix
- `integer_maximum` treats policy values as inclusive non-negative integer
  ceilings

For predictable resource use, `path_glob` policy values are limited to 1,024
bytes and 256 path segments. Request values are limited to 4,096 bytes and 256
segments. Values beyond those limits fail closed and do not match a rule.

Generated grants compare attributes exactly by default. A provider may set an
attribute's `GrantMatch` mode when an approved value is a constraint rather
than an exact value. For example, `integer_maximum` lets an approved
`max_bytes: 10` grant authorize requests up to 10 bytes without changing exact
matching for other attributes.

A provider may set `GrantMayOmit` for a runtime attribute that does not need to
be present in every grant. Omitted attributes remain unconstrained; when the
grant includes the attribute, its exact or `GrantMatch` constraint still
applies. This choice belongs to the provider registry because only the provider
knows whether an unconstrained runtime value changes the approved authority.

This keeps typed provider parsing in the broker while making the decision
semantics reusable. For example, hf-broker parses a JSON byte count, validates
it as an integer, and passes a one-element list containing its canonical
base-10 form to brokerkit. Each operation lists the attrs it supports.

Attrs match by exact registry name. brokerkit does not apply provider aliases
such as `ref` versus `refs` or `path` versus `paths`. A broker must classify
and normalize provider input into the attr names it registered before it calls
the policy core.

## Grants

An approved grant becomes a generated allow rule. Generated rules use the same
matching semantics as static rules, but they also have runtime metadata:

- grant id
- client
- expiry time
- use budget
- status
- approved attrs
- decision-token verifier

Generated grant rules must never use wildcard clients. Raw decision tokens must
not be stored in grant/status objects or serialized grant JSON; brokers should
pass the raw token only to the approval notification path.

## Grant Policy

`request` rules must include `grant_policy`.

Each grantable operation declares a provider-owned default grant mode and may
declare a bounded set of allowed modes. `window` grants authorize an exact
classified request for a bounded time and use budget. `execution` grants
approve one exact provider-built action and are always single-use. A request
rule may contain several operations only when they resolve to one mode that
every operation allows.

Minimal example:

```json
{
  "mode": "window",
  "default_minutes": 5,
  "max_minutes": 10,
  "default_max_uses": 1,
  "max_uses": 1
}
```

The shared `window` grant mode is a short time window with a use budget.
`default_max_uses` is always a positive finite default. `max_uses` is either
a positive finite ceiling or `null`, which permits callers to request
unlimited uses only until the required expiry. Omitting a requested
`max_uses` selects the finite default; an explicit request `null` selects
unlimited use. Execution grants remain exactly single-use.

## Validation

An explicitly empty `rules` array is a valid deny-all policy. Policy loading
must reject:

- missing or null `rules`
- unknown fields
- duplicate rule ids
- unsupported effects
- unsupported operations
- unsupported target kinds
- unsupported attrs
- attrs on a rule that are not supported by every operation listed in that rule
- invalid glob patterns
- request rules without `grant_policy`
- allow or deny rules with `grant_policy`
- generated grants with wildcard clients
- overlapping request rules with different normalized grant policies when the
  core cannot prove they are disjoint

## Boundaries

The policy core does not:

- authenticate clients
- parse provider requests
- execute commands
- call GitHub or Hugging Face
- run sudo or systemd
- decide whether a Git push is a fast-forward
- inspect shell commands
- write audit logs by itself
- project provider-specific approval semantics for the shared presentation model

Those responsibilities stay with the broker using brokerkit.
