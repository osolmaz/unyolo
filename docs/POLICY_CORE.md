# Policy Core

This document defines the shared policy model brokerkit should provide.
Provider-specific brokers register their own operations, target kinds, attrs,
and validation rules. The intended migration is cutover: brokers should use this
core directly instead of keeping local compatibility policy engines alive.
See [OWNERSHIP.md](OWNERSHIP.md) for the broader brokerkit versus broker
boundary.

## Minimal Policy File

```json
{
  "rules": [
    {
      "id": "bob-can-run-restart",
      "effect": "allow",
      "clients": ["bob"],
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
- attr type rules
- which attrs are relevant to which operations
- which operations may be grantable

The core evaluator should not hard-code provider vocabulary.

Example registry shape:

```go
type Registry struct {
    Operations map[string]OperationSpec
    Targets    map[string]TargetSpec
    Attrs      map[string]AttrSpec
}
```

The exact Go API is intentionally not fixed yet.

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

The provider registry decides whether each attr is a string, number, boolean,
or list constraint.

## Grants

An approved grant becomes a generated allow rule. Generated rules use the same
matching semantics as static rules, but they also have runtime metadata:

- grant id
- client
- expiry time
- use budget
- status
- approved attrs

Generated grant rules must never use wildcard clients.

## Grant Policy

`request` rules must include `grant_policy`.

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

The first shared grant mode should be `window`: a short time window with a use
budget. Execution-plan grants can come later.

## Validation

Policy loading must reject:

- missing `rules`
- unknown fields
- duplicate rule ids
- unsupported effects
- unsupported operations
- unsupported target kinds
- unsupported attrs
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
- compose provider-specific approval messages

Those responsibilities stay with the broker using brokerkit.
