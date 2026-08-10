---
title: Policy schema
description: Field reference for policy rules, matching, grants, and validation errors.
---

This reference covers every field in `scope.json` and `policy.json`. Read the
[policy engine](/docs/concepts/policy) for decision behavior or
[write a policy](/docs/guides/write-a-policy) for a complete example.

## Document

```json
{ "rules": [ /* zero or more rule objects */ ] }
```

`rules` is the only top-level key. It is required and may not be null. An explicitly empty array is
valid and denies everything.

## Rule object

| Field | Required | Type | Notes |
| --- | --- | --- | --- |
| `id` | Yes | string | Unique across the file. Appears in `matched_rule_ids` in audit records. |
| `effect` | Yes | string | `allow`, `request`, or `deny`. |
| `clients` | Yes | string array | Client names or globs. Never a wildcard on a generated grant. |
| `operations` | Yes | string array | Exact registered operation names. No prefix or wildcard matching. |
| `targets` | Yes | object array | Each requires `kind`; other fields come from the registry. |
| `attrs` | No | object | Constraint values, always lists. |
| `grant_policy` | For `request` | object | Required on `request`, forbidden on `allow` and `deny`. |
| `description` | No | string | Operator-facing explanation. |

Unknown fields are validation errors.

## Effects

| Effect | Meaning |
| --- | --- |
| `allow` | May run without human approval. |
| `request` | May create a pending grant. May not run yet. |
| `deny` | Refused. |

The engine also returns `no_match` when nothing matches, which denies.

Decision order is fixed and independent of order in the file:

```text
deny > active generated grant > allow > request > no_match
```

## Targets

A target is an object with a required `kind`. The provider registry declares which additional
fields the kind allows and requires, and some kinds are identified by `kind` alone.

```json
{ "kind": "repo", "type": "dataset", "owner": "osolmaz", "name": "news" }
{ "kind": "repo", "owner": "osolmaz", "name": "gh-broker" }
{ "kind": "user", "name": "deploy" }
{ "kind": "bucket", "namespace": "osolmaz", "name": "artifacts" }
{ "kind": "pull_request", "owner": "osolmaz", "repo": "unyolo", "number": 123 }
```

Common fields are `owner`, `name`, `type`, and `host`, but the valid set is per-registry rather
than universal.

## Attrs

Attr values are always lists, even for a single value. Names are exact, with no aliasing between
`ref` and `refs` or between `path` and `paths`.

```json
{ "refs": ["refs/heads/main"] }
{ "paths": ["README.md", "docs/*"] }
{ "command_ids": ["restart-myapp"] }
{ "max_bytes": ["10485760"] }
```

Matching rules differ by effect. For `allow` and `request`, every concrete value in the request
must satisfy the constraint. For `deny`, any single matching value denies the whole batch. An empty
list never matches.

Lists behave as sets for grant and idempotency comparison, so order and duplicates do not change
the classified authorization unit. Durable grants are written as sorted, duplicate-free arrays, and
the grant store accepts the earlier scalar representation on load and rewrites it to the canonical
array schema.

### Matcher modes

| Mode | Behaviour |
| --- | --- |
| `glob` | Segment-safe glob. `*` does not cross `/`. |
| `any_glob` | Same syntax; matches when any value in the list matches. |
| `path_glob` | Adds a complete `**` path segment. |
| `recursive_path_glob` | `**` may appear anywhere in a relative pattern and crosses `/`. |
| `path_outside_prefix` | Accepts concrete paths only when they stay outside every configured relative prefix. |
| `integer_maximum` | Treats the policy value as an inclusive non-negative integer ceiling. |

### Bounds

| Scope | Byte limit | Segment limit |
| --- | --- | --- |
| `path_glob` policy value | 1,024 | 256 |
| `path_glob` request value | 4,096 | 256 |

Values beyond these limits fail closed and match no rule.

### Grant matching

Generated grants compare attributes exactly by default. Two registry settings change that per
attribute.

`GrantMatch` applies when an approved value is a constraint rather than a literal. An approved
`max_bytes: 10` under `integer_maximum` authorizes requests up to ten bytes while every other
attribute still matches exactly.

`GrantMayOmit` marks a runtime attribute that need not appear in every grant. When omitted the
attribute is unconstrained; when present its exact or `GrantMatch` constraint applies.

## Grant policy

```json
{
  "mode": "window",
  "default_minutes": 5,
  "max_minutes": 10,
  "default_max_uses": 1,
  "max_uses": 3
}
```

| Field | Notes |
| --- | --- |
| `mode` | `window` or `execution`. It defaults to `window`; every grantable operation allows both. |
| `default_minutes` | Duration used when the caller does not ask for one. |
| `max_minutes` | Ceiling on requested duration. |
| `default_max_uses` | Always a positive finite default. |
| `max_uses` | A positive finite ceiling no greater than `1000000`, or `null` to permit unlimited uses within the window. |

A `window` grant authorizes an exact classified request for a bounded time and use budget. Every
grantable operation defaults to this mode, and a provider may impose a lower operation-specific
ceiling. An `execution` grant approves one exact provider-built action and is always single-use.

A rule may list several operations only when they resolve to one mode that every listed operation
allows.

## Generated grant metadata

An approved grant becomes a generated allow rule carrying a grant ID, the client, an expiry time, a
use budget, a status, the approved attrs, and a decision-token verifier. Raw decision tokens are
never stored in grant or status objects or serialized into grant JSON.

## Validation errors

Policy loading rejects:

- missing or null `rules`
- unknown fields
- duplicate rule IDs
- unsupported effects
- unsupported operations
- unsupported target kinds
- unsupported attrs
- attrs on a rule that are not supported by every operation the rule lists
- invalid glob patterns
- `request` rules without `grant_policy`
- `allow` or `deny` rules that carry `grant_policy`
- generated grants with wildcard clients
- overlapping request rules with different normalized grant policies when the core cannot prove
  they are disjoint

## Worked examples

Allow reads and append pushes on one dataset:

```json
{
  "id": "allow-scraped-news",
  "effect": "allow",
  "clients": ["agent-a"],
  "operations": ["repo.contents.read", "git.fetch", "git.push.append"],
  "targets": [
    { "kind": "repo", "type": "dataset", "owner": "osolmaz", "name": "scraped-news" }
  ]
}
```

Allow pushes only to an agent's own branch namespace:

```json
{
  "id": "agent-a-push-own-branches",
  "effect": "allow",
  "clients": ["agent-a"],
  "operations": ["git.push.fast_forward"],
  "targets": [{ "kind": "repo", "owner": "osolmaz", "name": "unyolo" }],
  "attrs": { "refs": ["refs/heads/agent-a/**"] }
}
```

Require approval for a history rewrite, capped at ten minutes and one use:

```json
{
  "id": "request-scraped-news-force",
  "effect": "request",
  "clients": ["agent-a"],
  "operations": ["git.push.force"],
  "targets": [
    { "kind": "repo", "type": "dataset", "owner": "osolmaz", "name": "scraped-news" }
  ],
  "grant_policy": {
    "mode": "window",
    "default_minutes": 5,
    "max_minutes": 10,
    "default_max_uses": 1,
    "max_uses": 1
  }
}
```

Deny an operation everywhere, overriding grants:

```json
{
  "id": "deny-ref-deletion-everywhere",
  "effect": "deny",
  "clients": ["*"],
  "operations": ["git.ref.delete"],
  "targets": [{ "kind": "repo" }],
  "description": "Deletion is never delegated."
}
```

Run one cataloged command as one Unix user:

```json
{
  "id": "agent-a-can-run-restart",
  "effect": "allow",
  "clients": ["agent-a"],
  "operations": ["exec.command"],
  "targets": [{ "kind": "user", "name": "deploy" }],
  "attrs": { "command_ids": ["restart-myapp"] }
}
```
