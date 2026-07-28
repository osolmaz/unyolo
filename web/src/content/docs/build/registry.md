---
title: Provider registry
description: Declaring operations, target kinds, and attrs, and choosing the match semantics for each.
---

The registry is where your provider's vocabulary lives, and it is the only place it may live. The
shared policy core ships no built-in GitHub, Hugging Face, or Unix semantics, so an operation your
registry does not declare fails policy loading rather than silently matching nothing.

## Shape

```go
type Registry struct {
    Operations map[string]OperationSpec
    Targets    map[string]TargetSpec
    Attrs      map[string]AttrSpec
}
```

The Go API is in `unyolo/policy`. Your broker supplies the values it passes in.

The registry defines valid operation names, valid target kinds, the required target fields per
kind, valid attr names, the attrs each operation supports, which operations may be granted, the
grant mode for each grantable operation, and the match semantics for every target field and attr.

## Operations

Names are hierarchical by convention and exact by rule. There is no prefix matching and no wildcard
expansion in a policy rule's operations list, so `git.push` does not cover `git.push.force`.

Choose names that make a policy file readable on its own. `gh-broker` uses `pull_request.create`,
`contents.read`, and `git.push.fast_forward`. The distinction between `git.push.fast_forward` and
`git.push.force` is doing real work: a reviewer scanning a policy can see which one an agent has.

Declare grantability per operation. A grantable operation names its default grant mode and may name
the bounded set of modes it allows. `window` authorizes an exact classified request for a bounded
time and use budget. `execution` approves one exact provider-built action and is always single-use.

## Target kinds

A target is an object with a required `kind`. Your registry decides which other fields that kind
allows and requires. Some kinds are identified by `kind` alone.

```json
{ "kind": "repo", "owner": "osolmaz", "name": "unyolo" }
{ "kind": "pull_request", "owner": "osolmaz", "repo": "unyolo", "number": 123 }
{ "kind": "user", "name": "deploy" }
```

Common fields across the shipped brokers are `owner`, `name`, `type`, and `host`, but nothing about
that set is universal. Pick fields that a human writing policy would recognise from your provider's
own vocabulary.

## Attrs

Attrs are the request details that matter for authorization. They turn "this agent may push to this
repository" into "this agent may push to branches under its own namespace".

Two constraints apply to every attr and cause most of the confusion when they are missed.

Names are exact. unYOLO applies no aliases, so `ref` and `refs` are different attrs. Your
classifier must normalize provider input into the exact names you registered before calling the
policy core.

Values are always lists, even for a single value. Multi-value provider fields such as Git refs stay
as lists rather than being joined into a delimiter-separated string. Lists behave as sets for grant
and idempotency comparison, so ordering and duplicates do not change the classified authorization
unit.

## Match semantics

Each field and attr declares how it is interpreted:

| Mode | Behaviour |
| --- | --- |
| `glob` | Segment-safe glob. `*` does not cross `/`. |
| `any_glob` | Same syntax; matches when any value in the list matches. |
| `path_glob` | Adds a complete `**` path segment. |
| `recursive_path_glob` | `**` may appear anywhere in a relative pattern and crosses `/`. |
| `path_outside_prefix` | Accepts concrete paths only when they stay outside every configured prefix. |
| `integer_maximum` | Treats the policy value as an inclusive non-negative integer ceiling. |

Path patterns are bounded so a pathological rule cannot become a resource problem. Policy values
are capped at 1,024 bytes and 256 path segments, request values at 4,096 bytes and 256 segments,
and anything beyond fails closed.

## Grant matching

Generated grants compare attributes exactly by default, which is usually right: an approved push to
`refs/heads/main` should not authorize a push to `refs/heads/release`.

Two settings soften that where exactness would be wrong.

`GrantMatch` applies when the approved value is a constraint rather than a literal. An approved
`max_bytes: 10` under `integer_maximum` authorizes requests up to ten bytes while every other
attribute still matches exactly.

`GrantMayOmit` marks a runtime attribute that need not appear in every grant. When omitted, the
attribute is unconstrained; when present, its normal constraint applies.

Both choices belong to you rather than to the framework, because only your broker knows whether
leaving a runtime value unconstrained changes the authority a human thought they were approving.

## Typed parsing stays in your broker

The policy core uses canonical string lists at its boundary, which means you do the typed parsing.
`hf-broker` parses a JSON byte count, validates it as an integer, and passes a one-element list
containing its canonical base-10 form. That keeps provider type rules in the provider and keeps the
decision semantics reusable.

## MCP projections

If your broker exposes MCP tools, you also own the canonical-to-MCP JSON Pointer projections for
public fields that collide with transcript redactors, applied in both directions. You own the
classification of canonical secret inputs and their sealed or credential-slot boundary.

The line is firm. A public key may be projected to `public_material`; an access token may not be
renamed around secret handling.

## Validation you get for free

Policy loading rejects unknown fields, duplicate rule IDs, unsupported effects, unsupported
operations, unsupported target kinds, unsupported attrs, attrs a rule's operations do not all
support, invalid glob patterns, `request` rules without `grant_policy`, `allow` or `deny` rules
that carry one, and generated grants with wildcard clients.

Ship registry conformance fixtures alongside your registry. The framework provides the mechanism;
proving your declared vocabulary matches what your classifier actually emits is your test.
