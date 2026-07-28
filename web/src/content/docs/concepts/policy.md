---
title: Policy engine
description: Effects, decision order, rule fields, the provider registry, and validation rules.
---

The policy engine decides whether a classified request may run. It is shared by every broker, it
carries no provider vocabulary of its own, and it is deliberately small. This page covers how it
decides, what a rule may contain, and what makes a policy file invalid.

## Minimal policy file

A policy is one top-level `rules` array:

```json
{
  "rules": [
    {
      "id": "agent-a-can-run-restart",
      "effect": "allow",
      "clients": ["agent-a"],
      "operations": ["exec.command"],
      "targets": [{ "kind": "user", "name": "deploy" }],
      "attrs": {
        "command_ids": ["restart-myapp"]
      }
    }
  ]
}
```

Each rule says which client may perform which operation on which target with which attrs. The file
is the authorization source of truth, loaded at startup. `hf-broker` and `gh-broker` call it
`scope.json`; `sudo-broker` calls it `policy.json`.

## Effects and decision order

Three effects exist, and the engine can also return a fourth outcome when nothing matches:

| Effect | Meaning |
| --- | --- |
| `allow` | The request may run without human approval. |
| `request` | The request may create a pending grant. It may not run yet. |
| `deny` | The request is refused. |
| `no_match` | Returned by the engine when no rule matches. Denies. |

Order of evaluation is fixed and does not depend on where rules appear in the file:

```text
deny > active generated grant > allow > request > no_match
```

Four consequences follow, and they are the properties worth internalising. Deny rules override
static allow rules. Deny rules also override active grants, so a human approval cannot resurrect
something a deny rule forbids. Request rules never permit execution by themselves. No matching rule
means deny.

## Rule fields

| Field | Required | Type | Meaning |
| --- | --- | --- | --- |
| `id` | Yes | string | Stable human-readable rule ID, recorded in audit entries. |
| `effect` | Yes | string | `allow`, `request`, or `deny`. |
| `clients` | Yes | string array | Client names or client globs. |
| `operations` | Yes | string array | Registered operation names. |
| `targets` | Yes | object array | Registered target matchers. |
| `attrs` | No | object | Attr constraints for request details. |
| `grant_policy` | For `request` | object | Grant bounds for requestable access. |
| `description` | No | string | Operator-facing explanation. |

Unknown fields are validation errors rather than ignored keys.

## Grant policy

A `request` rule must carry `grant_policy`, and an `allow` or `deny` rule must not:

```json
{
  "mode": "window",
  "default_minutes": 5,
  "max_minutes": 10,
  "default_max_uses": 1,
  "max_uses": 1
}
```

Each grantable operation declares a provider-owned default mode and may declare a bounded set of
allowed modes. A `window` grant authorizes an exact classified request for a bounded time and use
budget. An `execution` grant approves one exact provider-built action and is always single-use. A
request rule may list several operations only when they resolve to one mode that every listed
operation allows.

`default_max_uses` is always a positive finite default. `max_uses` is either a positive finite
ceiling or `null`, and `null` lets callers request unlimited uses bounded only by the required
expiry. Omitting a requested `max_uses` selects the finite default; explicitly requesting `null`
selects unlimited use within the window.

Grant mode is authorization metadata rather than a transport selector. Agent-facing MCP and CLI
calls always submit through Agent Operations V1 regardless of mode, and a matching active window
grant authorizes the stored operation and reserves one use atomically during admission or
execution.

## The provider registry

The registry is where provider vocabulary lives, and it is the only place it may live. It defines
valid operation names, valid target kinds, required target fields per kind, valid attr names, the
attrs each operation supports, which operations may be granted, the grant mode for each grantable
operation, and the match semantics for every field and attr.

```go
type Registry struct {
    Operations map[string]OperationSpec
    Targets    map[string]TargetSpec
    Attrs      map[string]AttrSpec
}
```

The Go API lives in `brokerkit/policy`, and brokers supply the registry values they pass into it.
The evaluator hard-codes no provider vocabulary, which is what keeps the shared core honest.

## Generated grants

An approved grant becomes a generated allow rule. It uses the same matching semantics as a static
rule and adds runtime metadata: a grant ID, the client, an expiry time, a use budget, a status, the
approved attrs, and a decision-token verifier.

Two constraints apply specifically to generated rules. They may never use wildcard clients. Raw
decision tokens must never be stored in grant or status objects or serialized into grant JSON; a
broker passes the raw token only to the approval notification path.

## Validation

An explicitly empty `rules` array is valid and denies everything. Policy loading rejects:

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

The rule about attrs and operations is the one that surprises people. If a rule lists two
operations and an attr that only one of them supports, the rule is invalid. Split it into two
rules.

## Engine boundaries

The policy core does not authenticate clients, parse provider requests, execute commands, call
GitHub or Hugging Face, run sudo or systemd, decide whether a Git push is a fast-forward, inspect
shell commands, write audit logs, or project provider-specific approval semantics into the shared
presentation model. Those all belong to the broker using it.

The fast-forward example is the useful one to remember. Deciding whether a push is append-only
requires reading Git objects, which is provider work. The broker does that, produces the operation
name `git.push.append` or `git.push.force`, and only then asks the engine anything.

## Native Git transactions

A receive-pack request is one authorization transaction. Provider adapters classify every ref
before any bytes go upstream. A deny rejects the whole batch. Requestable refs produce a single
approval bound to the exact body digest and ordered command set.

The original Git request waits for the durable decision, reacquires any provider lock,
revalidates policy and repository state, reserves one use, and only then forwards the unchanged
body. Atomic and multi-ref pushes are never split into separately authorized updates, so a partial
result is not a state the design allows.
