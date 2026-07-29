---
title: Request vocabulary
description: Clients, operations, targets, and attrs, the four-part tuple every authorization decision runs on.
---

Before a broker decides anything, it reduces the incoming request to four values:

```text
client
operation
target
attrs
```

That tuple is the only thing the policy engine sees. It does not inspect HTTP requests, Git
packets, GitHub payloads, or Unix command lines, because by the time it runs, the broker has
already turned those into a tuple. Understanding the four parts is most of what you need to read
and write policy.

## Client

A client is a named identity with its own shared secret, listed in the broker's secrets file:

```text
client-name = generated-secret
```

Secrets must carry at least 32 bytes of entropy-equivalent material, and diagnostics never print
them again after setup. A client secret authorizes nothing by itself; it identifies who is asking
so policy can decide.

Client names accept globs in rule matching, so `clients: ["*"]` matches every client and
`clients: ["agent-*"]` matches a family. One place globs are refused is generated grant rules: an
approved grant is always bound to exactly one client, so a wildcard there is a validation error.

Operator identities are a separate namespace with separate secrets on a separate listener. Reusing
a client secret as an operator secret is rejected, which is the mechanism that stops an agent from
approving its own request.

## Operation

An operation is a registered name for something the broker can do, such as `git.push.append`,
`repo.contents.read`, `pull_request.create`, or `exec.command`. Names are hierarchical by
convention and exact by rule: there is no prefix matching and no wildcard expansion in the
operations list.

The provider registry is the only place operation names exist. It declares valid names, which
attrs each operation supports, whether the operation may be granted, its default mode, and its
allowed modes. Every grantable operation defaults to `window` and allows both `window` and
`execution`. The shared engine ships no built-in Hugging Face, GitHub,
or Unix semantics, so an operation the registry does not declare fails policy loading.

Operation naming carries meaning that matters when writing rules. On both Git-speaking brokers, an
update to an existing branch classifies as `git.push.force` unless the broker can prove the update
is a fast-forward. Ancestry is verified against a local commits-only mirror, so the check is cheap
even for very large repositories, but the classification is conservative: if the broker cannot
prove it, the safe name wins.

## Target

A target is an object with a required `kind` field. The registry decides which additional fields
that kind allows and requires, and some kinds are identified by `kind` alone:

```json
{ "kind": "repo", "type": "dataset", "owner": "osolmaz", "name": "news" }
{ "kind": "repo", "owner": "osolmaz", "name": "gh-broker" }
{ "kind": "user", "name": "deploy" }
```

Common fields are `owner`, `name`, `type`, and `host`, but the set is per-registry rather than
universal. `hf-broker` uses `repo`, `bucket`, and `inference` kinds; `gh-broker` uses `repo`,
`pull_request`, and `installation`; `sudo-broker` V1 has only `user`.

The registry also declares how each field matches. That is where `glob` behaviour comes from, and
it is why `owner: "osolmaz"` and `name: "*"` in a discovery rule mean something specific rather
than being a free-form pattern.

## Attrs

Attrs are the request details that matter for authorization. They are what turns "this agent may
push to this repository" into "this agent may push to branches under its own namespace, at most ten
megabytes at a time":

```json
{ "refs": ["refs/heads/main"] }
{ "paths": ["README.md", "docs/*"] }
{ "command_ids": ["restart-myapp"] }
```

Two rules about attrs cause most of the confusion, so they are worth stating plainly.

**Attr names are exact.** unYOLO applies no aliases. `ref` and `refs` are different attrs, and
so are `path` and `paths`. A broker must classify and normalize provider input into the names it
registered before calling the policy core.

**Values are always lists.** Even a single value is a one-element list. Multi-value provider fields
such as Git refs and repository paths stay as lists rather than being joined into a
delimiter-separated string, which removes a class of ambiguity around values containing the
delimiter.

For `allow` and `request` rules, every concrete value in the request must satisfy the rule's
constraint. For `deny` rules, any single matching value denies the whole batch, so a forbidden ref
cannot ride along beside allowed ones in the same push. An empty list never matches anything.

Lists behave as sets for grant and idempotency comparison, so ordering and duplicates do not change
the classified authorization unit. Durable grants are written as sorted, duplicate-free arrays.

### Matcher modes

The registry declares how each field and attr is interpreted:

| Mode | Behaviour |
| --- | --- |
| `glob` | Segment-safe glob. `*` does not cross `/`. |
| `any_glob` | Same syntax, matches when any value in the list matches. |
| `path_glob` | Adds support for a complete `**` path segment. |
| `recursive_path_glob` | `**` may appear anywhere in a relative pattern and crosses `/`. |
| `path_outside_prefix` | Accepts concrete paths only when they stay outside every configured prefix. |
| `integer_maximum` | Treats the policy value as an inclusive non-negative integer ceiling. |

Path patterns are bounded so a pathological rule cannot become a resource problem. Policy values
are limited to 1,024 bytes and 256 path segments; request values are limited to 4,096 bytes and 256
segments. Anything beyond those limits fails closed and matches no rule.

### Attrs in grants

Generated grants compare attributes exactly by default, which is usually what you want: an approved
push to `refs/heads/main` should not authorize a push to `refs/heads/release`.

Two registry settings soften that where exactness would be wrong. A provider may set an attribute's
`GrantMatch` mode when the approved value is a constraint rather than a literal, so an approved
`max_bytes: 10` grant authorizes requests up to ten bytes under `integer_maximum` while every other
attribute still matches exactly. A provider may set `GrantMayOmit` for a runtime attribute that
does not have to appear in every grant; when it is omitted the attribute is unconstrained, and when
it is present its normal constraint applies.

Both choices belong to the provider registry, because only the provider knows whether leaving a
runtime value unconstrained changes the authority a human thought they were approving.

## Putting it together

A GitHub push to a feature branch becomes this tuple:

```text
client:    agent-a
operation: git.push.fast_forward
target:    {"kind": "repo", "owner": "osolmaz", "name": "unyolo"}
attrs:     {"refs": ["refs/heads/agent-a/parser-fix"]}
```

and a rule allowing `refs/heads/agent-a/**` under `recursive_path_glob` matches it. The same push
to `refs/heads/main` produces the same client, operation, and target with a different attr value,
matches nothing, and is denied. That difference is the entire mechanism.
