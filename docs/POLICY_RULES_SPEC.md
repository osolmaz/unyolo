# Policy Rules Specification

Status: draft for vNext, 2026-07-08.

This specification defines the cutover policy-rule format for hf-broker.
It replaces the exact-entry v1 `scope.json` model with a small typed rule
system that supports wildcards, repo listing, requestable approvals, and
generated temporary grants.

The current v1 `repos[]` and `buckets[]` schema remains valid only until
this format is implemented. After cutover, runtime policy loading accepts
only `version: 2`. A one-shot converter may translate v1 files, but the
broker does not keep dual runtime formats.

## Smallest Valid File

```json
{
  "version": 2,
  "rules": [
    {
      "id": "list-visible-repos",
      "effect": "allow",
      "clients": ["local-agent"],
      "operations": ["repo.list", "repo.metadata.read"],
      "targets": [
        {"kind": "repo", "type": "*", "owner": "*", "name": "*"}
      ]
    }
  ]
}
```

This lets `local-agent` list repositories and read repository metadata.
It does not allow file contents, git fetch, git push, settings changes,
member changes, or deletion.

## Full Example

```json
{
  "version": 2,
  "rules": [
    {
      "id": "list-all-repos",
      "effect": "allow",
      "clients": ["local-agent"],
      "operations": ["repo.list", "repo.metadata.read"],
      "targets": [
        {"kind": "repo", "type": "*", "owner": "*", "name": "*"}
      ]
    },
    {
      "id": "read-known-smoke-datasets",
      "effect": "allow",
      "clients": ["local-agent"],
      "operations": ["repo.contents.read", "git.fetch"],
      "targets": [
        {
          "kind": "repo",
          "type": "dataset",
          "owner": "dutifulbob",
          "name": "hf-broker-*",
          "refs": ["refs/heads/main"]
        }
      ]
    },
    {
      "id": "append-smoke-datasets",
      "effect": "allow",
      "clients": ["local-agent"],
      "operations": ["git.push.append"],
      "targets": [
        {
          "kind": "repo",
          "type": "dataset",
          "owner": "dutifulbob",
          "name": "hf-broker-*",
          "refs": ["refs/heads/main"]
        }
      ]
    },
    {
      "id": "request-any-repo-content-or-write",
      "effect": "request",
      "clients": ["local-agent"],
      "operations": [
        "repo.contents.read",
        "git.push.append",
        "git.push.force",
        "git.ref.delete",
        "git.tag.update"
      ],
      "targets": [
        {"kind": "repo", "type": "*", "owner": "*", "name": "*"}
      ],
      "grant_policy": {
        "default_minutes": 5,
        "max_minutes": 60,
        "default_max_uses": 1,
        "max_uses": 3
      }
    },
    {
      "id": "deny-openclaw-admin",
      "effect": "deny",
      "clients": ["*"],
      "operations": [
        "repo.settings.update",
        "repo.members.update",
        "repo.delete"
      ],
      "targets": [
        {"kind": "repo", "type": "*", "owner": "openclaw", "name": "*"}
      ]
    }
  ]
}
```

## Object Model

A policy file contains a version number and an ordered list of rules.
Each rule is independent. A request matches a rule only when that same
rule matches the client, operation, target, and all relevant attributes.

Rules are not mixed together. The broker must not combine the operation
from one rule with the target from another rule. That rule is the main
guardrail against accidental privilege composition.

Static rules and approved grants use the same decision engine. An
approved grant becomes a generated temporary allow rule with expiry and
use-budget constraints.

## Top-Level Fields

| Field | Required | Type | Meaning |
|-------|----------|------|---------|
| `version` | yes | integer | Policy format version. This spec defines `2`. |
| `rules` | yes | array | Ordered rule list. Empty means deny everything. |

Unknown top-level fields are rejected.

## Rule Fields

| Field | Required | Type | Meaning |
|-------|----------|------|---------|
| `id` | yes | string | Stable human-readable rule id, unique within the file. |
| `effect` | yes | string | `allow`, `request`, or `deny`. |
| `clients` | yes | array | Client names or `*`. |
| `operations` | yes | array | Operation names or operation-family globs. |
| `targets` | yes | array | Target matchers. |
| `attrs` | no | object | Extra attribute constraints, such as refs, paths, visibility direction, or bucket keys. |
| `grant_policy` | required for `request` | object | Bounds for generated approval requests. |
| `description` | no | string | Operator-facing explanation. No policy effect. |

Unknown rule fields are rejected.

## Effects

### `allow`

The operation may execute immediately when the rule matches and no deny
rule matches.

### `request`

The operation may not execute immediately. The agent may create an
approval request for the exact classified operation, target, and
attributes. If the operator approves, the broker creates a generated
temporary allow rule.

Request rules are how an agent asks for access to arbitrary named repos
without granting standing execution access to those repos.

### `deny`

The operation is refused. Deny rules win over static allow rules,
request rules, and active grants. A deny rule is not requestable.

## Decision Algorithm

For a classified broker request:

1. Authenticate the client.
2. Classify the operation, target, and request attributes.
3. Reject unknown operations, unknown target kinds, malformed targets, and
   unclassified requests.
4. Find all matching `deny` rules. If any match, refuse.
5. Find matching active generated grant rules. If one matches and its
   expiry/use constraints allow this request, allow and reserve/consume
   use budget as required.
6. Find matching static `allow` rules. If any match, allow.
7. Find matching `request` rules. If this is a grant-request endpoint,
   create a pending request within the matching `grant_policy` bounds. If
   this is an execution endpoint, refuse with "approval required".
8. If no rule matches, refuse.

This is fail-closed: no match means no access.

## Conflict Resolution

Rule list order does not affect authorization. The `rules` array is
ordered only so humans can keep related rules together and so diagnostics
can report matching rule ids predictably.

The broker resolves overlapping rules by effect, not by position:

```text
deny > active generated grant allow > static allow > request > no match
```

Cases:

- Multiple matching `deny` rules are allowed. The request is refused.
- Multiple matching static `allow` rules are allowed. The request is
  allowed unless a `deny` rule also matches.
- A matching active grant and a matching static `allow` both allow the
  request, unless a `deny` rule also matches.
- A matching `allow` rule and a matching `request` rule means execution
  is already allowed. Approval is not required for that classified
  request.
- A matching `request` rule and no matching `allow` or active grant means
  execution is refused with "approval required"; the grant-request
  endpoint may create a pending request.
- Multiple matching `request` rules for the same classified request are
  valid only when their normalized `grant_policy` objects are identical.
  If the normalized grant policies differ, the policy is invalid at
  startup.

Normalization fills `grant_policy` defaults before comparison:

- `mode` defaults from the operation registry.
- `default_minutes` defaults to `5`.
- `max_minutes` defaults to `60`.
- `default_max_uses` defaults to `1` for window grants.
- `max_uses` defaults to `default_max_uses`.

The broker does not intersect or merge different grant policies. Requiring
identical request policies keeps operator prompts predictable and avoids
silent privilege changes from overlapping wildcard rules.

For cutover, overlap validation is intentionally conservative. When two
`request` rules have the same possible client and operation, and their
target matchers are identical or one side contains a wildcard that can
cover the other side, their normalized grant policies must be identical.
If the broker cannot prove two request rules are disjoint, it rejects the
policy at startup. Operators should split or narrow rules until the
overlap is obvious.

## Operation Registry

Operation names are stable strings. New operations require an explicit
registry entry, default grant mode, and tests.

Operation-family globs are allowed only at a single dot segment boundary:
`repo.*`, `git.*`, `bucket.*`. Arbitrary partial operation globs such as
`repo.*.read` or `git.push.*` are invalid in v2.

| Operation | Default grant mode | Meaning |
|-----------|--------------------|---------|
| `repo.list` | none | List repositories visible to the upstream token, filtered by matching target rules. |
| `repo.metadata.read` | none | Read repository metadata such as id, type, visibility, tags, and timestamps. |
| `repo.contents.read` | window | Read repo files, file listings, README/card text, branches, tags, commits, or raw blobs. |
| `git.fetch` | window | Git clone/fetch. This is content read. |
| `git.push.append` | window | Fast-forward push or new ref creation allowed by append-only policy. |
| `git.push.force` | window | Non-fast-forward ref update. |
| `git.ref.delete` | window | Branch or non-tag ref deletion. |
| `git.tag.update` | window | Tag move or tag deletion. |
| `bucket.object.list` | none | List bucket/object keys or prefixes. |
| `bucket.object.read` | window | Read object contents. |
| `bucket.object.write` | window | Create object or overwrite with snapshot policy. |
| `bucket.object.delete` | execution | Delete object or prefix. |
| `repo.create.private` | execution | Create a private repository. |
| `repo.metadata.update` | execution | Update non-security metadata such as description, tags, or card metadata. |
| `repo.visibility.update` | execution | Change repository visibility. |
| `repo.settings.update` | execution | Change repository settings beyond non-security metadata. |
| `repo.members.update` | execution | Add, remove, or modify members, roles, or permissions. |
| `repo.delete` | execution | Delete a repository. |

Operations with default grant mode `none` are not grantable. They must be
allowed by static policy or refused.

Never grantable through hf-broker, even with this policy format:

- generic Hugging Face API proxying
- arbitrary HTTP requests
- upstream token, secret, webhook, or credential changes
- org roles, resource groups, namespace transfer, or ownership changes
- billing, paid hardware, storage tier, or quota changes
- Space secrets or variables that may expose credentials

## Repo Listing And Content Reads

`repo.list` is intentionally separate from `repo.contents.read`.

The repo listing endpoint is:

```text
GET /api/repos
```

Query parameters:

| Parameter | Required | Meaning |
|-----------|----------|---------|
| `type` | no | `model`, `dataset`, or `space`. |
| `owner` | no | Exact owner filter. |
| `private` | no | `true` or `false`. |
| `limit` | no | Page size. Default `100`, maximum `500`. |
| `cursor` | no | Opaque pagination cursor returned by the broker. |

The cursor is opaque. Clients must not parse it. Invalid cursors return
`400`.

Listing may return repository inventory metadata:

```json
{
  "repos": [
    {
      "id": "dutifulbob/hf-broker-smoke",
      "type": "dataset",
      "private": true,
      "updated_at": "2026-07-08T00:00:00Z"
    }
  ],
  "next_cursor": "opaque"
}
```

Metadata includes only: repo id, type, owner, name, visibility/private
flag, created timestamp, updated timestamp, tags, and cheap aggregate
counters such as likes or downloads when the upstream list API already
returns them.

Contents include: file paths, file contents, README text, model card
text, dataset card text, dataset rows, branches, tags, commit ids, commit
messages, raw blobs, LFS metadata, and sibling/file-tree listings.
Contents require `repo.contents.read` or `git.fetch`.

When a `repo.list` rule uses wildcard targets, the broker may ask the Hub
for accessible repos, then filter the response through matching policy
targets before returning it. If a repo does not match a `repo.list` allow
rule, it is not included in the response.

Public repositories are not special when accessed through the broker.
Broker-routed public reads still require policy. Agents may read public
Hub data directly without the broker if they do not need the broker's
credential or audit trail.

## Target Matchers

### Repo Target

```json
{
  "kind": "repo",
  "type": "dataset",
  "owner": "dutifulbob",
  "name": "hf-broker-*",
  "refs": ["refs/heads/main"]
}
```

Fields:

| Field | Required | Type | Meaning |
|-------|----------|------|---------|
| `kind` | yes | string | Must be `repo`. |
| `type` | yes | string | `model`, `dataset`, `space`, or `*`. |
| `owner` | yes | string | Exact owner or segment glob. |
| `name` | yes | string | Exact repo name or segment glob. |
| `refs` | no | array | Exact ref names or ref globs. Applies only to git operations. |
| `paths` | no | array | Repo file path globs. Applies only to content reads when the broker can classify paths. |
| `visibility` | no | array | `public`, `private`, or `*` for operations that know visibility. |

### Bucket Target

```json
{
  "kind": "bucket",
  "owner": "dutifulbob",
  "name": "pipeline-output",
  "keys": ["runs/2026-*/**"]
}
```

Fields:

| Field | Required | Type | Meaning |
|-------|----------|------|---------|
| `kind` | yes | string | Must be `bucket`. |
| `owner` | yes | string | Exact owner or segment glob. |
| `name` | yes | string | Exact bucket/repo name or segment glob. |
| `keys` | no | array | Object key globs. |
| `snapshot_prefix` | no | string | Prefix reserved for broker snapshots; write/delete requests under it are refused. |

Unknown target fields are rejected.

## Glob Rules

The policy format uses small segment globs, not arbitrary regular
expressions.

- `*` matches zero or more characters within one segment.
- `?` matches one character within one segment.
- `**` is allowed only in path/key fields and matches across `/`.
- Globs in `owner`, `name`, and `type` never match `/`.
- `..`, empty segments, and absolute paths are invalid.
- Matching is case-sensitive.
- URL path inputs are decoded exactly once before matching.
- Invalid percent encoding, NUL bytes, absolute paths, and any `..`
  segment are refused before policy matching.
- Leading `/` is trimmed only for repo file paths and bucket keys.
- Unicode is compared as received. The broker does not normalize Unicode
  in v2.

Examples:

| Pattern | Matches | Does not match |
|---------|---------|----------------|
| `dutifulbob` | `dutifulbob` | `other` |
| `hf-broker-*` | `hf-broker-smoke` | `other-smoke` |
| `refs/heads/*` | `refs/heads/main` | `refs/tags/v1` |
| `runs/**/*.json` | `runs/a/b/out.json` | `runs/a/out.txt` |

## Attribute Constraints

`attrs` holds constraints that are not part of the stable target identity.
Every field in `attrs` is matched with AND semantics. Arrays are OR
within one field.

Example:

```json
{
  "attrs": {
    "visibility_direction": ["public_to_private"],
    "max_bytes": 10485760
  }
}
```

Initial attribute keys:

| Key | Applies to | Meaning |
|-----|------------|---------|
| `visibility_direction` | `repo.visibility.update` | `public_to_private` or `private_to_public`. |
| `max_bytes` | upload/write operations | Maximum request or object size accepted by the rule. |
| `ref_change` | git push operations | `create`, `fast_forward`, `non_fast_forward`, `delete`, or `tag_update`. |

Unknown attribute keys are rejected unless the operation registry defines
them.

Numeric attributes use `actual <= configured` semantics. Negative
configured values are invalid policy. If a rule requires a numeric
attribute and the broker cannot classify the request's actual value, the
request is refused.

## Grant Policy

`request` rules require `grant_policy`.

```json
{
  "grant_policy": {
    "default_minutes": 5,
    "max_minutes": 60,
    "default_max_uses": 1,
    "max_uses": 3,
    "mode": "window"
  }
}
```

Fields:

| Field | Required | Type | Meaning |
|-------|----------|------|---------|
| `mode` | no | string | `window` or `execution`. Defaults from operation registry. |
| `default_minutes` | no | integer | Default grant duration. Default `5`. |
| `max_minutes` | no | integer | Maximum grant duration. Default `60`, max `60`. |
| `default_max_uses` | no | integer | Default use budget for window grants. Default `1`. |
| `max_uses` | no | integer | Maximum use budget. Default `default_max_uses`, max `25`. |

Execution grants ignore multi-use budgets and are single-use plans.
Window grants require a use budget. Git push use accounting remains one
receive-pack request per use, regardless of commit count.

## Generated Grant Rules

An approved grant is stored as a generated allow rule. Generated rules are
not authored in `scope.json`, but they use the same matching semantics.

```json
{
  "id": "grant_01J...",
  "source": "telegram",
  "effect": "allow",
  "clients": ["local-agent"],
  "operations": ["git.push.force"],
  "targets": [
    {
      "kind": "repo",
      "type": "dataset",
      "owner": "dutifulbob",
      "name": "hf-broker-smoke",
      "refs": ["refs/heads/main"]
    }
  ],
  "expires_at": "2026-07-08T10:30:00Z",
  "uses_remaining": 1
}
```

Generated grant rules:

- are exact or narrower than the approved request
- never broaden static policy
- are checked after deny rules
- are bound to the requesting client only
- expire absolutely
- are consumed according to their operation mode
- are audit-logged on every lifecycle transition

Generated grant rules must never use `clients: ["*"]`.

## Validation Rules

The broker validates the full policy at startup and refuses to boot on
invalid policy.

Hard limits:

| Limit | Value |
|-------|-------|
| Policy file size | 1 MiB |
| Rules | 1000 |
| Targets per rule | 50 |
| Operations per rule | 50 |
| Clients per rule | 100 |
| Glob length | 256 bytes |
| Rule id length | 128 bytes |

Invalid policy examples:

- duplicate rule ids
- unknown effect
- empty `clients`, `operations`, or `targets`
- unknown operation name
- unsupported operation/target pairing
- unknown fields
- malformed glob
- overlapping `request` rules whose normalized `grant_policy` objects
  differ for the same possible classified request
- `request` rule without `grant_policy`
- `allow` rule with `grant_policy`
- `deny` rule with `grant_policy`
- grant policy where defaults exceed maxima
- a repo target whose `owner` or `name` contains `/`
- generated grant rule with `clients: ["*"]`
- file larger than 1 MiB
- rule, target, client, operation, glob, or id count beyond the hard
  limits

Policy is loaded only from local disk. There is no broker endpoint to
read, update, or reload policy.

## Audit Requirements

Every policy decision audit entry includes at least:

```json
{
  "client": "local-agent",
  "operation": "git.push.append",
  "target": "dataset/dutifulbob/hf-broker-smoke",
  "decision": "allowed",
  "matched_deny_rule_ids": [],
  "matched_grant_rule_ids": [],
  "matched_allow_rule_ids": ["append-smoke-datasets"],
  "matched_request_rule_ids": [],
  "grant_id": ""
}
```

Audit entries must not include upstream tokens, broker client secrets,
request bodies that may contain secrets, pack contents, file contents, or
object payloads.

## Legacy Scope Migration

This is a cutover migration. After the policy engine is implemented, the
broker runtime accepts only `version: 2`. The project may provide a
one-shot converter for old v1 `scope.json`, but the server must not keep
both v1 and v2 runtime policy loaders.

A v1 repo entry:

```json
{
  "id": "dutifulbob/hf-broker-smoke",
  "type": "dataset",
  "mode": "append-only"
}
```

compiles to standing vNext rules equivalent to:

```json
[
  {
    "id": "repo-read-dataset-dutifulbob-hf-broker-smoke",
    "effect": "allow",
    "clients": ["*"],
    "operations": ["repo.metadata.read", "repo.contents.read", "git.fetch"],
    "targets": [
      {
        "kind": "repo",
        "type": "dataset",
        "owner": "dutifulbob",
        "name": "hf-broker-smoke"
      }
    ]
  },
  {
    "id": "repo-append-dataset-dutifulbob-hf-broker-smoke",
    "effect": "allow",
    "clients": ["*"],
    "operations": ["git.push.append"],
    "targets": [
      {
        "kind": "repo",
        "type": "dataset",
        "owner": "dutifulbob",
        "name": "hf-broker-smoke"
      }
    ]
  }
]
```

Existing `grant_policy` entries compile to `request` rules with matching
targets and grant bounds.

The old `internal/scope` package is replaced by `internal/policy`.
Handlers classify requests into `policy.Request`; only `internal/policy`
decides allow/request/deny. Do not compile v2 policy into the old scope
model.

## Security Invariants

- Deny wins.
- No match denies.
- Unknown operation denies.
- Unknown target denies.
- Requestable does not mean executable.
- Listing repos does not imply reading contents.
- Reading contents does not imply writing.
- Writing does not imply admin/settings/member access.
- Active grants do not override deny rules.
- No policy path returns or logs upstream token material.
