# Policy Rules Specification

Status: draft for vNext, 2026-07-08.

This specification defines the future policy-rule format for hf-broker.
It is meant to replace the current exact-entry `scope.json` model with a
small typed rule system that supports wildcards, repo listing, requestable
approvals, and generated temporary grants.

The current v1 `repos[]` and `buckets[]` schema remains valid until this
format is implemented. A v1 entry can be compiled into equivalent vNext
rules during migration.

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

## Operation Registry

Operation names are stable strings. New operations require an explicit
registry entry and tests.

| Operation | Meaning |
|-----------|---------|
| `repo.list` | List repositories visible to the upstream token, filtered by matching target rules. |
| `repo.metadata.read` | Read repository metadata such as id, type, visibility, tags, and timestamps. |
| `repo.contents.read` | Read repo files, file listings, README/card text, branches, tags, commits, or raw blobs. |
| `git.fetch` | Git clone/fetch. This is content read. |
| `git.push.append` | Fast-forward push or new ref creation allowed by append-only policy. |
| `git.push.force` | Non-fast-forward ref update. |
| `git.ref.delete` | Branch or non-tag ref deletion. |
| `git.tag.update` | Tag move or tag deletion. |
| `bucket.object.list` | List bucket/object keys or prefixes. |
| `bucket.object.read` | Read object contents. |
| `bucket.object.write` | Create object or overwrite with snapshot policy. |
| `bucket.object.delete` | Delete object or prefix. |
| `repo.create.private` | Create a private repository. |
| `repo.metadata.update` | Update non-security metadata such as description, tags, or card metadata. |
| `repo.visibility.update` | Change repository visibility. |
| `repo.settings.update` | Change repository settings beyond non-security metadata. |
| `repo.members.update` | Add, remove, or modify members, roles, or permissions. |
| `repo.delete` | Delete a repository. |

Never grantable through hf-broker, even with this policy format:

- generic Hugging Face API proxying
- arbitrary HTTP requests
- upstream token, secret, webhook, or credential changes
- org roles, resource groups, namespace transfer, or ownership changes
- billing, paid hardware, storage tier, or quota changes
- Space secrets or variables that may expose credentials

## Repo Listing And Content Reads

`repo.list` is intentionally separate from `repo.contents.read`.

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
  ]
}
```

Listing must not return file paths, file contents, README text, model
card text, dataset rows, branch names, tag names, commit messages, or raw
blobs. Those require `repo.contents.read` or `git.fetch`.

When a `repo.list` rule uses wildcard targets, the broker may ask the Hub
for accessible repos, then filter the response through matching policy
targets before returning it. If a repo does not match a `repo.list` allow
rule, it is not included in the response.

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
- expire absolutely
- are consumed according to their operation mode
- are audit-logged on every lifecycle transition

## Validation Rules

The broker validates the full policy at startup and refuses to boot on
invalid policy.

Invalid policy examples:

- duplicate rule ids
- unknown effect
- empty `clients`, `operations`, or `targets`
- unknown operation name
- unsupported operation/target pairing
- unknown fields
- malformed glob
- `request` rule without `grant_policy`
- `allow` rule with `grant_policy`
- `deny` rule with `grant_policy`
- grant policy where defaults exceed maxima
- a repo target whose `owner` or `name` contains `/`

Policy is loaded only from local disk. There is no broker endpoint to
read, update, or reload policy.

## Legacy Scope Migration

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
