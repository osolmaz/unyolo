# Policy Rules Specification

Status: cutover implementation specification, 2026-07-08.

This specification defines the cutover policy-rule format for hf-broker.
It replaces the exact-entry v1 `scope.json` model with a small typed rule
system that supports wildcards, repo listing, requestable approvals, and
generated temporary grants.

The current v1 `repos[]` and `buckets[]` schema remains valid only until
this format is implemented. After cutover, `scope.json` is a rules file:
runtime policy loading accepts the new `rules` format only. A one-shot
converter may translate old files, but the broker does not keep dual
runtime formats.

## Smallest Valid File

```json
{
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

`scope.json` contains an ordered list of policy rules. Each rule is
independent. A request matches a rule only when that same rule matches
the client, operation, target, and all relevant attributes.

Rules are not mixed together. The broker must not combine the operation
from one rule with the target from another rule. That rule is the main
guardrail against accidental privilege composition.

Static rules and approved grants use the same decision engine. An
approved grant becomes a generated temporary allow rule with expiry and
use-budget constraints.

## Top-Level Fields

| Field | Required | Type | Meaning |
|-------|----------|------|---------|
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

## Policy Decision Object

All broker handlers classify their request into a `policy.Request` and
ask `internal/policy` for one decision. Handlers do not interpret policy
rules directly.

Conceptual request:

```json
{
  "client": "local-agent",
  "operation": "git.push.append",
  "target": {
    "kind": "repo",
    "type": "dataset",
    "owner": "dutifulbob",
    "name": "hf-broker-smoke"
  },
  "attrs": {
    "ref": "refs/heads/main",
    "ref_change": "fast_forward"
  }
}
```

Conceptual decision:

```json
{
  "effect": "allow",
  "reason": "policy_allowed",
  "matched_deny_rule_ids": [],
  "matched_grant_rule_ids": [],
  "matched_allow_rule_ids": ["append-smoke-datasets"],
  "matched_request_rule_ids": [],
  "grant_id": "",
  "grant_policy": null
}
```

Decision effects:

| Effect | Meaning |
|--------|---------|
| `allow` | Request may execute. |
| `request` | Request may be submitted for approval, but may not execute yet. |
| `deny` | Request is refused by policy. |
| `no_match` | Request is refused because no rule matched. |

Stable decision reasons:

| Reason | Meaning |
|--------|---------|
| `policy_allowed` | Static allow rule matched. |
| `grant_allowed` | Active generated grant matched. |
| `approval_required` | Request rule matched, but this is an execution endpoint. |
| `requestable` | Request rule matched on a grant-request endpoint. |
| `policy_denied` | Deny rule matched. |
| `no_matching_rule` | No rule matched. |
| `invalid_operation` | Operation could not be classified or is unknown. |
| `invalid_target` | Target could not be classified or is malformed. |
| `invalid_attrs` | Attributes are malformed or incomplete for the operation. |
| `grant_expired` | Matching grant is expired. |
| `grant_consumed` | Matching grant has no remaining uses. |

## JSend API Envelope

Every JSON API response under `/api/*` uses JSend. Git smart-HTTP routes
do not use JSend because Git clients require Git-shaped responses.

Request bodies are endpoint-specific JSON objects. They are not wrapped
in JSend; JSend is the response envelope.

All `/api/*` responses use `application/json`. Field names are
snake_case. Unknown request fields are rejected unless an endpoint
explicitly declares an extension object.

Success:

```json
{
  "status": "success",
  "data": {}
}
```

Client, auth, validation, and policy failures:

```json
{
  "status": "fail",
  "data": {
    "reason": "approval_required",
    "message": "Approval required"
  }
}
```

Server or upstream errors:

```json
{
  "status": "error",
  "message": "upstream request failed",
  "code": "upstream_error"
}
```

HTTP status still carries the transport class:

| Case | HTTP | JSend |
|------|------|-------|
| Success | `200` or `201` | `success` |
| Bad request | `400` | `fail` |
| Missing auth | `401` | `fail` |
| Bad auth | `403` | `fail` |
| Policy denied | `403` | `fail` |
| Approval required | `403` | `fail` |
| Not found | `404` | `fail` |
| Method not allowed | `405` | `fail` |
| Conflict/idempotency mismatch | `409` | `fail` |
| Request too large | `413` | `fail` |
| Upstream/server error | `500` or `502` | `error` |

Stable `fail.data.reason` values:

```text
missing_auth
bad_auth
malformed_json
validation_failed
approval_required
policy_denied
not_requestable
invalid_operation
invalid_target
invalid_attrs
invalid_cursor
invalid_limit
grant_not_found
grant_expired
grant_consumed
grant_revoked
grant_denied
idempotency_conflict
not_found
method_not_allowed
request_too_large
```

Stable `error.code` values:

```text
upstream_error
internal_error
```

API responses never include raw upstream response bodies, broker client
secrets, upstream tokens, request bodies, pack contents, file contents,
object payloads, or unredacted generated grant plans.

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
- `request_ttl_minutes` defaults to `5`.
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

Operation-family globs are allowed only as full first-segment families:
`repo.*`, `git.*`, `bucket.*`. A family glob matches all registered
operations whose name starts with that family prefix. Arbitrary partial
operation globs such as `repo.*.read` or `git.push.*` are invalid in the
cutover format.

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

Success response:

```json
{
  "status": "success",
  "data": {
    "repos": [
      {
        "id": "dutifulbob/hf-broker-smoke",
        "type": "dataset",
        "owner": "dutifulbob",
        "name": "hf-broker-smoke",
        "private": true,
        "updated_at": "2026-07-08T00:00:00Z"
      }
    ],
    "next_cursor": "opaque"
  }
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

The broker cursor wraps the upstream pagination cursor and the original
broker filters. A cursor is valid only for the same authenticated client
and same query shape. The cursor must not expose the upstream token,
upstream URL, or unfiltered repo ids.

Public repositories are not special when accessed through the broker.
Broker-routed public reads still require policy. Agents may read public
Hub data directly without the broker if they do not need the broker's
credential or audit trail.

## Bucket Listing And Object Reads

Bucket operations follow the same split as repo operations:

- `bucket.object.list` returns object keys, prefixes, size, etag/hash
  metadata, and update timestamps when the upstream API provides them.
- `bucket.object.read` returns object bytes or signed/read URLs.
- `bucket.object.write` creates or overwrites objects under append-only
  snapshot policy.
- `bucket.object.delete` deletes objects or prefixes and is an execution
  grant by default.

Bucket listing must not return object contents. Object contents require
`bucket.object.read`.

Object keys are normalized with the same path rules as repo paths:
decode once, reject invalid percent encoding, reject NUL, reject absolute
paths, trim one leading `/`, reject `..`, and compare case-sensitively.

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
  in the cutover format.

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
    "request_ttl_minutes": 5,
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
| `default_minutes` | no | integer | Default approved access duration in minutes. Default `5`, min `1`. |
| `max_minutes` | no | integer | Maximum approved access duration in minutes. Default `60`, min `1`, max `60`. |
| `request_ttl_minutes` | no | integer | How long a pending approval request stays actionable. Default `5`, min `1`, max `60`. |
| `default_max_uses` | no | integer | Default use budget for window grants. Default `1`, min `1`. |
| `max_uses` | no | integer | Maximum use budget. Default `default_max_uses`, min `1`, max `25`. |

Execution grants ignore multi-use budgets and are single-use plans.
Window grants require a use budget. Git push use accounting remains one
receive-pack request per use, regardless of commit count.

Approved access starts when the operator approves, not when the agent
creates the pending request. `expires_at = approved_at + minutes`.
`pending_until = requested_at + request_ttl_minutes`.

## Grant API

Agent-facing grant request endpoint:

```text
POST /api/grants
```

Request body:

```json
{
  "operation": "repo.contents.read",
  "target": {
    "kind": "repo",
    "type": "dataset",
    "owner": "dutifulbob",
    "name": "hf-broker-smoke",
    "refs": ["refs/heads/main"]
  },
  "attrs": {},
  "minutes": 5,
  "max_uses": 1,
  "reason": "need to inspect repo contents before updating policy",
  "client_request_id": "optional-idempotency-key"
}
```

Fields:

| Field | Required | Meaning |
|-------|----------|---------|
| `operation` | yes | One operation from the operation registry. |
| `target` | yes | One target object. |
| `attrs` | no | Operation attributes. |
| `minutes` | no | Requested approved access duration. Defaults from matching request rule. |
| `max_uses` | no | Requested use budget for window grants. Defaults from matching request rule. |
| `reason` | yes | Human-readable reason shown to the operator. Length `1..500`. |
| `client_request_id` | no | Idempotency key scoped to the authenticated client. Length `1..128` when present. |

If a matching request rule exists and the requested bounds fit its
normalized `grant_policy`, the broker creates a pending grant:

```json
{
  "status": "success",
  "data": {
    "grant": {
      "id": "grant_01J...",
      "status": "pending",
      "operation": "repo.contents.read",
      "target": {
        "kind": "repo",
        "type": "dataset",
        "owner": "dutifulbob",
        "name": "hf-broker-smoke",
        "refs": ["refs/heads/main"]
      },
      "attrs": {},
      "mode": "window",
      "minutes": 5,
      "max_uses": 1,
      "uses_remaining": 0,
      "pending_until": "2026-07-08T10:30:00Z",
      "expires_at": null
    }
  }
}
```

If no request rule allows asking:

```json
{
  "status": "fail",
  "data": {
    "reason": "not_requestable",
    "message": "No policy rule allows requesting this operation"
  }
}
```

Grant read endpoints:

```text
GET /api/grants
GET /api/grants/{id}
```

`GET /api/grants` accepts `status=pending|active|expired|consumed|denied|revoked`
and returns only grants for the authenticated client on the agent-facing
API. Operator channels may list all grants.

Grant list response:

```json
{
  "status": "success",
  "data": {
    "grants": [
      {
        "id": "grant_01J...",
        "status": "pending",
        "operation": "repo.contents.read",
        "target": {
          "kind": "repo",
          "type": "dataset",
          "owner": "dutifulbob",
          "name": "hf-broker-smoke",
          "refs": ["refs/heads/main"]
        },
        "mode": "window",
        "max_uses": 1,
        "uses_remaining": 0,
        "pending_until": "2026-07-08T10:30:00Z",
        "expires_at": null
      }
    ],
    "next_cursor": null
  }
}
```

Operator-only decision endpoints:

```text
POST /api/grants/{id}/approve
POST /api/grants/{id}/deny
POST /api/grants/{id}/revoke
```

These endpoints must not be reachable with the agent's broker secret.
They are allowed only on an operator channel, such as a host-local admin
listener, operator CLI, or Telegram decision path. They still use JSend
when exposed as JSON APIs.

Approving a window grant sets `status=active`, `expires_at`, and
`uses_remaining`. Approving an execution grant creates a single-use plan
and may execute it immediately or mark it ready for one execution,
depending on the operation registry entry.

Decision response:

```json
{
  "status": "success",
  "data": {
    "grant": {
      "id": "grant_01J...",
      "status": "active",
      "expires_at": "2026-07-08T10:26:00Z",
      "uses_remaining": 1
    }
  }
}
```

Approving, denying, or revoking an expired or terminal grant returns
`409` with the current grant state. Operators may safely retry a decision
request; repeated identical decisions return the existing grant state.

`client + client_request_id` is idempotent. Repeating the same body
returns the existing grant. Reusing the same key with a different body
returns `409` with reason `idempotency_conflict`.

## Operator Prompt Contract

Operator channels must render approval requests from the classified
operation and target, not from raw URLs or request bodies.

Prompts include:

- product name: `hf-broker`
- client name
- plain operation label, such as "push to a Git repo" or "force-push to a
  Git repo"
- target owner/name/type
- ref, path, or key constraints when present
- requested access duration
- use budget or execution-plan summary
- request expiration time
- human reason

Prompts must visually distinguish pending, approved, denied, expired, and
consumed states. When a grant changes state, the corresponding operator
message is updated if the channel supports updates. Expired grants update
their prompt state even when no operator clicked a button.

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

## Generated Grant Storage

Generated grants are stored under the broker state directory, not inside
`scope.json`:

```text
state/grants/grants.json
```

The store is append-auditable JSON written atomically with temp-file +
rename and mode `0600`.

One grant record:

```json
{
  "id": "grant_01J...",
  "status": "active",
  "client": "local-agent",
  "client_request_id": "optional-idempotency-key",
  "operation": "git.push.force",
  "target": {
    "kind": "repo",
    "type": "dataset",
    "owner": "dutifulbob",
    "name": "hf-broker-smoke",
    "refs": ["refs/heads/main"]
  },
  "attrs": {
    "ref": "refs/heads/main"
  },
  "mode": "window",
  "reason": "repair main after a bad push",
  "requested_at": "2026-07-08T10:20:00Z",
  "pending_until": "2026-07-08T10:25:00Z",
  "approved_at": "2026-07-08T10:21:00Z",
  "expires_at": "2026-07-08T10:26:00Z",
  "max_uses": 1,
  "uses_remaining": 1,
  "reserved_uses": 0,
  "operator": "telegram:@operator",
  "generated_rule": {
    "id": "grant_01J...",
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
    "expires_at": "2026-07-08T10:26:00Z",
    "uses_remaining": 1
  }
}
```

Grant statuses:

```text
pending -> active
pending -> denied
pending -> expired
active  -> consumed
active  -> expired
active  -> revoked
active  -> retained
```

Terminal statuses are `consumed`, `denied`, `expired`, and `revoked`.
`retained` means a use reservation may have reached upstream and requires
operator review before the broker can safely finalize it.

Window grants reserve one use before forwarding the operation upstream.
The reservation is committed to disk before forwarding. If the operation
definitely did not reach upstream, the reservation may be released. If
the broker cannot prove that, the reservation is retained fail-closed.

Execution grants store a canonical plan hash and consume on successful
execution. If an execution may have partially applied upstream, the grant
is retained for operator review and is not retried automatically.

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

Startup diagnostics must include rule ids and field paths, for example:

```text
scope.json rules[3].grant_policy.max_minutes: must be <= 60
scope.json rules[5]: request rule overlaps rule request-any-repo-content-or-write with different grant_policy
```

Diagnostics must not print broker client secrets, upstream tokens,
request bodies, pack contents, file contents, object payloads, or
unredacted generated grant plans.

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

If many rules match, audit entries include at most the first 50 matched
rule ids per category plus a count:

```json
{
  "matched_allow_rule_ids": ["rule-a", "rule-b"],
  "matched_allow_rule_count": 2
}
```

## Legacy Scope Migration

This is a cutover migration. After the policy engine is implemented, the
broker runtime accepts only the rule-based `scope.json`. The project may
provide a one-shot converter for old v1 `scope.json`, but the server must
not keep both old and new runtime policy loaders.

A v1 repo entry:

```json
{
  "id": "dutifulbob/hf-broker-smoke",
  "type": "dataset",
  "mode": "append-only"
}
```

compiles to standing rule-based policy equivalent to:

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
decides allow/request/deny. Do not compile rule policy into the old scope
model.

## Canonical Test Fixtures

Implementation must include policy fixture files for:

- minimal repo listing allow
- broad repo listing with no content read
- append-only dataset push
- request-any named repo content read
- deny overriding static allow
- deny overriding active generated grant
- overlapping request rules with identical grant policy
- invalid overlapping request rules with different grant policy
- invalid operation-family glob
- invalid target path normalization
- generated grant bound to one client
- generated grant with `clients: ["*"]` rejected

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
