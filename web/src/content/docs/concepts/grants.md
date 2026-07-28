---
title: Grants
description: Grant states, window and execution modes, use budgets, reservations, and idempotency.
---

A grant is temporary authority created when an operator approves a requestable operation. It
behaves as a generated allow rule that is bound to one client, one operation, one target, and the
attrs policy approved, and it expires. This page covers the lifecycle, the two modes, and the
mechanics that make retries safe.

## Grant contents

Beyond the matching fields it shares with a static rule, a grant carries runtime state: a grant ID,
the client it belongs to, an expiry time, a use budget, a status, the approved attrs, and a
decision-token verifier. The raw decision token is never stored in the grant object or serialized
into grant JSON. Only the verifier is durable; the token itself goes to the notification path once.

Grants can only be as wide as the policy rule that produced them and only as wide as the request
that asked for them. An operator approving a request may shorten its duration or reduce its use
count. No route accepts a replacement operation, target, attribute set, provider body, or execution
plan.

## States

```text
pending → active → consumed
        ↘ denied
        ↘ canceled
        ↘ expired
  active → revoked
```

A request starts `pending`. An operator decision moves it to `active` or `denied`. The requester,
and only the requester, may `cancel` its own pending request through the agent surface; a canceled
request stays a distinct terminal state so audit records show it was withdrawn rather than refused.
An active grant becomes `consumed` when its use budget runs out, `expired` when its window closes,
or `revoked` when an operator ends it early.

Every transition is persisted atomically before the broker acknowledges success, so a crash between
the decision and the response does not lose the decision.

## Window grants

A `window` grant is the general-purpose mode. It authorizes an exact classified request for a
bounded time and a use budget:

```json
{
  "mode": "window",
  "default_minutes": 5,
  "max_minutes": 10,
  "default_max_uses": 1,
  "max_uses": 3
}
```

`default_max_uses` is always a positive finite default. `max_uses` is either a positive finite
ceiling no greater than `1000000`, or `null`. Providers may impose a lower operation-specific
limit. Setting it to `null` permits a caller to request unlimited uses, which are still bounded by
the required expiry, so "unlimited" means unlimited within the window rather than unlimited full
stop. Omitting a requested `max_uses` selects the finite default. When a reusable policy omits
both use fields, they default to the lowest provider ceiling among its operations. Execution
grants always default to and require one use.

## Execution grants

An `execution` grant approves one exact provider-built action and is always single-use. Where a
window grant says "this client may do this thing for the next five minutes", an execution grant
says "this specific planned action may happen once".

The provider plan behind it is treated as an immutable, content-addressed record. A missing,
malformed, or mismatched plan fails approval and execution closed. GitHub's admin merge uses this
shape: the broker resolves the pull request itself, binds approval to the exact head commit,
rechecks it before execution, and passes it to GitHub as the mutation's atomic `expectedHeadOid`
guard. A pull request that changed after approval must be submitted and approved again.

## Use budgets and reservations

Consuming a grant is not simply decrementing a counter after the fact. The broker reserves one use
atomically as part of admission or execution, under the same grant-store lock that validates the
activation. That ordering is what makes concurrent requests against a single-use grant resolve to
exactly one execution.

Reservations are private. Public resources and lifecycle events never expose decision-token
verifiers, raw plans, credentials, provider bodies, command output, or reservation internals.

If a provider execution ends ambiguously, the broker does not automatically retry the mutation.
Authority is retained for reconciliation instead, because retrying an operation that may already
have succeeded is worse than reporting that the outcome is unknown.

## Idempotency

Every grant request carries a client request ID, reused on retries. Sending the same ID with the
same immutable request returns the existing grant. Sending it with a conflicting request returns a
bounded conflict error rather than quietly creating a second grant.

The Agent V1 API calls this value `idempotency_key` internally. MCP exposes it as `request_id`, and
the two map one to one. Git pushes get this for free: repeating a push while its approval is
pending reuses the same request rather than piling up duplicates in the operator inbox.

## Requesting a grant

Most of the time you do not request a grant explicitly. Submitting an operation that policy marks
`request` creates the approval as part of the operation, and approval resumes that operation.

Explicit grant requests exist for the case where a native protocol will consume the authority
later. Git is the example: you may want the capability in place before running `git push`.

```sh
hf-broker client grant request git.push.force osolmaz/model \
  --type model \
  --ref refs/heads/main \
  --minutes 30 \
  --max-uses unlimited \
  --reason "Repair protected history" \
  --request-id repair-main
```

Omit `--minutes` or `--max-uses` to take the matched policy's finite defaults. `--max-uses` accepts
a positive integer or `unlimited`, and an unlimited grant still expires at the approved time. The
command waits for a decision by default.

Repository requests use repeatable `--ref` and `--path` flags; bucket requests use repeatable
`--key` flags. A path or key may be exact or a single bounded trailing `/**` prefix. The broker
validates the operation, scope, duration, and use budget against the exact matched policy rule
before creating an approval.

Grant state can be resumed or changed without holding the protected operation open:

```sh
hf-broker client grant get <grant-id>
hf-broker client grant wait <grant-id>
hf-broker client grant cancel <grant-id>
hf-broker client grant revoke <grant-id>
```

## Over HTTP

Authenticated clients can request grants directly. Every request needs a unique
`client_request_id`, reused on retries:

```sh
curl -sS -H "Authorization: Bearer $HF_BROKER_SHARED_SECRET" \
  -H "Content-Type: application/json" \
  -d '{
    "operation": "git.push.force",
    "target": {
      "kind": "repo",
      "type": "dataset",
      "owner": "osolmaz",
      "name": "scraped-news",
      "refs": ["refs/heads/main"]
    },
    "reason": "recover main after a bad commit",
    "minutes": 5,
    "max_uses": 1,
    "client_request_id": "recover-main-after-bad-commit"
  }' \
  https://hf-broker.example.com/api/grants
```

The shared routes are `POST /api/grants`, `GET /api/grants`, and `GET /api/grants/{id}`. They exist
for protocol and window-grant use where the underlying protocol sits outside Agent V1. Discrete
operations use the Agent V1 lifecycle instead.

## Deny still wins

The property that makes grants safe to hand out is that they sit below deny in the decision order.
An approved grant authorizes a request only when no deny rule matches it. Adding a deny rule
immediately neuters every existing grant it covers, without anyone having to find and revoke them
individually.
