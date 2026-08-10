---
title: Agent V1 API
description: API reference for submitting and tracking agent operations.
---

Agents use Agent Operations V1 (`unyolo.io/agent/v1`) to submit and resume provider operations
without receiving the provider credential. The OpenAPI file is `protocol/openapi/agent-v1.yaml`.
Generated Go clients and Echo interfaces are under `protocol/agentwire/`.

The shared contract owns identity, idempotency, lifecycle, presentation, and safe errors. Providers
own target, argument, execution, and result validation.

## Routes

```text
GET  /healthz

GET  /.well-known/unyolo-agent
POST /api/agent/v1/operations
GET  /api/agent/v1/operations/{id}
GET  /api/agent/v1/operations/{id}/events
POST /api/agent/v1/operations/{id}/cancel
POST /api/agent/v1/sealed-payloads
POST /api/agent/v1/streams
GET  /api/agent/v1/streams/{id}

POST /api/grants
GET  /api/grants
GET  /api/grants/{id}
```

`GET /healthz` is the only unauthenticated route. Everything else requires the broker client secret
as a bearer token.

Provider surfaces add their own protocol routes on top. `gh-broker` adds smart-HTTP and LFS paths
plus `POST /webhooks/github`; `hf-broker` adds `GET /v1/models` and `POST /v1/chat/completions` for
Router inference. Discrete JSON operations always go through Agent V1, and there are no direct
repository-list or contents proxy routes.

## Discovery

`GET /.well-known/unyolo-agent` returns the exact generated contract digest and build identity.
Clients compare that digest to detect protocol drift without logging response bodies.

A version label alone is never treated as compatibility evidence.

## Handles

| Handle | Meaning |
| --- | --- |
| `idempotency_key` | Exact admission and retry identity. Exposed by MCP as `request_id`. |
| `operation_id` | Durable operation lifecycle identity. |
| `approval_id` | Internal approval linkage. Not exposed by MCP. |
| `transfer_id` | Bounded stream correlation handle. |
| `credential_slot` | Encrypted destination for generated credentials. |

Supplying the same idempotency key with the same immutable request returns the existing operation.
Supplying it with a conflicting request returns a bounded conflict rather than creating a second
execution.

## Submission

Submission returns immediately with the transcript-safe operation: its ID, request ID, state,
revision, timestamps, and safe presentation. It never waits for approval.

Authorization happens inside this one lifecycle. A static allow executes immediately and creates no
approval state. A matching active window grant authorizes the stored operation and reserves one use
atomically. A `request` effect with no active grant creates one approval linked to that operation.
A deny makes no provider request.

## Lifecycle and recovery

```sh
gh-broker operation get    <id>
gh-broker operation wait   <id>
gh-broker operation cancel <id>
```

`GET /api/agent/v1/operations/{id}/events` streams lifecycle events for that operation.

Cancellation is requester-owned. Only the authenticated requester may cancel its own pending
request, and a canceled request stays a distinct terminal state so audit records show it was
withdrawn rather than refused. Operators deny pending requests and revoke active grants through
[Operator V1](/docs/reference/operator-v1) instead.

## Transfers

`POST /api/agent/v1/sealed-payloads` accepts a bounded authenticated sealed payload.
`POST /api/agent/v1/streams` and `GET /api/agent/v1/streams/{id}` move bounded stream content with
a `transfer_id` correlating the two halves. Both are authenticated and scoped to the calling
client's own work.

## Admission

Submission passes through the admission controller before any durable operation or approval
notification is created. Authentication, request validation, and idempotent replay all happen
before quota charging, so a correct retry does not consume a slot.

A refusal returns a stable `429` with `Retry-After`, creates no operation, and does not consume
another slot. Cancellation, operator decisions, liveness, and readiness bypass submission admission
and stay available during overload.

Defaults are 60 submissions per client per minute, 25 active and 10 pending operations per client,
512 active operations globally, and 64 executing globally. See
[admission control](/docs/deploy/admission-control).

## Errors

Errors reduce to a closed set of broker-owned codes before either logs or metric labels see them:

```text
authentication  authorization  canceled   conflict
invalid_response  rate_limited  rejected   storage
timeout           unavailable   other
```

Provider error text is sanitized before it reaches a client. `gh-broker` parses GitHub's documented
error `message` fields, removes control characters, redacts credential-like values, and limits the
length. Raw response bodies, GraphQL paths, and extensions are not retained. Sealed operations omit
provider messages entirely, because a provider may echo request values back.

Ambiguous completions are never retried automatically. Authority is retained for reconciliation and
the outcome is reported as unprovable. Reuse a stable request ID when retrying, and never retry an
ambiguous execution under a new one.

## Grant routes

`POST /api/grants` is the explicit protocol endpoint for clients that need a grant before using a
native protocol such as Git. Every request carries a unique `client_request_id`, reused on retries:

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

Discrete operations should use the Agent V1 lifecycle instead. Requesting a grant before an
ordinary operation creates approval state that nobody needed.

## MCP projection

MCP returns a closed `unyolo.io/mcp-operation/v1` projection defined in
`protocol/openapi/mcp-v1.yaml`. It excludes clients, canonical arguments, approval linkage, and
plan data.

Waits default to 25 seconds and never exceed 25 seconds. Lists default to 20 results, cap at 50,
use validated opaque cursors, and support exact request-ID recovery. See
[MCP servers](/docs/guides/mcp-server).
