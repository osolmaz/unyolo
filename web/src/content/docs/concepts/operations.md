---
title: Agent operations
description: Submit an operation, track it, and recover it after an interrupted call.
---

Agents use Agent Operations V1 to submit typed provider work without receiving the provider
credential. CLI commands, MCP tools, and direct HTTP requests use this API. Git traffic uses a
separate listener because it speaks the Git protocol.

## Contract ownership

The shared contract owns identity, idempotency, lifecycle, presentation, and safe errors. Providers
own target validation, argument validation, execution, and result validation. That split is why
`gh-broker` can generate hundreds of typed operations from pinned GitHub definitions without the
shared lifecycle code learning anything about GitHub.

## Handles

Five identifiers appear in the lifecycle, and mixing them up is the most common source of
confusion:

| Handle | Meaning |
| --- | --- |
| `request_id` | Exact admission and retry identity, chosen by the caller or generated. |
| `operation_id` | Durable operation lifecycle identity. |
| `approval_id` | Internal approval linkage. Not exposed by MCP. |
| `transfer_id` | Bounded stream correlation handle. |
| `credential_slot` | Encrypted destination for generated credentials. |

The internal Agent V1 API calls the first one `idempotency_key`. MCP exposes the same value as
`request_id`, and the mapping is one to one. Supplying the same request ID with the same immutable
request returns the existing operation; supplying it with a conflicting request returns a bounded
`request_id_conflict` rather than creating a second execution.

## Submission

Submission returns immediately with the transcript-safe operation, including its ID, request ID,
state, revision, timestamps, and safe presentation. It never waits for approval. That property is
what makes the surface usable from an LLM tool call, where a blocking call would burn the context
window on a wait.

The CLI prints the operation record on stdout and lifecycle guidance on stderr. `pending`,
`approved`, and `executing` mean the requested action is not complete. The guidance includes the
exact wait command for the same operation ID. Only `succeeded` means the action completed;
`failed`, `denied`, `expired`, and `canceled` mean it did not.

```sh
gh-broker operation submit repo.contents.read \
  --target-json '{"kind":"repo","owner":"osolmaz","name":"unyolo"}' \
  --arguments-json '{"path":"README.md","ref":"main"}' \
  --wait
```

The `--wait` flag is a client convenience that polls after submitting. The submission itself still
returned right away.

## Authorization inside the lifecycle

Authorization mode does not select a dispatch path. Every ordinary operation tool submits one
durable Agent V1 operation, and static allow, active window grant, approval request, and deny are
all outcomes inside that single lifecycle.

An allowed operation executes immediately and creates no approval state. A requestable operation
without an active grant creates one approval linked to that operation. A matching active window
grant authorizes the stored operation and reserves one use atomically. A denied operation makes no
provider request at all.

This matters for a practical reason. An allowed read of a private repository executes immediately
using the broker's credential; it does not ask for a grant and it does not expose the token.
Explicit grant tools are for callers deliberately managing access that a native protocol will use
later, and reaching for them before an ordinary operation creates approval requests nobody needed.

## Recovery

Operations are durable, so a lost connection or a restarted process does not lose the work. Run
the exact `Next:` command printed by the CLI. Do not submit another operation when a wait times out:

```sh
gh-broker operation get <id>
gh-broker operation wait <id>
gh-broker operation cancel <id>
```

Over MCP the same three exist as `<prefix>operation_get`, `<prefix>operation_wait`, and
`<prefix>operation_list`. Waits default to 25 seconds, never exceed 25 seconds, and return the
latest known state on timeout. List defaults to 20 results, caps at 50, uses validated opaque
cursors, and supports exact request-ID recovery. Listing is scoped to the authenticated client.

Cancellation belongs to the requester. An operator cannot cancel someone's pending request; an
operator denies it, which is a different terminal state and reads differently in the audit log.

## Routes

The agent listener exposes the lifecycle plus its supporting transfer surfaces:

```text
GET  /.well-known/unyolo-agent
POST /api/agent/v1/operations
GET  /api/agent/v1/operations/{id}
GET  /api/agent/v1/operations/{id}/events
POST /api/agent/v1/operations/{id}/cancel
POST /api/agent/v1/sealed-payloads
POST /api/agent/v1/streams
GET  /api/agent/v1/streams/{id}
```

Sealed payloads and streams are how bounded content moves without going through the JSON body.
Both are authenticated and bounded, and both stay inside the client's own scope.

The discovery document at `/.well-known/unyolo-agent` exposes the exact generated contract
digest and build identity, so a client can detect protocol drift without logging response bodies. A
version label alone is never treated as compatibility evidence.

## Ambiguous outcomes

When a provider execution times out or completes ambiguously, the broker does not automatically
retry the mutation. Committed plans recover after a crash, and unprovable outcomes fail explicitly
rather than being retried into a possible duplicate. Authority is retained for reconciliation.

The rule this implies for callers is short: reuse a stable request ID when retrying, and never
retry an ambiguous execution under a new ID.

## Result safety

Provider-native request and result schemas stay provider-owned, but the projection into public
output is bounded. Providers project public names that collide with supported transcript
redactors, and real secrets remain sealed or credential-slot-backed.

Provider errors get sanitized before a client sees them. `gh-broker` parses GitHub's documented
error `message` fields, removes control characters, redacts credential-like values, and limits the
text. Raw response bodies, GraphQL paths, and extensions are not retained. Sealed operations omit
provider messages entirely, because a provider may echo request values back. A durable operation
can therefore report something useful like a disabled merge method while machine behaviour keeps
using validated codes, HTTP status, and request IDs.

## Admission

Submission passes through an admission controller before any durable operation or approval
notification is created. Authentication, request validation, and idempotent replay all happen
before quota charging, so a replayed request does not consume a slot.

A refusal returns a stable `429` with `Retry-After`, creates no operation, and does not consume
another slot. Cancellation, operator decisions, liveness, and readiness bypass submission admission
and stay available during overload. See [admission control](/docs/deploy/admission-control) for
the limits and how to configure them.
