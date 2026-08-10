---
title: Admission control
description: Limit submissions so one agent cannot fill the queue or operator inbox.
---

The admission controller checks a request before unYOLO creates an operation or approval
notification. It limits submission rates, active work, pending approvals, and stored data.

## Defaults

Without configuration, the controller allows 60 submissions per client per minute, 25 active and 10
pending operations per client, 512 active operations globally, and 64 executing operations
globally.

Stream, sealed payload, and pending-grant stores enforce independent global and per-client storage
caps on top of these.

## Ordering

Authentication, request validation, and idempotent replay all happen before quota charging. A
replayed request that returns an existing operation does not consume a slot, so a client retrying
correctly with a stable request ID is not penalised for the retry.

A refusal returns a stable `429` with `Retry-After`, creates no operation and no approval, and does
not consume another slot.

## Availability under load

Cancellation, operator decisions, liveness, and readiness do not pass through submission admission.

That separation is the point of the design. During an overload, the operations you need are the
ones that reduce load: an operator denying a pile of pending requests, a client cancelling its own
work, and the health checks that tell you what is happening. Putting those behind the same quota as
new submissions would make an overloaded broker impossible to recover.

## Configuration

`hf-broker` and `gh-broker` read an optional absolute path from `HF_BROKER_ADMISSION_CONFIG` and
`GH_BROKER_ADMISSION_CONFIG`. `sudo-broker` accepts the same file through
`sudo-broker serve --admission-config`. An omitted file uses the conservative defaults above.

A configured file is a closed JSON object and must define every default and global value:

```json
{
  "requests_per_window": 60,
  "window_seconds": 60,
  "client_active": 25,
  "client_pending": 10,
  "global_active": 512,
  "global_executing": 64,
  "clients": {
    "automation-a": {
      "requests_per_window": 20,
      "window_seconds": 60,
      "active": 8,
      "pending": 4
    }
  }
}
```

Partial configuration is rejected. Supplying only the values you want to change is not supported,
because a half-specified quota file makes the effective limits depend on which defaults happened to
be current when it was written.

## Validation

Startup fails on unknown client keys, duplicate or unknown JSON fields, partial values,
non-positive limits, pending limits above active limits, and client active limits above the global
active limit. Client override keys must exactly match configured authentication identities.

The file is bounded to 64 KiB, and its path must be absolute and normalized.

Failing startup rather than warning is consistent with how unYOLO treats policy. A quota file
with a typo in a client name silently applies the default limits to that client, which is exactly
the surprise you do not want to discover during an incident.

## Choosing limits

The defaults suit an interactive agent doing a handful of operations a minute. Two situations
justify changing them.

A batch automation client that legitimately submits in bursts needs a higher
`requests_per_window`, and giving it a per-client override rather than raising the global default
keeps the interactive clients protected.

A client you do not fully trust yet is the opposite case. Lowering its `pending` limit caps how
many approval requests it can queue for a human, which is usually the resource that runs out first
in practice.

## Observing it

The metrics registry reports admitted and rejected Agent V1 submissions with stable rejection
codes, along with durable pending-approval, queued-operation, and executing-operation depths.

Those queue gauges are the ones to watch. A steadily rising pending-approval depth usually means an
agent is requesting things nobody intends to approve, which is a policy problem rather than a quota
problem. See [metrics and logs](/docs/operate/observability).

## Related drills

The submission overload drill asserts that new work receives a stable `429` while replay,
cancellation, approval, and readiness remain available. It lives in
`authorization/admission/admission_test.go` and `operation/runtime/runtime_test.go`. The clock
drill in the same admission test asserts that a backward wall clock does not reset a rate window
backward. See [failure drills](/docs/operate/failure-drills).
