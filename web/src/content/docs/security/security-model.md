---
title: Security model
description: The boundaries unYOLO maintains, the controls behind each one, and how to verify them on a real host.
---

unYOLO's security model rests on keeping several things apart that are usually the same thing:
the credential and the process that uses it, the agent and the operator, the network path and the
authorization decision. This page describes each separation and the control that maintains it. The
[threat model](/docs/security/threat-model) covers the specific attacks and the required failure
behaviour.

## Write-only secrets

Secret material goes into a broker and does not come out. No API, log line, error message, or
helper returns the upstream credential, and audit logs never contain secrets, request bodies, or
pack contents.

This is enforced at the shape of the interface rather than by filtering. Callers choose an
operation and a target. There is no parameter for a credential kind, a token scope, a GitHub
installation, or a permission set, so there is no request that could ask for one.

Generated credentials that must reach a caller go through encrypted credential slots rather than
appearing in a response body, and sealed operations omit provider messages entirely because a
provider may echo request values back.

## Separate authority domains

Agent credentials cannot approve requests. The operator inbox runs on its own listener with its own
secret file, and a credential reused by a broker client is rejected at construction time rather
than at request time.

The practical consequence is worth stating: an agent that fully compromises its own credential
gains exactly the operations its policy allows, and gains no ability to widen them.

Notification channels carry one-time decision tokens. They are transports rather than long-term
authority stores. The Telegram ingress may retain encrypted callback authority only until terminal
delivery or expiry, after which the nonce, ciphertext, and token are erased and only redacted
lifecycle evidence remains.

## Reachability and authorization

Every endpoint except `GET /healthz` requires its route-appropriate authentication. Running a
broker behind a Tailnet or a restricted network is worth doing, and it changes nothing about the
authentication requirement.

Agent routes require the broker client secret. The operator listener requires the separate operator
credential. The GitHub webhook route requires a verified `X-Hub-Signature-256` payload signature.
The Git listener requires its own scoped credential and exposes only Git routes.

## Process isolation

Run a broker where its clients cannot inspect its process or credential files. If the agent account
can read `/etc/hf-broker/hf-token`, nothing in the software matters.

This is the one part of the model unYOLO cannot enforce from inside the process, which is why
every broker ships a doctor that checks it:

```sh
hf-broker doctor \
  --agent-user agent \
  --broker-pid "$(pgrep -x hf-broker)" \
  --token-file /etc/hf-broker/hf-token \
  --socket /run/unyolo/huggingface/agent/broker.sock
```

The doctor fails closed when the agent is root, is root-equivalent through a group such as `sudo`,
`wheel`, `admin`, `docker`, `lxd`, or `incus`, can read or modify the token file, can read the
broker's process environment, can write to the checked socket, or shares the broker's UID.

A useful host layout keeps three accounts apart:

```text
operator-a = administrator account
agent-a    = agent account, no root-equivalent groups
hf-broker  = service account that can read the real token
```

## Narrowing-only authority

Policy bounds what may be requested. A request may ask for less than the policy default and never
more than the policy maximum. An operator approving a request may shorten its duration or reduce
its use count, and may not do anything else.

No route accepts a replacement operation, target, attribute set, provider body, or execution plan.
A decision applies to the broker's canonical stored request, so a compromised presentation layer
cannot change what executes.

Deny sits above active grants in the decision order, which means adding a deny rule immediately
neuters every grant it covers without anyone hunting them down individually.

## Immutable execution plans

Provider execution plans are immutable, content-addressed records. A missing, malformed, or
mismatched plan fails approval and execution closed.

GitHub's admin merge shows why this matters. The broker resolves the pull request itself, binds
approval to the exact head commit, rechecks it before execution, and passes it to GitHub as the
mutation's atomic `expectedHeadOid` guard. A pull request that changed between approval and
execution must be submitted and approved again.

## Bounded inputs

Request bodies, query sizes, pages, cursors, presentation text, event retention, grant duration,
and use counts all have limits. Path patterns are capped at 1,024 bytes and 256 segments for policy
values and 4,096 bytes and 256 segments for request values, and anything beyond fails closed.

Unknown command JSON fields, unsupported protocol versions, duplicate scalar query parameters,
invalid transitions, widened approval constraints, and unsupported state shapes are all rejected.

## Durability before acknowledgement

Transitions, events, idempotency records, reservations, and notification claims are persisted
atomically before success is acknowledged. A Telegram callback and its next update offset commit in
one transaction before the ingress answers Telegram.

The exception is deliberate: external audit export failure does not roll back committed authority.
It surfaces through the `X-Broker-Audit-Export` header and a safe diagnostic. Making a commit
conditional on an external log sink would let an unavailable sink deny access that policy already
granted.

## Verified executables

Persistent services execute only from a verified immutable host bundle. Callback consumers stop
before a release switch and start only after provider readiness succeeds.

Native service definitions point at the exact root-controlled `current` destination, and every
resulting process is verified against the selected immutable release before activation commits.
Operator credentials stay outside signed runtime manifests; a manifest may contain only the
absolute path of the token file needed for authenticated local readiness.

Exact generated Agent and Operator contract digests are required. A version label alone is never
compatibility evidence.

## Browser and host integration

Trusted web applications call the operator API from their server backend. They must not send
operator credentials to browsers and must not accept browser-supplied provider plans.

Broker sources are registered statically. Browser input cannot select an endpoint, a credential, a
proxy, a header, or an executable plan. A browser decision carries only the request ID, expected
revision, idempotency key, and bounded narrowing.

## Coverage limits

unYOLO does not sandbox provider code, validate arbitrary shell strings, proxy arbitrary
provider APIs, or replace host hardening and secret rotation. It does not protect a machine where
the broker account, state files, operator secret, provider credential, or privileged helper
endpoint is already compromised.

Those non-protections are stated explicitly in the
[threat model](/docs/security/threat-model), which is the page to read before deciding this fits
your environment.
