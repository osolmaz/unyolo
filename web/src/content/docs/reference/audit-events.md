---
title: Audit events
description: Field reference for audit records, the closed error categories, and the exclusion list.
---

Every broker emits JSON audit events with the same common fields. This is the field reference; the
[audit logging](/docs/concepts/audit-logging) page covers how audit differs from metrics and why
export failure does not roll back authority.

## Common fields

| Field | Meaning |
| --- | --- |
| `time` | Event timestamp. |
| `broker` | Broker name, for example `hf-broker`. |
| `client` | Authenticated client identity. |
| `operation` | Registered operation name. |
| `target` | Classified target object. |
| `attrs` | Classified attrs. |
| `decision` | `allow`, `request`, `deny`, or `no_match`. |
| `reason` | Caller-supplied reason where one exists. |
| `matched_rule_ids` | Policy rule IDs that matched. |
| `grant_id` | Grant involved, where one exists. |
| `approver` | Operator identity for a decision event. |
| `status` | Outcome status. |
| `duration` | Bounded duration. |
| `error_code` | Closed error code. |
| `extensions` | Typed broker-specific metadata. |

`matched_rule_ids` is the field that makes the log useful for auditing the policy rather than just
the traffic. A rule that never appears is dead or misnamed. A rule appearing on requests you did
not expect is too broad.

Broker-specific metadata belongs under typed `extensions` rather than being spliced into the common
fields.

## Exclusion list

Audit output must never include:

- upstream tokens
- broker client secrets
- approval tokens
- Telegram bot tokens
- request bodies that may contain secrets
- Git pack contents
- command input or command output by default
- raw upstream responses
- token metadata

Token metadata is on the list for a reason that is easy to miss. Recording a credential's scope
set, expiry, or fingerprint describes the secret rather than the decision, and the audit record's
job is the decision.

## Closed error categories

Broker-owned failure codes reduce to this set before either logs or metric labels see them:

```text
authentication  authorization  canceled   conflict
invalid_response  rate_limited  rejected   storage
timeout           unavailable   other
```

## Credential lifecycle events

Setup emits one `credential.lifecycle` event per credential class it creates, rotates, or locally
retires. Each contains the actor, the class, the outcome, and truncated SHA-256 identifiers for the
old and new protected material. It contains no credential values, paths, provider targets, or raw
errors.

`hf-broker` writes these to the protected append-only `credential-lifecycle.jsonl` in the installed
config directory, `/etc/hf-broker` on Linux, rather than into terminal output. Add `--verbose` to
mirror them to standard error while troubleshooting.

## Structured diagnostics

Separate from audit, the shared boundary writes JSON diagnostics to stderr for operation start and
completion, approval-notification delivery, and durable dependency retries.

| Field | Meaning |
| --- | --- |
| event name | Stable identifier for the diagnostic. |
| broker or provider | Which component emitted it. |
| correlation ID | Opaque and bounded; ties the record to an audit entry. |
| risk class | Catalog risk classification. |
| result | Closed result value. |
| error category | One of the closed categories above. |
| duration | Bounded duration. |

These records never contain the operation name, target, reason, repository, user, path, command,
URL, token, or raw error. When you need that detail, the correlation ID leads to the audit record
that has it.

## Git and Telegram

Native Git discovery, upload-pack, receive-pack, and LFS requests emit the provider's normal policy
and proxy audit records. The Git listener's identity response contains only the provider ID.
Credential-helper input and output are never logged, and neither are Basic credentials.

Telegram callback authority is observable only as aggregate queue lifecycle. Operational logs may
report callback receipt, retry, terminal state, route, update ID, and a bounded attempt count. They
must not report callback data, decision tokens, rendered messages, usernames, or chat IDs.

## Host diagnostics

`brokerkit system status --json` and `brokerkit system doctor --json` emit a closed host-level
report: bundle IDs, release build IDs, artifact digest results, native service names, PIDs,
executable paths, active state, and recovery-required state. Neither contains credentials, Telegram
destinations, decision authority, reasons, or provider payloads.

## Export failure

An external audit exporter that fails after a decision has committed cannot turn that decision into
an apparent failure. The committed lifecycle stays authoritative and a safe diagnostic is emitted;
on the operator API the failure surfaces in the `X-Broker-Audit-Export` response header.

## Verification

The shared test contract requires every broker to assert that audit output contains no secrets, and
CI runs `gitleaks` with redaction across the repository. Related drills are in
[failure drills](/docs/operate/failure-drills).
