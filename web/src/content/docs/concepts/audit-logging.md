---
title: Audit logging
description: The shared audit event shape, what is excluded from it by rule, and how it differs from metrics.
---

Every broker emits JSON audit events with the same common fields, so a host running three brokers
gets one comparable stream rather than three formats. Audit is the security evidence trail;
[metrics](/docs/operate/observability) report aggregate behaviour and are not a substitute.

## Event fields

```text
time
broker
client
operation
target
attrs
decision
reason
matched_rule_ids
grant_id
approver
status
duration
error_code
extensions
```

`matched_rule_ids` is the field that earns its place. It records which policy rules matched, which
turns the log into a way to audit the policy itself: a rule that never appears is dead or misnamed,
and a rule appearing on requests you did not expect is too broad.

Broker-specific metadata goes under typed `extensions` rather than being spliced into the common
fields.

## Exclusions

Audit output must never include upstream tokens, broker client secrets, approval tokens, Telegram
bot tokens, request bodies that may contain secrets, Git pack contents, command input or command
output by default, raw upstream responses, or token metadata.

The exclusion of token metadata is deliberate and easy to miss. Recording that a token has a
particular scope set, expiry, or fingerprint leaks structure about the credential, so the audit
record stays with the decision rather than describing the secret used to act on it.

## Credential lifecycle events

Setup emits one `credential.lifecycle` audit event for each credential class it creates, rotates,
or locally retires. Each event contains the actor, the class, the outcome, and truncated SHA-256
identifiers for the old and new protected material. It carries no credential values, paths, provider
targets, or raw errors.

Truncated digests are there so you can correlate a rotation across systems without the log
containing anything usable.

If audit output fails after a successful readiness check, setup reports that as a partial
operational failure and does not restore an old credential. A committed cutover stays committed.

## Record destinations

`hf-broker` keeps credential lifecycle events in a protected append-only
`credential-lifecycle.jsonl` in the installed broker config directory, which is `/etc/hf-broker` on
Linux. They are kept out of ordinary terminal output on purpose. Add `--verbose` to mirror those
secret-safe JSON records to standard error while troubleshooting.

Native Git discovery, upload-pack, receive-pack, and LFS requests emit the provider's normal policy
and proxy audit records. The dedicated Git listener's identity response contains only the provider
ID, and credential-helper input, output, and Basic credentials are never logged.

## Export failure

An external audit exporter that fails after a decision has committed cannot turn that decision into
an apparent failure. The committed lifecycle stays authoritative and a safe diagnostic is emitted;
on the operator API the failure surfaces in the `X-Broker-Audit-Export` response header.

This is a deliberate trade. Making commit conditional on export would mean an unavailable log
sink could deny access that policy already granted, and turning a committed grant into a reported
failure would leave the caller and the broker disagreeing about what happened.

## Diagnostics on stderr

Alongside audit, the shared boundary writes JSON diagnostics to stderr for operation start and
completion, approval-notification delivery, and durable dependency retries. These are operational
records rather than security evidence, and they are more heavily reduced.

Each record contains a stable event name, the broker or provider, an opaque bounded correlation ID,
the catalog risk class, a closed result, a closed error category, and a bounded duration. They
never contain the operation name, target, reason, repository, user, path, command, URL, token, or
raw error.

Broker-owned failure codes reduce to a closed set before either the logs or the metric labels see
them: `authentication`, `authorization`, `canceled`, `conflict`, `invalid_response`, `rate_limited`,
`rejected`, `storage`, `timeout`, `unavailable`, or `other`.

## Provider errors

A provider error can carry sensitive data, so the public API maps it to a closed error code and
keeps detail only in provider-owned, secret-safe audit data. That is why a client sees a stable
code while the audit stream can hold more context.

## Testing the guarantee

The shared test contract requires every broker to assert that audit output contains no secrets, and
CI runs `gitleaks` across the repository. The relevant drills live in
[failure drills](/docs/operate/failure-drills), which pairs each failure class with the tests
that cover it.
