---
title: State maintenance
description: The offline check, backup, restore, and export commands, and why they require a stopped service.
---

Every broker exposes the same offline maintenance surface over its SQLite state:

```text
<broker> state check   --state-dir /absolute/state [--full]
<broker> state backup  --state-dir /absolute/state --output /absolute/new-backup
<broker> state restore --state-dir /absolute/state --backup /absolute/backup
<broker> state export  --state-dir /absolute/state --output /absolute/new-export.json
```

## Stopping the service

Maintenance commands acquire the unYOLO state lease, which the running service holds. That is
the mechanism behind the requirement rather than a convention, so a command run against a live
service fails rather than producing a torn result.

## No implicit migration

These commands accept only the exact current SQLite schema. They never create, migrate, or convert
a database while checking, backing up, or exporting it.

That is consistent with how unYOLO handles state format changes generally. A format change is an
explicit replacement performed during bundle activation: the old service stops, its state directory
is archived beside the original, and the candidate starts with fresh current-format state. Rollback
restores the archive with the old executable. Runtime compatibility readers and mixed-format state
are not supported, so a maintenance command that quietly upgraded a database would break the
rollback path it exists to protect.

## Backup

Backup uses SQLite's consistent backup API and publishes a private database plus a checksum
manifest. Both are needed for a restore.

```sh
sudo systemctl stop hf-broker
sudo -u hf-broker hf-broker state backup \
  --state-dir /var/lib/hf-broker \
  --output /var/backups/hf-broker-2026-07-28
sudo systemctl start hf-broker
```

## Restore

Restore validates format, integrity, checksum, size, ownership, and modes before replacing offline
state. A backup that fails any of those checks does not replace the current state, which is the
behaviour the corruption drill asserts.

```sh
sudo systemctl stop hf-broker
sudo -u hf-broker hf-broker state restore \
  --state-dir /var/lib/hf-broker \
  --backup /var/backups/hf-broker-2026-07-28
sudo systemctl start hf-broker
```

## Export

Export is deterministic and bounded, which makes it suitable for diffing two points in time or for
feeding an external inventory.

It omits operation inputs and results, reasons, plan bodies, decision tokens, notification
destinations, and credential material. What remains is lifecycle shape rather than content: enough
to answer what happened and when, and not enough to reconstruct what was pushed or executed.

```sh
sudo -u hf-broker hf-broker state export \
  --state-dir /var/lib/hf-broker \
  --output /tmp/hf-broker-export.json
```

## Checking integrity

`state check` verifies the database without modifying it. Add `--full` for the deeper pass when you
suspect corruption rather than as part of a routine.

Startup and restore both fail closed on corruption or an incompatible database. A broker that
cannot open its state does not start serving with an empty one, and readiness failing means the
listener does not receive traffic.

## State contents

The durable store holds grant lifecycle records with their revisions and events, idempotency
records, reservations, notification claims and delivery state, durable cursors, and operation
records. Retention is bounded, which is why an SSE cursor older than retained history returns
`410 cursor_expired` and the consumer has to refresh its list.

The Telegram ingress keeps its own separate SQLite inbox at
`/var/lib/unyolo-telegram/callbacks.db`, encrypted with the key in
`/etc/unyolo-telegram/inbox-key`. It is not covered by the broker state commands, and losing the
key while callbacks are pending makes those callbacks unreadable rather than falling back to
plaintext.

## Related drills

Two entries in the [failure drills](/docs/operate/failure-drills) matrix cover this surface
directly. SQLite corruption and incompatible restore must fail closed without replacing current
state, covered by `internal/storage/state/maintenance_test.go` and
`internal/storage/state/grants_test.go`. A read-only or failed durable write must not report any
decision or notification transition as committed, covered by `authorization/grants/grants_test.go`
and `authorization/grants/notifications_test.go`.
