---
title: Runtime bundles
description: Signed immutable release activation, atomic switching, rollback, and why state changes are replacements.
---

Persistent unYOLO services are deployed as one signed runtime bundle. The `unyolo` host
command stages each separately released broker and ingress binary under an immutable release
directory, verifies its digest and its exact Agent and Operator contract identities, then activates
the complete set together.

The reason for the ceremony is narrow. A host running `hf-broker`, `gh-broker`, `sudo-broker`, and
`unyolo-telegram` has four processes that speak generated contracts to each other. Upgrading
them one at a time creates a window where two of them disagree about the wire format, and the
Telegram ingress in particular can consume an update it cannot correctly route.

## Commands

```sh
unyolo system plan    --manifest manifest.json --signature manifest.sig --public-key release.pub
unyolo system install --manifest manifest.json --signature manifest.sig --public-key release.pub
unyolo system upgrade --manifest manifest.json --signature manifest.sig --public-key release.pub
unyolo system status
unyolo system doctor
unyolo system rollback
```

## Release layout

Linux uses `/opt/unyolo/releases/<bundle-id>` and macOS uses
`/Library/Application Support/unyolo/releases/<bundle-id>`. A `current` symlink points at the
active release and is switched atomically.

Native service definitions use exact component paths below that root-controlled pointer, and
production setup rejects standalone mutable executables. Each started process is then verified
against the selected immutable release, so a unit file that quietly points somewhere else does not
survive activation.

## Activation order

Providers stop after consumers and start before consumers. In practice that means the Telegram
ingress stops first and starts last, because it is the process that calls into the brokers.

Exact readiness is checked before the activation record commits. Any failure restores the previous
release pointer, the state replacement, the service order, and readiness before Telegram resumes.

Before stopping a service, the host writes a private activation transaction. An interrupted
install, upgrade, or rollback is reconciled under the host lock before another lifecycle command
can run: a committed and healthy candidate is kept, and an uncommitted transaction restores its
recorded previous release.

That reconciliation is what makes a power loss mid-upgrade a recoverable event rather than a
manual repair.

## The manifest

The closed `unyolo.io/runtime-bundle/v1` manifest is defined by
`protocol/runtime-bundle.schema.json`. A production manifest requires a detached Ed25519 signature.

`--development` permits unsigned local fixtures, but development build identities cannot enter a
signed production bundle. Development activation also requires explicit isolated root and state
directories and cannot write the production activation paths, so the two modes cannot be confused
at runtime.

The public key supplied for the first production install is pinned under the private host state
directory. Later plans and upgrades use that pinned key and reject an attempted key replacement.

Each required provider component names its local Operator endpoint and the absolute path of its
Operator token file. The token itself is never stored in the manifest. Activation and `doctor` use
that local credential to verify the running provider's exact contract and build identity without
exposing it.

## State format replacement

unYOLO does not run migrations, and it has no runtime compatibility readers. A state-format
change is an explicit replacement: the old service stops, its state directory is archived beside
the original, and the candidate starts with fresh current-format state.

Rollback restores the archived directory together with the old executable. Mixed-format state is
not a supported condition.

This trade is deliberate. Compatibility readers accumulate, they are hard to test against every
historical shape, and they turn a rollback into a question of whether the new code wrote something
the old code will misread. Replacing the directory makes rollback a file move.

## Host health

`unyolo system doctor` compares the activation record, the immutable artifact digests, the
native service state, the process executable paths, and the active bundle.

A host is unhealthy when an artifact digest changes, a required service is inactive, a process
executable differs from the immutable active release, a Linux executable is marked `(deleted)`, or
a rollback did not complete.

The `(deleted)` check catches a specific and easy-to-miss failure. Replacing a binary on disk while
its old process keeps running leaves a service that reports as active while executing code nobody
can inspect. Linux marks that executable path as deleted, and the host doctor treats it as
unhealthy rather than as a running service.

```sh
unyolo system status --json
unyolo system doctor --json
```

Both produce a closed report containing bundle IDs, release build IDs, artifact digest results,
native service names, PIDs, executable paths, active state, and recovery-required state. Neither
contains credentials, Telegram destinations, decision authority, reasons, or provider payloads.

## Contract identity

Exact Agent and Operator digests are exposed by discovery and health responses, so clients can
report contract drift without logging response bodies.

A version label alone is never treated as compatibility evidence. The Telegram ingress compares
each route's exact digest before every poll batch, and a mismatch makes it exit without consuming
another update, which leaves the service manager or a bundle rollback to repair the host.
