# Atomic Runtime Bundle Implementation Plan

Date: 2026-07-21

Status: implemented; release qualification pending

## Objective

unYOLO needs one host-level installation and upgrade transaction for every
component that participates in an approval. The brokers remain separate
processes, release artifacts, credential domains, listeners, state stores, and
audit streams. A signed bundle manifest pins the compatible artifacts and the
host runtime activates them together.

An installed system must never report healthy while a running process uses a
different Operator contract from its peers. Telegram decisions must also
survive restarts and temporary route failures without being lost.

## Incident That Motivated This Work

On 2026-07-21, `unyolo-telegram.service` was still running a deleted
`0.1.0+70dc15c` executable after a newer binary had replaced the file on disk.
The GitHub broker used a newer Operator V1 decision schema. Telegram delivered
notifications successfully, but button clicks sent the old decision payload.
The broker rejected it because required presentation evidence was missing, and
the ingress reduced the error to `Broker temporarily unavailable`.

The services, sockets, and credentials were healthy. The failure came from
four lifecycle gaps:

- component installers could replace binaries independently;
- replacing a binary did not guarantee that its service restarted;
- Operator discovery identified only `unyolo.io/operator/v1`, even when the
  in-place v1 schema had changed; and
- Telegram acknowledged a failed callback without a durable retry record.

This plan removes those gaps together. Restarting one service is an immediate
repair, but it does not meet the objective.

## Design Rules

1. Broker processes and provider ownership boundaries stay separate.
2. The host activates one reviewed set of compatible artifacts.
3. Running executables come from immutable release directories.
4. Operator clients and servers require an exact contract digest.
5. Telegram persists callbacks before acknowledging them.
6. Activation either commits the complete bundle or restores the previous one.
7. Linux and macOS expose the same host lifecycle through native service
   adapters.
8. Pre-release formats remain at version 1 and are replaced in place. No
   compatibility readers, dual protocols, fallback payloads, or mixed-version
   mode will be added.

## Target Architecture

### Host command

Add `cmd/unyolo` as the operator-facing host command. Its system lifecycle is
provider-neutral:

```text
unyolo system plan
unyolo system install --manifest <path-or-release>
unyolo system upgrade --manifest <path-or-release>
unyolo system status [--json]
unyolo system doctor [--json]
unyolo system rollback
```

Provider commands continue to own credentials, policy, catalogs, and provider
configuration. `unyolo system` owns artifact staging, release activation,
service ordering, compatibility checks, rollback, and host-level evidence.

### Immutable host layout

Linux uses:

```text
/opt/unyolo/releases/<bundle-id>/
  manifest.json
  bin/unyolo-telegram
  bin/gh-broker
  bin/hf-broker
  bin/sudo-broker
  libexec/sudo-broker-exec

/opt/unyolo/current -> releases/<bundle-id>
/var/lib/unyolo-host/activation.json
/var/lib/unyolo-host/activation.lock
```

macOS uses the same internal layout beneath:

```text
/Library/Application Support/unyolo/releases/<bundle-id>/
/Library/Application Support/unyolo/current
/Library/Application Support/unyolo/activation.json
```

Configuration and broker state remain in their existing provider-owned
locations. Public command links, systemd units, and launchd plists use the
root-controlled `current` path. Starting a service resolves that pointer to an
executable in one immutable release, and runtime verification checks the
process against that exact release. Setup rejects a mutable executable path
such as a standalone file in `/usr/local/bin` for managed production services.

Release directories are root-owned, non-symlinked below their release root,
and not writable by service accounts or agents. The `current` link is the only
mutable release pointer.

### Bundle manifest

Create a closed `unyolo.io/runtime-bundle/v1` manifest. It contains no
credentials or machine-specific configuration.

```json
{
  "api_version": "unyolo.io/runtime-bundle/v1",
  "bundle_id": "2026.07.21.1",
  "source_commit": "<full commit sha>",
  "operator_contract_digest": "sha256:<digest>",
  "components": [
    {
      "name": "unyolo-telegram",
      "release_tag": "unyolo-telegram/v0.2.0",
      "asset": "unyolo-telegram_0.2.0_linux_amd64.tar.gz",
      "sha256": "<digest>",
      "required": true
    }
  ]
}
```

The final schema also records:

- artifact provenance identity and signer workflow;
- operating system and architecture;
- executable name, mode, and relative destination;
- build identity for every executable;
- Agent and Operator contract digests used by that component;
- state-format and configuration-contract digests;
- the services and sockets owned by each component; and
- minimum host-command version.

The release workflow generates and attests the manifest after all referenced
component releases exist. A bundle resolves every tag once to an immutable
commit and asset digest. Installation downloads and verifies the complete set
before changing the host. Partial or mutable manifests are rejected.

Separate provider release tags remain available for development and client-only
installation. Managed production services install only through a bundle.

## Exact Protocol Identity

### Canonical digest

Extend the protocol generator to derive a deterministic SHA-256 digest from
the canonical Operator OpenAPI document and every generated closed schema that
defines its wire behavior. The generator emits the digest into:

- `operator/v1` as a build constant;
- generated Go and TypeScript protocol packages;
- the runtime bundle manifest; and
- release metadata checked by CI.

The digest is based on canonical structured content rather than YAML layout,
comments, timestamps, or generator paths. CI regenerates it and rejects drift.

### Discovery and readiness

Replace the Operator V1 descriptor in place with required fields:

```json
{
  "api_version": "unyolo.io/operator/v1",
  "contract_digest": "sha256:<digest>",
  "build_id": "gh-broker/v0.4.0+<commit>"
}
```

Agent discovery receives the same treatment because host bundles also pin
agent-facing clients. Health responses include the active build and contract
digests. A health response is ready only after configuration, state, policy,
credentials, and protocol identity are ready.

The Operator client requires both the API version and contract digest to
match. Unknown or missing digests fail closed. `unyolo-telegram` checks every
configured route before polling and repeats the check periodically. A mismatch
stops polling and makes ingress readiness fail.

The host command checks the manifest, every executable on disk, every running
process, and every authenticated discovery response. Linux diagnostics also
detect `/proc/<pid>/exe (deleted)`. macOS uses the native process executable
lookup. Any disagreement makes `unyolo system status` unhealthy.

## Transactional Activation

### Preflight

`unyolo system install` and `upgrade` acquire the host activation lock and
complete all checks before stopping a service:

1. verify manifest schema, signature, provenance, and component completeness;
2. verify every archive and executable digest;
3. reject unsafe ownership, modes, symlinks, and destinations;
4. inventory configured components, units, sockets, state paths, and current
   running builds;
5. validate that all selected components share the manifest contract digest;
6. validate provider configuration using the staged binaries;
7. check disk space and create bounded offline state backups when required;
8. render the complete Linux or macOS activation plan without mutation.

The plan records every intended file, link, service action, readiness probe,
and rollback action. Dry-run output contains no secrets.

### Activation order

The host command then performs one bounded transaction:

1. stop `unyolo-telegram` so Telegram retains new updates upstream;
2. stop optional shared UI consumers;
3. stop provider services and their socket activation units;
4. fsync the staged release and atomically switch `current`;
5. reload native service definitions that point through the managed `current` path;
6. start provider sockets and brokers;
7. verify authenticated discovery, readiness, state, and contract identity;
8. start Telegram ingress and other shared consumers;
9. verify ingress route health and the running process inventory;
10. run the post-activation approval smoke suite;
11. commit `activation.json` and retire the bounded previous release set.

The provider services start before any callback consumer. Socket activation is
disabled during the switch so an old or partially activated process cannot be
started by traffic.

### Rollback

Any failure before the activation record commits triggers rollback:

1. stop every process from the candidate release;
2. restore the previous `current` link and unit definitions;
3. restore any state directory replaced by an explicit state-format change;
4. reload the native service manager;
5. start the previous provider services and verify their exact digests;
6. start the previous Telegram ingress only after all routes are ready;
7. preserve a redacted failure record for `doctor` and audit.

Rollback runs with a fresh bounded context so cancellation of the original
command cannot interrupt recovery. If rollback fails, Telegram stays stopped,
all admission endpoints remain closed, and the host reports a recovery-required
state. The command never marks a partial activation successful.

### State format changes

The manifest records a state-format digest for each broker. An unchanged digest
reuses the existing state. A changed digest requires an explicit replacement
declaration and an offline backup produced by the old binary before activation.
The new binary starts with fresh current-format state. Rollback restores the old
state and old binary together.

No binary reads an older state format. Successful replacement may archive the
old backup for the configured retention period, but it cannot load or migrate
it into the new format.

## Native Service Integration

### Linux

Install a `unyolo.target` that groups the configured unYOLO units. Each
unit declares `PartOf=unyolo.target`, while the host command retains explicit
start and readiness ordering. The target supports status, emergency stop, and
operator inspection. It is not used as a substitute for the activation
transaction.

Existing single-provider setup commands write service definitions through the
shared systemd runtime and require the exact managed `current` destination for
production. The stable unit definitions are not rewritten during an upgrade.
Production setup refuses standalone executables and independent binary
replacement when a service belongs to a bundle.

### macOS

Add the equivalent multi-service transaction over system LaunchDaemons. The
host command boots out Telegram first, activates provider daemons, verifies
their Unix sockets and discovery responses, and then bootstraps Telegram.
Plists point through the root-controlled `current` path. Rollback restores the
previous release pointer without rewriting the stable plist set.

Both adapters implement the same typed host plan and emit the same activation
record. Platform packages contain service-manager mechanics only.

## Durable Telegram Decision Inbox

Add a private SQLite database under the Telegram ingress state directory. It
owns the update offset and callback delivery lifecycle. Decision tokens are
stored only in an encrypted bounded envelope using a service-owned key. They
are removed as soon as the decision reaches a terminal state or its pending
deadline passes.

The callback path becomes:

1. receive and validate the Telegram update;
2. atomically persist its update ID, callback ID, route, message identity,
   encrypted decision authority, and expiry;
3. persist the next Telegram offset in the same transaction;
4. answer the callback with neutral receipt text;
5. dispatch the decision to the owning broker;
6. retry bounded transient failures with jittered backoff;
7. persist the broker's terminal response;
8. update the Telegram message and remove its buttons;
9. delete the encrypted authority and retain only redacted lifecycle evidence.

A uniqueness constraint on update ID and callback ID makes replay idempotent.
The existing broker idempotency key remains the final mutation guard. Route
failure cannot block healthy routes because workers lease queue entries by
route. Restart recovery resumes unexpired entries before polling for more
updates.

Contract mismatch is handled before polling, so it produces no callback queue.
A broker that becomes unavailable after polling leaves callbacks durable until
the route recovers or the grant expires. Expiry renders the authoritative
closed state and clears buttons.

## Installer and Release Work

1. Add the host command and closed bundle-manifest schema.
2. Extend `internal/tooling/release` to emit reproducible component metadata.
3. Add a bundle release workflow that verifies every referenced release asset,
   checksum, and attestation before publishing its own attested manifest.
4. Stage complete releases in immutable directories and fsync before publish.
5. Make broker service setup register its unit and executable with the host
   inventory.
6. Reject independent production binary replacement for bundle-owned units.
7. Keep user-local client installation independent because it creates no
   persistent service and participates in no approval callback path.

Release archives and manifests use full commit SHAs. Production binaries must
report a release build ID; a `dev-*` build is rejected unless the operator
selects an explicit development mode that cannot overwrite a production
activation.

## Doctor and Observability

`unyolo system doctor` reports one row per component with:

- desired and running build IDs;
- desired and discovered contract digests;
- configured executable and actual process executable;
- service-manager state and PID;
- route discovery and health state;
- callback queue depth and oldest age;
- active and previous bundle IDs; and
- pending rollback or recovery state.

Text output shows no tokens, callback payloads, reasons, Telegram destinations,
or provider credentials. JSON output uses a closed schema.

Add structured events and metrics for activation stage, rollback, protocol
mismatch, deleted running executable, callback receipt, retry, terminal
decision, queue age, and route health. Callback failures log the operator error
code, HTTP status, route, grant correlation ID, and unYOLO correlation ID.
Raw response bodies remain excluded.

An unavailable callback increments a dedicated counter. A protocol mismatch or
deleted executable is a readiness failure rather than a warning.

## Test Strategy

### Unit and package tests

Cover:

- canonical protocol and manifest digest generation;
- strict manifest parsing, signatures, platform selection, and path safety;
- immutable release publication and atomic link replacement;
- every activation failure point and reverse-order rollback;
- state-digest replacement and old-state restoration;
- systemd and launchd plan validation and command ordering;
- Telegram callback encryption, leases, retries, expiry, replay, and cleanup;
- process identity and deleted-executable detection; and
- secret redaction in every new error and diagnostic surface.

Use failpoints around every filesystem, service-manager, readiness, SQLite, and
rollback boundary. Tests assert final files, running release, state ownership,
and durable callback state.

### Upgrade qualification

CI installs the previous published bundle in a clean Linux VM, configures all
three routes, and creates a pending approval. It then upgrades to the candidate
bundle and verifies:

1. every running executable belongs to the candidate release;
2. every discovery response has the candidate contract digest;
3. the pending Telegram decision succeeds exactly once after restart;
4. GH and HF operations resume through Agent and Git transports;
5. sudo executes only the approved catalog command;
6. rollback restores the previous complete bundle after injected failure.

A dedicated regression fixture recreates the 2026-07-21 incident by pairing an
old Telegram binary with a new Operator server. Preflight and runtime readiness
must reject the pair before Telegram polling begins.

Run the same lifecycle on a macOS runner using launchd. Local fake Telegram and
provider servers cover deterministic failures. Release qualification also runs
one real Telegram approval per configured provider in the target deployment.

### Required repository gates

The implementation must pass the repository's normal Go, lint, Slophammer,
protocol-generation, schema, release, Linux, macOS, and packed-install checks.
Mutation tooling remains disabled unless explicitly requested.

## Implementation Order

### 1. Contract identity

- Generate deterministic Agent and Operator contract digests.
- Add required digest and build fields to discovery and health.
- Make all clients enforce exact identity.
- Add mixed-build regression tests.

### 2. Bundle and host inventory

- Add the manifest schema, parser, verifier, and release inventory.
- Add immutable platform layouts and activation records.
- Implement `plan`, `status`, and `doctor` before mutation commands.

### 3. Host transaction

- Add the typed multi-service plan.
- Implement Linux activation and rollback.
- Implement the matching macOS transaction.
- Route provider service setup through the host inventory.

### 4. Durable Telegram intake

- Add the encrypted callback database and persisted offset.
- Move polling through the durable dispatcher.
- Add route leases, retry, expiry, and terminal rendering.
- Require contract readiness before polling.

### 5. Signed bundle release

- Publish reproducible host manifests that pin existing component artifacts.
- Verify the full set before installation.
- Enforce release build IDs and reject mutable production executables.

### 6. Qualification and deployment

- Run previous-to-candidate upgrades on Linux and macOS.
- Run rollback and stale-process drills.
- Install the bundle on the test host and perform real callbacks for every
  configured route.
- Promote the release only after running process inventory and live decisions
  are green.

These steps form one release. Do not ship a host upgrader that lacks protocol
identity or a durable Telegram path.

## Acceptance Criteria

The work is complete when:

1. managed production services execute only from an immutable active release;
2. replacing a file cannot leave a deleted executable reported as healthy;
3. every installed artifact is pinned by one signed and attested bundle
   manifest;
4. Agent and Operator discovery expose deterministic exact contract digests;
5. every client rejects a missing or different digest before performing work;
6. Telegram verifies every route before polling and periodically afterward;
7. one command activates or rolls back the complete configured component set;
8. candidate failure restores the previous binaries, units, and state before
   Telegram resumes;
9. Linux systemd and macOS launchd pass the same transaction contract;
10. service setup cannot independently overwrite a bundle-owned executable;
11. Telegram update offsets and callbacks survive process and host restarts;
12. transient broker failures retry without losing or duplicating decisions;
13. terminal broker decisions always remove Telegram buttons after eventual
    reconciliation;
14. callback authority is encrypted at rest and removed after closure;
15. doctor detects version drift, protocol drift, deleted executables, route
    failure, queue backlog, and incomplete rollback;
16. the old-ingress/new-broker regression fails readiness before consuming a
    callback;
17. upgrade qualification covers GH, HF, sudo, Telegram, Agent V1, Operator V1,
    Git, and MCP on the candidate release;
18. rollback failure leaves admission and callback consumption closed;
19. no legacy protocol payload, state reader, alias, or mixed-version fallback
    remains; and
20. maintained deployment, Telegram, operations, failure-drill, and
    observability documentation describes the implemented bundle lifecycle.

## Documentation Changes During Implementation

Update these maintained documents with the final behavior:

- `docs/OPERATIONS_RUNTIME.md`
- `docs/SYSTEMD_INSTALL_RUNTIME.md`
- `docs/TELEGRAM_INGRESS.md`
- `docs/FAILURE_DRILLS.md`
- `docs/OBSERVABILITY.md`
- `docs/ARCHITECTURE.md`
- `docs/security/THREAT_MODEL.md`
- `docs/README.md`

After live qualification, change this plan's status to complete and record the
release, exact commit, upgrade fixture, rollback result, and target-host
verification.
