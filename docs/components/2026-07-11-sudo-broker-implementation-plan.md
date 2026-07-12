# sudo-broker Implementation Plan

Date: 2026-07-11

Status: implementation, repository review, CI, live isolated privilege test,
and coordinated installation complete; first component release pending

Monorepo destination: `brokers/sudo`

Required companion plans:

- `docs/2026-07-11-universal-broker-platform-plan.md`
- `docs/2026-07-11-monorepo-consolidation-plan.md`

## Outcome

Build `sudo-broker` as a separate local authority service that lets an
authenticated agent request one cataloged command as a configured Unix user,
routes approval through BrokerKit Operator V1, validates the exact canonical
plan again at activation and execution, and records a secret-safe audit result.

The supported V1 operation is deliberately narrow:

```text
exec.command
```

V1 does not support arbitrary command lines, shell strings, interactive shells,
TTY attachment, generic `sudo` flags, user-provided environment variables,
background daemons, or command discovery outside the root-owned catalog.

## Security Boundary

`sudo-broker` is a separate executable, process, listener, credential domain,
state directory, and audit stream. BrokerKit shared packages, HF/GH brokers,
the OpenClaw plugin, and the Gateway remain unprivileged.

The deployment uses privilege separation:

```text
agent
  -> unprivileged sudo-broker frontend
       -> BrokerKit policy/grant/approval state
       -> canonical plan store
       -> local authenticated executor protocol
            -> minimal privileged sudo-broker-exec helper
                 -> exact cataloged exec as target user
```

The privileged helper is not a generic root shell. It independently loads the
root-owned command catalog, validates the received plan and file-system facts,
accepts only the dedicated broker service identity over a local Unix socket,
enforces one-shot execution ids, clears the environment, applies limits, and
executes only a declared command shape.

Compromise of another monorepo artifact must not make the helper reachable.
Repository co-location does not relax runtime separation.

## Package Layout

```text
brokers/sudo/
  cmd/
    sudo-broker/
      main.go
    sudo-broker-exec/
      main.go
  internal/
    catalog/
    executorclient/
    executorprotocol/
    executorserver/
    hostcheck/
    plan/
    presenter/
    privexec/
    routes/
    sudopolicy/
  docs/
    threat-model.md
    operations.md
    catalog.md
  catalog.example.json
```

Provider-specific code remains under `brokers/sudo`. Shared BrokerKit packages
must not import it.

## Command Catalog

The operator creates one root-owned JSON file. Minimal example:

```json
{
  "version": 1,
  "commands": [
    {
      "id": "nginx-reload",
      "executable": "/usr/bin/systemctl",
      "arguments": [
        { "literal": "reload" },
        { "literal": "nginx.service" }
      ],
      "target_users": ["root"],
      "working_directory": "/",
      "timeout_seconds": 30,
      "max_output_bytes": 65536
    }
  ]
}
```

The catalog is loaded at process start into an immutable validated snapshot.
There is no agent/operator API to read, write, reload, or enumerate the raw
catalog. A bounded agent route may list command ids and safe descriptions only
when policy permits `catalog.read`; that route is outside the execution path
and never returns executable paths/templates unless explicitly marked safe.

### Catalog fields

| Field | Required | Rule |
| --- | --- | --- |
| `version` | Yes | Exactly `1`. |
| `commands` | Yes | 1-1024 unique command definitions. |
| `id` | Yes | 1-64 lowercase alphanumeric/hyphen characters. |
| `executable` | Yes | Absolute, normalized, non-symlink executable path. |
| `arguments` | Yes | 0-64 closed argument specifications. |
| `target_users` | Yes | 1-16 existing non-numeric user names. |
| `working_directory` | Yes | Absolute fixed directory, not agent-selected. |
| `timeout_seconds` | Yes | Integer 1-3600. |
| `max_output_bytes` | Yes | Integer 0-1,048,576 across stdout/stderr. |
| `environment` | No | Closed fixed name/value map; omission means empty baseline. |
| `description` | No | Bounded safe operator text. |
| `risk` | No | `low`, `medium`, or `high`; omission is `high`. |

Unknown fields are errors. Duplicate command ids, duplicate environment names,
NUL/control characters, relative paths, empty values, and values beyond limits
are errors. Catalog errors stop both frontend and helper readiness.

### Argument specifications

V1 supports only:

```json
{ "literal": "nginx.service" }
```

and bounded typed slots:

```json
{
  "slot": "replicas",
  "type": "integer",
  "minimum": 0,
  "maximum": 20
}
```

```json
{
  "slot": "environment",
  "type": "enum",
  "values": ["staging", "production"]
}
```

```json
{
  "slot": "artifact",
  "type": "path_beneath",
  "roots": ["/srv/releases"],
  "must_exist": true,
  "file_type": "regular"
}
```

There are no regex, glob, raw string, variadic, shell fragment, flag map, or
unbounded path slots. Integer values are rendered canonically in base ten.
Enum values match exact bytes. Path slots are resolved without following a
symlink outside an allowed root and are revalidated by the helper immediately
before execution.

## Agent Request

The authenticated agent route accepts:

```json
{
  "command_id": "scale-worker",
  "target_user": "deploy",
  "arguments": {
    "environment": "production",
    "replicas": 4
  },
  "reason": "Increase capacity for the release"
}
```

The route rejects unknown fields, duplicate JSON keys, missing/extra slots,
wrong types, non-canonical numbers, target users not declared by the command,
and requests outside body limits. It never accepts executable, argv, cwd,
environment, timeout, uid/gid, shell, TTY, stdin, output path, or file
descriptor fields.

Authentication identifies the BrokerKit client. Policy classifies:

- operation: `exec.command`;
- target kind: `user`;
- target: normalized target user;
- attrs: command id plus bounded typed slot facts needed by configured policy.

Policy attrs contain no executable path or secret. An unclassified request is
denied.

## Canonical Plan

After request/schema/catalog/policy validation, the broker creates one
content-addressed immutable plan before creating the pending grant:

```go
type Plan struct {
    Version          uint8
    RequestID        string
    ClientID         string
    CommandID        string
    TargetUser       string
    TargetUID        uint32
    TargetGID        uint32
    SupplementaryGIDs []uint32
    Executable       string
    Arguments        []string
    WorkingDirectory string
    Environment      []string
    TimeoutSeconds   uint32
    MaxOutputBytes   uint32
    CatalogDigest    string
    CreatedAt        time.Time
}
```

The stored digest is `sha256` over deterministic canonical encoding. It binds
the grant to client, request, command, target identity, exact argv, cwd,
environment, limits, and catalog snapshot. The plan contains no credential or
approval presentation.

Plan creation resolves user/group ids and every slot once. It rejects a target
identity that is ambiguous, disabled by host policy, or changes during
resolution. The plan store writes the plan atomically before making its grant
visible. An orphan plan is harmless and garbage-collected; a visible grant
without its exact plan fails closed.

## Activation Validation

BrokerKit's single `DecisionService` calls the sudo-owned activation validator
for every operator HTTP, channel, CLI, and future decision path. Approval is
refused unless:

- the immutable plan exists and its digest matches the grant binding;
- request/client/operation/target match the grant;
- the command still exists in the current catalog with the same security
  digest;
- target user and group identities still resolve to the pinned ids;
- executable, cwd, and path-slot host facts still pass;
- requested duration/max uses remain within one short one-shot command grant;
- no previous execution/reservation is unresolved; and
- the helper readiness and protocol version are healthy.

V1 approvals always use `max_uses = 1`. The grant expiry cannot exceed the
short broker-configured ceiling and is narrowed by the operator when offered.

## Provider Presentation

The sudo presenter emits bounded plain text:

```text
Title: Run privileged command
Summary: Run nginx-reload once as root.
Risk: high
Facts:
  Command: nginx-reload
  Target user: root
  Working directory: /
  Timeout: 30 seconds
  Arguments: fixed by catalog
```

For typed slots, show each safe normalized value. Path facts show only the
bounded operator-reviewed path. Presentation never exposes environment values
marked sensitive, internal helper paths, plan digests, socket paths, policy
files, client secrets, or raw serialized plans.

Presenter failure uses BrokerKit's safe fallback and cannot broaden actions or
bounds.

## Privileged Helper Protocol

The helper listens only on a root-owned Unix socket whose directory is not
traversable by other users. It authenticates peer credentials and permits only
the configured unprivileged broker uid. Network sockets are forbidden.

Request:

```text
protocol version
execution id
plan canonical bytes
plan digest
grant/request id
reservation id
expiry
```

The protocol is length-prefixed, bounded, strictly decoded, and rejects
unknown fields/version. It does not accept a shell command or generic options.

The helper independently:

1. checks peer uid and request freshness;
2. atomically records/claims the one-shot execution id;
3. verifies canonical encoding and digest;
4. loads and verifies the root-owned catalog snapshot;
5. checks command/target/argv/cwd/environment/limits against the catalog;
6. re-resolves target identity and filesystem facts;
7. creates pipes with close-on-exec, clears inherited descriptors/environment,
   applies resource limits, drops supplementary groups/gid/uid, and execs;
8. enforces timeout and output caps; and
9. returns a bounded structured outcome.

The execution-id claim survives helper restart long enough to prevent replay.
A duplicate id returns the original terminal result when known or an ambiguous
status when execution may have started. It never runs twice to make a retry
look successful.

## Filesystem And Process Safety

- Catalog, config, secret, plan, state, socket directory, helper binary, and
  executable path chains must pass owner/mode/ACL checks.
- Reject symlinked or non-absolute security-sensitive paths.
- On Linux, use descriptor-relative/openat2-style resolution and execveat/fd
  execution where supported to close path replacement races.
- On macOS, use the strongest available no-follow descriptor checks and repeat
  identity/mode checks immediately before exec; document residual race limits.
- Reject executable/cwd/path components writable by the broker uid, target
  user, or untrusted groups unless the command's threat model explicitly
  treats that content as data and the executable remains trusted.
- Start from an empty environment. Add only a fixed safe baseline and
  catalog-fixed names. Reject `LD_*`, `DYLD_*`, interpreter startup, locale/path
  injection, and name/value control characters.
- Set a fixed safe `PATH` only if an executable legitimately spawns declared
  children; prefer absolute child paths.
- Stdin is `/dev/null`. V1 has no TTY.
- Apply process group, timeout, file-size, descriptor, process-count, core-dump,
  and output limits before dropping identity/exec.
- Kill the entire process group on timeout and reap it.

## Reservation And Settlement

Execution uses BrokerKit's reserve/commit/release lifecycle:

1. fetch active one-shot grant and exact plan;
2. reserve its only use atomically;
3. send the execution id/plan to the helper;
4. commit the use when the helper proves execution started;
5. record exit/timeout/signal/limit result separately from authority use; and
6. mark ambiguous settlement fail closed and never auto-retry execution.

A pre-exec validation rejection releases the reservation. Network/socket loss
after the helper might have started is ambiguous: retain consumed/unavailable
authority, reconcile by execution id, and show `Needs attention` in the
presenter/operator state. Never release and rerun merely because the response
was lost.

## Audit

Audit records correlate:

- authenticated client and operator;
- optional trusted-host `on_behalf_of` attribution;
- request/grant/plan/execution/reservation ids or safe hashes;
- command id and target uid/user;
- catalog digest;
- decision revision/action/idempotency outcome;
- start/end/duration and exit/timeout/signal/result category; and
- helper/frontend correlation ids.

Do not audit raw client secrets, operator credentials, environment values,
stdin/stdout/stderr content, arbitrary reasons beyond the existing
audit-sensitive bounded field, or plan bytes. Output content is returned only
to the authenticated requesting call within strict caps and is not stored by
default.

## Host Doctor

Readiness and `doctor` must fail closed on:

- frontend or helper running as the wrong user;
- socket owner/mode/peer mismatch;
- catalog/config/secret/plan/state path owner/mode/ACL problems;
- writable executable/cwd path chains;
- missing target users/groups;
- unsupported helper protocol;
- unavailable privilege transition backend;
- core dumps enabled for secret/privileged processes;
- overlapping frontend/helper credentials or state; and
- listener exposure beyond configured local interfaces.

Health endpoints remain status-only. Diagnostics never print secret values or
full plans.

## Tests

### Unit/property/fuzz

- catalog and request strict decoding;
- every typed slot boundary and canonical rendering;
- plan deterministic encoding/digest and mutation rejection;
- user/group/path normalization;
- presenter bounds/redaction;
- helper protocol framing, length, version, replay, and malformed input;
- environment/descriptor/resource-limit construction; and
- seeded secret canaries absent from errors/logs/audit.

### Privilege-boundary integration

Run only in disposable isolated CI hosts/containers/VMs designed for privilege
tests. Verify:

- correct dedicated peer can execute one cataloged harmless command;
- every other uid/network path is rejected;
- arbitrary executable, added/changed argv, cwd, env, uid/gid, timeout, and
  stale plan are rejected;
- symlink/path replacement and writable binary/directory attacks fail;
- privilege is dropped exactly to target identity;
- inherited descriptors/environment/core dumps are absent;
- output/process/time limits kill the complete process group;
- duplicate/ambiguous execution id never runs twice; and
- stopping OpenClaw/HF/GH has no effect on helper privilege isolation.

### BrokerKit conformance

- Operator V1 list/watch/decision/revoke behavior;
- activation validation through every decision transport;
- one-shot grant reservation and crash recovery;
- idempotent decision versus one-shot execution idempotency distinction;
- cursor/restart/state corruption behavior; and
- OpenClaw plugin uses the same request without provider branches.

## Implementation Order For The Single Cutover

These are dependency-ordered commits in the one implementation branch, not
supported intermediate releases:

1. freeze threat model, catalog schema, helper protocol, and adversarial tests;
2. implement catalog/request/plan/presenter packages with no privilege;
3. implement helper protocol and fake executor;
4. implement isolated privileged helper and host checks;
5. assemble BrokerKit control plane, plan store, activation validator, routes,
   reservation, settlement, and audit;
6. add installers/operations documentation and isolated CI;
7. pass common Operator V1 and plugin multi-source conformance; and
8. include the binary/helper only in the complete coordinated cutover release.

## Clean Cutover Rules

- There is no pre-BrokerKit sudo control plane or state to import.
- Ship only Operator V1 and the exact command operation.
- Do not include alternate shell/session/TTY code.
- Do not accept old/alternate catalog, request, plan, or helper formats.
- Do not expose a generic sudo or shell endpoint.
- Do not run the frontend, BrokerKit library, OpenClaw plugin, or other brokers
  as root.
- The first supported deployment is the complete reviewed frontend/helper pair.

## Acceptance Criteria

`sudo-broker` is complete when:

- an authenticated client can request only a cataloged exact command;
- every approval is bound to one immutable content-addressed plan and revision;
- every decision path invokes the same sudo activation validator;
- the helper independently rejects plan/catalog/identity/filesystem drift;
- the command runs at most once as the exact target identity with bounded
  environment, cwd, output, processes, descriptors, and time;
- no shell string, arbitrary executable, TTY, stdin, or raw environment path
  exists;
- ambiguous execution never retries or restores authority;
- provider credentials and sudo privilege remain unreachable from other
  monorepo processes;
- Operator V1, adversarial, restart, replay, privilege-boundary, doctor, audit,
  and secret-leak tests pass; and
- only the complete new V1 format/runtime is supported.

## Implemented Status

The monorepo implementation now includes:

- strict catalog, request, helper protocol, execution-state, and immutable-plan
  schemas with duplicate-key, unknown-field, trailing-data, size, and count
  rejection;
- restart-stable request idempotency and old orphan-plan collection;
- one-shot reserve/commit/release settlement with ambiguous outcomes retained;
- a root helper authenticated by Unix peer credentials on a private socket;
- durable execution-id replay protection with uncertain records retained and
  only old completed outcomes eligible for cleanup;
- Linux `openat2` plus `execveat` descriptor execution and a documented macOS
  immediate-revalidation fallback;
- empty-baseline environment construction, identity dropping, resource limits,
  process-group timeout/output termination, and bounded outcomes;
- shared Operator V1, Telegram, policy, grant, audit, setup-client, typed
  systemd, release, installer, and doctor integration;
- a two-binary checksummed release archive and libexec helper installation; and
- unit, race, restart, malformed-state, protocol, CLI, setup, release,
  installer, conformance, and isolated child-setup tests.

The final coordinated cutover still requires the repository-wide review/CI
loop and a live disposable-host test that runs a harmless catalog command
through the installed root helper. That operational gate does not change the
implemented V1 API or storage format.
