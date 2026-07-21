# Shared systemd Installation Runtime

Status: implemented.

Brokerkit owns the privileged, provider-neutral host changes required to install
a broker as a Linux systemd service. Consumers provide provider-specific file
contents and the already typed `SystemdUnit`; they do not create accounts,
resolve numeric ids, write or chown files, or invoke `systemctl` themselves.

Single-service setup remains the configuration and account bootstrap boundary.
Production binary upgrades use the host bundle transaction described in
`OPERATIONS_RUNTIME.md`; independently replacing a running executable is not a
service upgrade. Bundle activation stops `brokerkit-telegram.service` first,
then provider services, switches the immutable release pointer, reloads
systemd, starts and verifies providers, and starts Telegram last. A candidate
failure restores the previous complete service set.

## Boundary

Brokerkit owns:

- creating the configured system group and non-login service account;
- resolving and verifying the configured user and group ids;
- creating and validating the config, state, and systemd directories;
- enforcing exact directory ownership and safe modes;
- writing opaque managed files atomically beneath config or state;
- removing explicitly named managed files after successful configuration
  activation;
- assigning every managed file to either the root or service ownership class;
- rendering and atomically installing the hardened systemd unit last;
- running `systemctl daemon-reload`, `systemctl enable`, and `systemctl restart`
  unless activation is disabled;
- rejecting symlinks, traversal, unsafe modes, duplicate files, path overlap,
  mutable trusted ancestors, and mismatches between the plan and unit.

Consumers own:

- provider credential input and validation;
- provider policy, scope, catalog, and environment-file contents;
- selecting whether each opaque file belongs in config or state;
- selecting root-owned or service-owned file semantics;
- provider-specific dry-run and summary text;
- provider-specific service hardening choices exposed by typed Brokerkit APIs.
- selecting and persisting any explicit loopback TCP Git listener; BrokerKit
  assigns no fixed Git port.

Git-speaking services may bind one explicit loopback TCP endpoint from their
root-owned environment file. That endpoint is separate from the
permission-scoped agent and operator Unix sockets and exposes only the shared
Git route gate. A missing Git endpoint disables native Git routing; a conflict
or non-loopback endpoint fails setup or startup instead of selecting another
port.

The default unit uses `ProtectSystem=strict`. A privileged execution broker may
explicitly select `HostFilesystemAccessAllow`, which renders
`ProtectSystem=false` so approved child processes retain the target Unix
account's normal filesystem permissions. This is an opt-in capability; it does
not change the default for credential brokers.

Brokerkit never parses, logs, returns, or adds provider meaning to managed file
contents.

## Typed Plan

The Linux API uses one `SystemdInstallPlan` containing:

```text
User, Group
ConfigDir, StateDir, SystemdDir
UnitName
Files[]
RemoveFiles[]
ReadyCheck, ReadyTimeout, ReadyInterval
Unit
NoStart
AllowNonRoot (tests only)
Runner (optional test seam)
```

Each managed file contains:

```text
Area  = config | state
Name  = one direct child name
Data  = opaque bytes
Mode  = regular Unix permission bits
Owner = root | service
```

Each removal contains only a config-area direct child name. Retirement is
restricted to the root-owned config directory so the service cannot race the
cleanup. The environment file must always be written and cannot be removed. A
plan cannot write and remove the same path.

An activated plan with removals must provide a readiness check. Brokerkit polls
it with bounded timeout and interval settings after `systemctl restart`; only a
successful check permits credential retirement. `HTTPReadyCheck` provides the
common loopback health-endpoint implementation.

Direct child names deliberately exclude `/`, `..`, absolute paths, and systemd
specifier syntax. Nested runtime state is created by the broker after startup,
not by privileged setup.

Root-owned managed files use `root:<service-group>`. Service-owned managed files
use `<service-user>:<service-group>`. The unit is always `root:root` and mode
`0644`. The config directory is `root:<service-group>` mode `0750`; the state
directory is `<service-user>:<service-group>` mode `0750`.
When two cooperating units keep separate state beneath one parent, the plan may
declare that shared state directory explicitly. Brokerkit then installs it as
`root:<service-group>` mode `0750`, allowing both units to traverse to their
separately owned state roots without making the parent writable.

## Install Order

1. Validate all syntax and cross-field invariants without mutation.
2. Require root, except for the explicit non-root test mode.
3. Create or verify the service group and account.
4. Resolve numeric ids.
5. Create and verify trusted directories without following symlinks.
6. Set exact directory ownership and modes through opened handles.
7. Atomically write and sync non-environment managed files.
8. Atomically write the environment file so it never references a secret that
   failed to install.
9. Render the systemd unit in strict path-validation mode.
10. Atomically install and sync the unit.
11. Reload systemd, enable the unit, and restart it so reruns apply changed
    configuration unless `NoStart` is set.
12. Poll the provider readiness check after activation.
13. Only after readiness succeeds, remove config files that the new
    process no longer references. Preserve them when activation is disabled,
    fails, or never becomes ready.

The unit is rendered last so strict validation observes the final config,
environment-file, executable, and state-directory ownership. A failure never
starts a partially configured service.

## Validation

An install plan is rejected when:

- a path is relative, contains parent traversal, or overlaps another root;
- a shared state directory is not a normalized strict ancestor of the unit's
  state directory;
- the unit identity or config/state paths differ from the install plan;
- the unit name is not a literal `.service` basename;
- a managed file name is not a literal direct child basename;
- two managed files resolve to the same area and name;
- a file is both written and removed, or the environment file is removed;
- retirement targets writable state or lacks a readiness check for activation;
- a managed file mode contains special bits or group/other write permission;
- the managed systemd environment file is not root-owned;
- managed data exceeds the shared bounded setup-file limit;
- a trusted existing path contains a symlink, is owned by an unrelated user,
  or is mutable by group/other;
- the final executable is not a regular file, an ancestor is not searchable,
  or the file cannot be executed by the configured service identity including
  its supplementary groups;
- non-root test mode is requested while service activation is enabled.

## Test Gates

- fake-runner account creation and existing-account paths;
- non-root temporary-root install with exact file contents, ownership classes,
  modes, unit ordering, and no `systemctl` calls when disabled;
- failed and successful service activation calls;
- symlink replacement cannot modify the link target;
- new secrets are installed before the environment is committed, and replaced
  secrets are removed only after successful activation;
- invalid names, duplicate files, unsafe modes, oversized files, path overlap,
  and plan/unit mismatch fail before mutation;
- strict service rendering rejects a directory or inaccessible file as the
  executable;
- Linux race tests, coverage, vet, lint, Slophammer, review, and consumer tests
  all pass.
- old-ingress/new-broker contract drift is rejected before Telegram consumes
  an update;
- complete bundle activation and injected readiness failure restore the exact
  prior release and provider-before-consumer ordering;
- a deleted or outside-release process fails host doctor.

Mutation tooling remains checked in but is disabled and non-blocking. It must
not run in the default required workflow unless a later explicit decision
re-enables it.

## Ownership Rule

BrokerKit owns account creation, UID/GID lookup, directory creation, file
installation, unit installation, and systemctl execution. Provider-specific
payload rendering remains local.
