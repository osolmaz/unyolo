# Shared systemd Installation Runtime

Status: implementation in progress.

Brokerkit owns the privileged, provider-neutral host changes required to install
a broker as a Linux systemd service. Consumers provide provider-specific file
contents and the already typed `SystemdUnit`; they do not create accounts,
resolve numeric ids, write or chown files, or invoke `systemctl` themselves.

## Boundary

Brokerkit owns:

- creating the configured system group and non-login service account;
- resolving and verifying the configured user and group ids;
- creating and validating the config, state, and systemd directories;
- enforcing exact directory ownership and safe modes;
- writing opaque managed files atomically beneath config or state;
- assigning every managed file to either the root or service ownership class;
- rendering and atomically installing the hardened systemd unit last;
- running `systemctl daemon-reload` and `systemctl enable --now` unless disabled;
- rejecting symlinks, traversal, unsafe modes, duplicate files, path overlap,
  mutable trusted ancestors, and mismatches between the plan and unit.

Consumers own:

- provider credential input and validation;
- provider policy, scope, catalog, and environment-file contents;
- selecting whether each opaque file belongs in config or state;
- selecting root-owned or service-owned file semantics;
- provider-specific dry-run and summary text;
- provider-specific service hardening choices exposed by typed Brokerkit APIs.

Brokerkit never parses, logs, returns, or adds provider meaning to managed file
contents.

## Typed Plan

The Linux API uses one `SystemdInstallPlan` containing:

```text
User, Group
ConfigDir, StateDir, SystemdDir
UnitName
Files[]
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

Direct child names deliberately exclude `/`, `..`, absolute paths, and systemd
specifier syntax. Nested runtime state is created by the broker after startup,
not by privileged setup.

Root-owned managed files use `root:<service-group>`. Service-owned managed files
use `<service-user>:<service-group>`. The unit is always `root:root` and mode
`0644`. The config directory is `root:<service-group>` mode `0750`; the state
directory is `<service-user>:<service-group>` mode `0750`.

## Install Order

1. Validate all syntax and cross-field invariants without mutation.
2. Require root, except for the explicit non-root test mode.
3. Create or verify the service group and account.
4. Resolve numeric ids.
5. Create and verify trusted directories without following symlinks.
6. Set exact directory ownership and modes through opened handles.
7. Atomically write, sync, own, and replace every managed file.
8. Render the systemd unit in strict path-validation mode.
9. Atomically install and sync the unit.
10. Reload systemd and enable/start the unit unless `NoStart` is set.

The unit is rendered last so strict validation observes the final config,
environment-file, executable, and state-directory ownership. A failure never
starts a partially configured service.

## Validation

An install plan is rejected when:

- a path is relative, contains parent traversal, or overlaps another root;
- the unit identity or config/state paths differ from the install plan;
- the unit name is not a literal `.service` basename;
- a managed file name is not a literal direct child basename;
- two managed files resolve to the same area and name;
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
- invalid names, duplicate files, unsafe modes, oversized files, path overlap,
  and plan/unit mismatch fail before mutation;
- strict service rendering rejects a directory or inaccessible file as the
  executable;
- Linux race tests, coverage, vet, lint, Slophammer, mutation CI, review, and
  consumer cutover tests all pass before adoption.

## Cutover Rule

Once a broker adopts this API, it deletes its local account creation, UID/GID
lookup, directory creation, file write/chown, unit write, and systemctl helpers
in the same change. Provider-specific payload rendering remains local.
