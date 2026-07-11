# Broker Operations Runtime

Brokerkit owns the provider-neutral install, setup, service, and doctor logic
used by the broker family. Consumer repositories keep only thin command
adapters and provider-specific service inputs.

## Installer

`installer/install.sh` is the canonical POSIX installer. A broker wrapper sets:

```text
BROKER=hf-broker
REPO=osolmaz/brokerkit
TAG_PREFIX=hf-broker/
```

and executes the Brokerkit script. The runtime detects Linux or macOS and
amd64 or arm64, resolves the latest qualified component release unless
`VERSION` is set, downloads the matching tarball and `checksums.txt`, verifies
the archive from its download directory, and installs the declared executable
set. HF and GitHub declare one CLI. Sudo additionally declares its privileged
`sudo-broker-exec` companion, which is installed outside the ordinary `PATH` in
the adjacent `libexec` directory.

The installer does not create users, credentials, config, state, or services.
Those changes belong to an explicit broker setup command.

The `BROKERKIT_LATEST_RELEASE_URL`, `BROKERKIT_RELEASE_BASE_URL`,
`BROKERKIT_UNAME_S`, and `BROKERKIT_UNAME_M` variables are deterministic test
seams. Normal installs do not need them.

## Setup

Package `setup` owns:

- the common `setup client` flags and validation;
- client config writing through `clientconfig`;
- file, stdin, or generated 256-bit secret inputs;
- the common `setup systemd` paths, account names, bind address, port,
  dry-run, no-start, and non-root test flag;
- executable resolution and common path validation.

Broker commands add only provider-specific inputs such as a Hugging Face token,
GitHub App key, scope file, sudo policy, or command catalog.

No setup result or diagnostic output includes a secret value.

Package `envfile` reads the literal `KEY=VALUE` files generated for systemd
services. It bounds input to 1 MiB, rejects duplicate or malformed assignments,
does not interpret shell syntax, and provides an overlay lookup where explicit
process environment values take precedence. Broker doctor commands use this
shared parser to inspect installed service configuration without inheriting the
systemd process environment.

## Service

Package `service` renders the common hardened systemd baseline:

```text
network-online ordering
explicit user and group
private environment file
absolute ExecStart
restart on failure
PrivateTmp=true
ProtectSystem=strict
explicit read-only config and writable state paths
```

Consumers may append only the explicitly allowed additive hardening directives.
Extensions cannot override the shared identity, execution, restart, filesystem,
or hardening directives, including through legacy systemd aliases. Paths
containing systemd specifier or tokenization syntax are rejected instead of
being rendered ambiguously. Trusted service paths are always rejected below
`/home`, `/root`, and `/run/user`, even when broker operations may access those
trees; service binaries, config, environment files, and state must be installed
outside user-controlled home directories.
Provider credentials and policy do not enter Brokerkit.

Home access is an explicit typed policy. The default is `deny`; `read-only` is
available for read-only integrations; and a future provider may select `allow`
only when its reviewed operations must access user home directories. sudo-broker
V1 keeps home access denied and requires root-trusted executable and working
directory chains. On systemd, `allow` adds explicit writable exceptions for
`/home`, `/root`, and `/run/user`; the rest of the filesystem remains protected
by `ProtectSystem=strict`. The writable state path may never be `/`.

Privilege escalation is a separate typed policy and is denied by default with
`NoNewPrivileges=true`. A broker that deliberately performs an identity
transition, such as sudo-broker's root helper, must explicitly select
`PrivilegeEscalationAllow`; Brokerkit then renders `NoNewPrivileges=false`.
Writable state, read-only config, the service executable, and the environment
file must occupy non-overlapping paths.
Existing trusted service path components must be root-owned, non-symlinked, and
not writable by group or other users. The final state directory may instead be
owned by the dedicated service account. `PathValidationPreview` exists only for
dry-runs and non-root temporary-directory fixtures; installable units use the
zero-value strict policy.

## Doctor

Package `doctor` provides portable building blocks for:

- local account and supplementary-group lookup;
- root and root-equivalent group detection;
- broker service and agent UID separation;
- secret-file type, mode, path stability, and agent read/write checks;
- stable text and JSON reports with `ok`, `unsafe`, and `inconclusive` status;
- the shared doctor exit codes `0`, `1`, and `2`.

The checks never read or print secret contents. A symbolic link or access
control list makes the portable path check inconclusive, and an agent-writable
or agent-owned path component makes it unsafe, so a replaceable credential path
cannot receive an `ok` verdict.
Provider-specific probes remain in each broker. For example, hf-broker owns
Hugging Face credential-source and mirror checks, gh-broker owns GitHub App and
ruleset checks, and sudo-broker owns catalog, target-user, and
privileged-executor checks.

## Adoption Rule

Cutover is direct. Once a broker adopts one of these APIs, its equivalent local
parser, renderer, installer body, or generic doctor helper is deleted in the
same pull request. Backward compatibility with the duplicated implementation
is not required.
