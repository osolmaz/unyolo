# Broker Operations Runtime

Brokerkit owns the provider-neutral install, setup, service, and doctor logic
used by the broker family. Consumer repositories keep only thin command
adapters and provider-specific service inputs.

## Installer

`installer/install.sh` is the canonical POSIX installer. A broker wrapper sets:

```text
BROKER=hf-broker
REPO=osolmaz/hf-broker
```

and executes the Brokerkit script. The runtime detects Linux or macOS and
amd64 or arm64, resolves the latest release unless `VERSION` is set, downloads
the matching tarball and `checksums.txt`, verifies the archive from its download
directory, and installs only the binary.

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

Consumers may append validated `key=value` directives required by their own
execution boundary. Provider credentials and policy do not enter Brokerkit.

## Doctor

Package `doctor` provides portable building blocks for:

- local account and supplementary-group lookup;
- root and root-equivalent group detection;
- broker service and agent UID separation;
- secret-file type, mode, and agent read/write checks;
- stable text and JSON reports with `ok`, `unsafe`, and `inconclusive` status;
- the shared doctor exit codes `0`, `1`, and `2`.

The checks never read or print secret contents. Provider-specific probes remain
in each broker. For example, hf-broker owns Hugging Face credential-source and
mirror checks, gh-broker owns GitHub App and ruleset checks, and sudo-broker
owns catalog, target-user, and privileged-executor checks.

## Adoption Rule

Cutover is direct. Once a broker adopts one of these APIs, its equivalent local
parser, renderer, installer body, or generic doctor helper is deleted in the
same pull request. Backward compatibility with the duplicated implementation
is not required.
