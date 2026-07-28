# Broker Operations Runtime

unYOLO owns the provider-neutral install, setup, service, and doctor logic
used by the broker family. Component directories keep only thin command
adapters and provider-specific service inputs.

## Installer

`install/install.sh` is the canonical POSIX installer. A broker wrapper sets:

```text
BROKER=hf-broker
REPO=osolmaz/unyolo
TAG_PREFIX=hf-broker/
```

and executes the unYOLO script. The runtime detects Linux or macOS and
amd64 or arm64. The wrapper resolves the selected qualified release tag to its
exact commit SHA and fetches the canonical installer from that immutable
revision. The installer downloads the matching tarball and `checksums.txt`,
checks the archive digest, and verifies GitHub artifact attestations for both
files against the unYOLO repository, release workflow, and selected tag. It
uses an exact GitHub CLI build whose Linux and macOS checksums are embedded in
the installer. It then installs the declared executable set. HF and GitHub
declare one CLI. Sudo additionally declares its privileged
`sudo-broker-exec` companion, which is installed outside the ordinary `PATH` in
the adjacent `libexec` directory.

The installer defaults to `$HOME/.local/bin` and never invokes `sudo`. An
explicit system destination requires an operator-controlled privileged shell.
It does not create users, credentials, config, state, or services; those
changes belong to an explicit broker setup command.

An offline installation may set `UNYOLO_VERIFIER_FILE` to an absolute,
executable path for a verifier the operator obtained and verified separately.
`UNYOLO_VERIFY_ONLY=true` downloads, authenticates, and validates release
contents without installing them. The release workflow combines it with
`UNYOLO_VERIFY_RELEASE_SET=true` after publication to verify all four
platform archives, the checksum manifest, and the SBOM. The remaining
`UNYOLO_*` URL and platform variables are test seams. Normal installs do not
need them.

### Atomic host bundles

Persistent unYOLO services are deployed as one signed runtime bundle. The
`unyolo` host command stages each separately released broker and ingress
binary under an immutable release directory, verifies its digest and exact
Agent and Operator contract identities, then activates the complete set:

```text
unyolo system plan --manifest manifest.json --signature manifest.sig --public-key release.pub
unyolo system install --manifest manifest.json --signature manifest.sig --public-key release.pub
unyolo system upgrade --manifest manifest.json --signature manifest.sig --public-key release.pub
unyolo system status
unyolo system doctor
unyolo system rollback
```

Linux uses `/opt/unyolo/releases/<bundle-id>` and macOS uses
`/Library/Application Support/unyolo/releases/<bundle-id>`. The `current`
symlink is switched atomically. Native service definitions use exact
component paths below that root-controlled pointer; production setup rejects
standalone mutable executables. Each started process is then verified against
the selected immutable release. Providers stop after consumers and start
before consumers. Exact readiness is checked before the activation record commits.
Any failure restores the previous release pointer, state replacement, service
order, and readiness before Telegram resumes.
Before stopping a service, the host writes a private activation transaction.
An interrupted install, upgrade, or rollback is reconciled under the host lock
before another lifecycle command can run. A committed and healthy candidate is
kept; an uncommitted transaction restores its recorded previous release.

The closed `unyolo.io/runtime-bundle/v1` manifest is defined by
`protocol/runtime-bundle.schema.json`. A production manifest requires a
detached Ed25519 signature. `--development` permits unsigned local fixtures,
but development build identities cannot enter a signed production bundle.
Development activation requires explicit isolated root and state directories;
it cannot write the production activation paths.
The public key supplied for the first production install is pinned under the
private host state directory. Later plans and upgrades use that key and reject
attempted key replacement.

Each required provider component names its local Operator endpoint and the
absolute path of its Operator token file. The token itself is never stored in
the manifest. Activation and `doctor` use that local credential to verify the
running provider's exact contract and build identity without exposing it.

State-format changes are explicit replacements. The old service is stopped,
its state directory is archived beside the original, and the candidate starts
with fresh current-format state. Rollback restores the archived directory with
the old executable. Runtime compatibility readers and mixed-format state are
not supported.

## Setup

Package `internal/host/setup` owns:

- the common `setup client` flags and validation;
- client config writing through `internal/config/client`;
- file, stdin, or generated 256-bit secret inputs;
- the common `setup systemd` paths, account names, bind address, port,
  dry-run, no-start, and non-root test flag;
- executable resolution and common path validation.

Broker commands add only provider-specific inputs such as a Hugging Face token,
GitHub App key, scope file, sudo policy, or command catalog.

No setup result or diagnostic output includes a secret value.

Package `internal/config/envfile` reads the literal `KEY=VALUE` files generated
for systemd services. It bounds input to 1 MiB, rejects duplicate or malformed
assignments, does not interpret shell syntax, and provides an overlay lookup
where explicit process environment values take precedence. Broker doctor
commands use this shared parser to inspect installed service configuration
without inheriting the systemd process environment.

## Agent MCP Operations

MCP execution tools are a resumable adapter over Agent Operations V1, not a
second lifecycle. A provider operation call durably submits one request and
returns immediately. Its optional public `request_id` maps once to Agent V1's
internal idempotency key. The MCP response is a closed
`unyolo.io/mcp-operation/v1` projection that excludes clients, canonical
arguments, approval linkage, and plan data.

Provider-prefixed get, wait, and list tools recover operations after transport
loss or process restart. Wait defaults to 25 seconds, never exceeds 25 seconds,
and returns the latest known state on timeout. List defaults to 20, is capped at
50, uses validated opaque cursors, and supports exact request-ID recovery.

`mcp/server` owns bounded JSON-RPC and MCP stdio mechanics. `agent/mcp` owns the
closed operation envelope, submission, and lifecycle utility dispatch.
`agent/client` owns authenticated Agent V1, sealed-payload, and stream
transport. `operation/capability` owns host compatibility classification and
bidirectional JSON Pointer projection mechanics. `mcp/operation` owns
request-ID generation, operation/page projections, bounded recovery, and
structured conflicts. Providers own semantic field aliases, schemas,
runtime adapters, result projection, and canonical provider validation.

Every ordinary provider operation tool enters Agent Operations V1. Static
allow, active window grant, approval request, and deny are authorization
outcomes inside that lifecycle; they are not separate MCP dispatch modes. An
allowed operation executes immediately without creating approval state. An
approved request resumes the original durable operation. Explicitly named
grant lifecycle tools remain only for clients intentionally managing native
protocol access outside a bounded operation call.

The advertised MCP set is the intersection of agent-facing catalog entries,
client exposure, policy vocabulary, and registered runtime adapters. Catalog
entries without an executor are discoverable as documentation, not runnable
tools.

## Service

Package `internal/host/service` renders the common hardened systemd baseline:

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
or hardening directives through equivalent systemd settings. Paths
containing systemd specifier or tokenization syntax are rejected instead of
being rendered ambiguously. Trusted service paths are always rejected below
`/home`, `/root`, and `/run/user`, even when broker operations may access those
trees; service binaries, config, environment files, and state must be installed
outside user-controlled home directories.
Provider credentials and policy do not enter unYOLO.

Home access is an explicit typed policy. The default is `deny`; `read-only` is
available for read-only integrations; and `allow` is available only when a
provider's reviewed operations must access user home directories. sudo-broker
V1 keeps home access denied and requires root-trusted executable and working
directory chains. On systemd, `allow` adds explicit writable exceptions for
`/home`, `/root`, and `/run/user`; the rest of the filesystem remains protected
by `ProtectSystem=strict`. The writable state path may never be `/`.

Privilege escalation is a separate typed policy and is denied by default with
`NoNewPrivileges=true`. A broker that deliberately performs an identity
transition, such as sudo-broker's root helper, must explicitly select
`PrivilegeEscalationAllow`; unYOLO then renders `NoNewPrivileges=false`.
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

`unyolo system doctor` adds the host-level view. It compares the activation
record, immutable artifact digests, native service state, process executable
paths, and active bundle. A Linux executable ending in `(deleted)`, any process
outside the active release, a digest mismatch, or an incomplete rollback makes
the host unhealthy. JSON output contains no provider credentials or callback
authority.

## State Maintenance

Every broker exposes the same offline maintenance surface:

```text
BROKER state check --state-dir /absolute/state [--full]
BROKER state backup --state-dir /absolute/state --output /absolute/new-backup
BROKER state restore --state-dir /absolute/state --backup /absolute/backup
BROKER state export --state-dir /absolute/state --output /absolute/new-export.json
```

Maintenance commands acquire the unYOLO state lease, so the service must be
stopped. They accept only the exact current SQLite schema and never create,
migrate, or convert a database while checking, backing up, or exporting it.
Backup uses SQLite's consistent backup API and publishes a private database plus
checksum manifest. Restore validates format, integrity, checksum, size,
ownership, and modes before replacing offline state. Export is deterministic
and bounded; it omits operation inputs and results, reasons, plan bodies,
decision tokens, notification destinations, and credential material.

## Ownership Rule

Broker directories contain only thin command adapters and provider-specific
inputs. Generic parser, renderer, installer, and doctor behavior belongs in
unYOLO.
