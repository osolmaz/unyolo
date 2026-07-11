# sudo-broker Threat Model

## Protected Authority

sudo-broker protects one local privilege transition: executing one cataloged
argv as one pinned Unix identity. The agent is untrusted and must not be root or
belong to a root-equivalent group such as `sudo`, `wheel`, `docker`, `lxd`, or
`incus`.

The unprivileged frontend is trusted to enforce BrokerKit authentication,
policy, approval, plan binding, and reservation settlement. The root helper is
trusted only for peer authentication, independent plan/catalog/identity/host
validation, replay prevention, process isolation, and execution. A compromise
of the frontend can invoke catalog entries but cannot introduce an arbitrary
binary, argv, target user, cwd, environment, or limit. Catalog design must
therefore assume every listed command could be requested by a compromised
frontend account.

## Enforced Boundaries

- The helper listens on a private Unix socket and accepts only the configured
  frontend uid from kernel peer credentials.
- Requests and outcomes use one bounded, length-prefixed, strict protocol.
- Plans are canonical, content-addressed, and bind client/request identity,
  exact execution facts, limits, catalog digest, and creation time.
- Execution ids bind plan, grant, and reservation ids in root-owned durable
  state before process start.
- Inherited environment is empty; stdin is `/dev/null`; output, time, process,
  descriptor, file-size, CPU, and core limits are applied.
- The child creates a process group, drops supplementary groups, gid, and uid,
  and uses no shell parsing.
- Timeout or output overflow kills the whole process group.

On Linux, the child opens the cwd and executable with `openat2` using
no-symlink/no-magic-link resolution, verifies the executable descriptor, drops
identity, and calls `execveat` on that descriptor. Script executables that
cannot satisfy close-on-exec descriptor semantics are rejected; use a trusted
binary entrypoint.

macOS does not expose equivalent `openat2`/`execveat` primitives through the
supported runtime. The helper repeats root ownership, mode, type, and symlink
checks immediately before `chdir` and `exec`. A root actor or filesystem with
hostile ACL/mount semantics remains outside the guaranteed race closure. Doctor
reports this as a warning, and high-risk macOS deployments should use a tighter
OS-native sandbox or Linux host until a descriptor backend is available.

## Non-Goals

V1 does not sandbox the semantics of an approved command. A command run as root
can perform whatever that exact binary and argv implement. The catalog and
upstream command configuration remain part of the trusted computing base.

V1 does not provide interactive shells, TTYs, stdin, arbitrary commands,
caller environment variables, package-manager access, editors, interpreters,
or generic sudo flags. It does not protect against a malicious kernel, root
operator, or replacement of trusted root-owned files by root.
