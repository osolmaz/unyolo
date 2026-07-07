# macOS Broker Support Plan

Status: planning, 2026-07-07.

## Goal

Support running hf-broker on macOS while preserving the core safety
property: the agent never receives the upstream Hugging Face credential,
and local deployments fail closed when the agent can plausibly read or
bypass that credential.

The broker's request enforcement should remain portable Go. The main gap
is the local isolation doctor, which currently has a Linux implementation
and an unsupported-platform stub.

## Non-goals

- Do not weaken the broker threat model for macOS.
- Do not add a generic Hub API proxy or repo administration operations.
- Do not require system services as part of the implementation.
- Do not add cgo or non-stdlib dependencies in the first milestone unless
  the stdlib-only approach cannot prove an important safety fact.
- Do not promise Linux-equivalent process-environment checks until macOS
  APIs can support them safely.

## Current State

The broker binary builds for macOS, and OS-neutral surfaces should keep
working there:

- configuration loading
- authentication
- git smart-HTTP proxying
- append-only policy enforcement
- grant storage and approval flow
- notification integrations
- audit logging

The local isolation doctor does not support macOS yet. The Linux doctor
depends on Linux-specific primitives:

- `/proc/<pid>/status`
- `/proc/<pid>/environ`
- Linux capability bits
- Linux xattrs for POSIX ACL detection
- process execution with `syscall.Credential`

On macOS, the doctor should use a separate backend and keep the same CLI,
JSON schema, check names where possible, and exit-code contract.

## Target Deployment Model

Recommended macOS deployment:

- broker runs as a dedicated non-login user, for example `_hfbroker`
- upstream token file is owned by the broker user and mode `0600`
- agent runs as a separate non-admin user
- human operator remains an admin user
- agent is not in `admin` or `wheel`
- broker binds to localhost or a private Tailnet-equivalent interface
- Unix socket, if used, is owned so only intended clients can connect

The doctor must report `unsafe` if the agent is root-equivalent. On
macOS, `admin` and `wheel` are root-equivalent because they can normally
lead to sudo/root access.

## Doctor Backend Architecture

Split the isolation implementation by platform:

```text
internal/isolation/
  isolation_linux.go      Linux doctor backend
  isolation_darwin.go     macOS doctor backend
  isolation_unsupported.go
  types.go                shared report/status/options types
  report.go               shared text and JSON rendering
```

Keep shared helpers in platform-neutral files only when their behavior is
identical across platforms. Keep platform-specific process, ACL, and
identity checks behind the platform backend.

The CLI should not change. These commands should work on macOS:

```sh
hf-broker doctor
hf-broker doctor --agent-user agent --token-file /path/to/hf-token
hf-broker doctor --agent-user agent --broker-pid 12345
hf-broker doctor --json
hf-broker doctor isolation ...
```

## macOS Checks

### Agent Identity

Required checks:

- fail if agent UID is `0`
- fail if agent belongs to `admin` or `wheel`
- pass if agent is neither root nor in known root-equivalent groups
- include UID, primary GID, supplementary GIDs, and group names in the
  JSON report when available

For bare `hf-broker doctor`, check the live doctor process identity by
default, as Linux does.

### Broker Process

Required checks:

- accept `--broker-pid`
- verify the broker process exists
- verify the broker UID differs from the agent UID
- return `unknown` when the broker process UID cannot be read safely

Implementation options:

- first milestone: use `ps -o uid= -p <pid>` via a small, sanitized helper
  only if there is no stdlib syscall path
- preferred long term: use Darwin process APIs directly if stdlib support
  is enough, or evaluate cgo/libproc in a separate design step

Do not read or print broker environment contents. If macOS cannot safely
verify broker environment readability, report that check as
`inconclusive`.

### Token File

Required checks:

- token file exists
- token file is not owned by the agent
- token file mode does not allow agent read or write
- token file is not world-readable or world-writable
- token file parent directories are not writable by the agent
- symlink targets are resolved and checked
- active read/write open probes run when the doctor can safely execute as
  the agent identity

ACL handling:

- first milestone: report `unknown` when ACL state cannot be proven from
  mode bits
- follow-up: inspect macOS ACLs with a dedicated parser if needed

### Unix Socket

Required checks:

- socket path exists and is a Unix socket
- socket is not world-writable
- socket is not writable by the agent
- socket parent directories are not writable by the agent
- optional active connect probe reports whether the agent can connect

### Process Environment

Linux checks `/proc/<pid>/environ`. macOS has no equivalent stable stdlib
path.

First milestone behavior:

- do not attempt to read process environment values
- report process-environment checks as `unknown` or `warn`
- keep secret values out of every report path

Long-term option:

- evaluate macOS-specific process APIs or a privileged helper, but only if
  it preserves the no-secret-output invariant and does not require broad
  root execution for normal doctor runs

## Implementation Phases

### Phase 1: Portable Broker Audit

Confirm OS-neutral broker paths build and test on macOS:

- `GOOS=darwin GOARCH=arm64 go build ./cmd/hf-broker`
- `GOOS=darwin GOARCH=amd64 go build ./cmd/hf-broker`
- keep Linux-only tests behind build tags
- identify any accidental Linux-only imports outside `internal/isolation`

Acceptance criteria:

- macOS builds pass in CI or a documented local equivalent
- unsupported-platform doctor stub remains the only known macOS runtime
  limitation before Phase 2

### Phase 2: Conservative macOS Doctor

Add `isolation_darwin.go` with conservative checks:

- agent root/admin/wheel detection
- token file mode and parent-directory checks
- socket mode and parent-directory checks
- broker UID separation when process UID can be determined
- explicit `unknown` findings for process facts macOS cannot prove yet

Acceptance criteria:

- `hf-broker doctor` runs on macOS
- unsafe root/admin agents fail closed
- readable or writable token files fail closed
- unclear process-environment and ACL facts are inconclusive, not OK
- report JSON schema matches Linux

### Phase 3: macOS Active Probes

Add active probes where macOS can run them safely:

- token-file read probe
- token-file write probe
- socket connect probe
- broker process environment readability only if a safe primitive exists

Acceptance criteria:

- probes never read, write, or print secret contents
- probe failures are reported as unknown instead of silently ignored
- tests cover successful and refused probe paths

### Phase 4: CI and Documentation

Add or document macOS validation:

- macOS GitHub Actions job if available and cost is acceptable
- otherwise documented local commands for macOS maintainers
- README section for macOS deployment layout
- specification update once behavior is implemented

Acceptance criteria:

- macOS support is visible in README and specification
- CI or maintainer docs cover the macOS build and doctor smoke
- Linux doctor behavior remains unchanged

## Test Plan

Unit tests:

- parse macOS identity/group fixtures
- classify `admin` and `wheel` as root-equivalent
- classify normal non-admin users as non-root-equivalent
- token-file owner/group/world mode checks
- parent-directory replacement checks
- socket mode checks
- JSON report compatibility

Integration smokes on macOS:

```sh
hf-broker doctor --json
hf-broker doctor --agent-user <non-admin-user> --token-file <broker-token>
hf-broker doctor --agent-user <admin-user> --token-file <broker-token>
hf-broker doctor --agent-user <non-admin-user> --broker-pid <broker-pid>
```

Expected results:

- admin/root agents report `unsafe`
- non-admin agent with unreadable token file can reach `ok` only when all
  required facts are proven
- missing process-environment or ACL proof reports `inconclusive`
- no secret values appear in stdout, stderr, JSON, logs, or test failures

## Open Questions

- Can broker process UID be read on macOS without cgo and without shelling
  out to `ps`?
- Is macOS ACL inspection needed for the first supported release, or is an
  `unknown` finding acceptable when mode bits are insufficient?
- Should macOS support a socket connect probe in Phase 2 or defer it to
  Phase 3?
- Do we need a documented launchd example later, or should service setup
  stay outside this repo's core docs?

## Done Definition

macOS broker support is done when:

- the broker builds on macOS
- `hf-broker doctor` runs on macOS instead of returning unsupported
- root/admin/wheel agents fail closed
- token-file and socket permission checks work on macOS
- unknown macOS-only gaps are reported as inconclusive, not OK
- the JSON report schema is stable across Linux and macOS
- Linux behavior and tests remain green
