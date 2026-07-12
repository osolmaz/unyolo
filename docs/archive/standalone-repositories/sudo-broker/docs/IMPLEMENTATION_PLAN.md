# sudo-broker Implementation Plan

sudo-broker is the Unix privilege-transition member of the broker family. It
uses brokerkit for shared control-plane behavior and owns only the Unix-specific
classification and execution boundary.

The shared broker-family install and setup cutover is specified in
[BROKERKIT_UNIFICATION.md](BROKERKIT_UNIFICATION.md).

There is no backward compatibility requirement. The first implementation should
cut directly to the brokerkit-based shape and should not preserve a temporary
sudoers-only runtime, legacy local config format, or second policy engine.

## Target Architecture

```text
agent CLI or API client
        ↓
sudo-broker daemon
        ↓
brokerkit auth
        ↓
sudo-broker request classifier
        ↓
brokerkit policy + grants
        ↓
operator approval when required
        ↓
sudo-broker executor
        ↓
sudo/systemd-run/launchd/root helper
        ↓
target Unix user
```

The broker is the policy and approval boundary. The OS privilege primitive is
the execution boundary.

## Security Invariants

- Do not build a sudo replacement.
- Do not run arbitrary shell strings for `exec.command`.
- Do not claim command-level confinement inside `session.shell`.
- Do not let the agent account read broker secrets, approval tokens, target-user
  credentials, privileged sockets, or daemon process environment.
- Do not expose command catalogs, policy files, grants, audit logs, session logs,
  or executor diagnostics in a way that leaks secrets.
- Fail closed if a request cannot be classified into one brokerkit policy
  request.
- Host-scoped requests must match the daemon's configured host identity before
  policy evaluation; a daemon with no host identity must reject host-scoped
  requests.
- Every successful privilege transition must have an audit record with client,
  operation, target user, command id or session id, grant id when present,
  start time, end time, exit status, and executor.

## Brokerkit Dependencies

sudo-broker should depend on brokerkit from the first real implementation.

Use brokerkit for:

- named-client authentication
- policy parsing and decisions
- generated grant rules
- durable grant lifecycle
- approval request, decision-token, callback, status, revoke, and fail-closed
  approval state handling
- audit-safe decision metadata
- notification interfaces and reusable Telegram approval transport
- common storage/config helpers
- common HTTP safety helpers if an HTTP API is exposed

Keep in sudo-broker:

- Unix user and group lookup
- host identity checks
- command catalog validation
- TTY/session lifecycle
- sudo/systemd/launchd/root-helper execution
- local isolation doctor checks
- OS-specific install and service setup
- sudo-specific approval message wording

## Policy Registry

sudo-broker registers this initial provider vocabulary with brokerkit.

Operations:

| Operation | Grantable | Meaning |
| --- | --- | --- |
| `exec.command` | Yes | Run one declared command as a target user. |
| `session.shell` | Yes | Start a short-lived interactive shell as a target user. |
| `session.attach` | No | Future interactive attach to an already approved broker-managed session. |
| `session.terminate` | No | Future policy vocabulary for terminating a broker-managed session. Current termination is owner-scoped through the session API. |
| `catalog.read` | No | Read command ids visible to the authenticated client. |

Target kinds:

| Kind | Fields | Meaning |
| --- | --- | --- |
| `user` | `name`, optional `host` | A local target Unix user. |
| `group` | `name`, optional `host` | A local group target for future group sessions. |
| `host` | `name` | A host identity for fleet-wide policy. |

Attrs:

| Attr | Applies To | Meaning |
| --- | --- | --- |
| `command_id` / `command_ids` | `exec.command` | Declared command id. |
| `command_digest` | `exec.command` | Non-secret digest over visible command metadata and env key names. |
| `cwd` / `cwds` | `exec.command` | Allowed working directory. |
| `timeout_seconds` | `exec.command` | Max command runtime. |
| `tty` | `session.shell` | Whether a TTY is required. |
| `shell` / `shells` | `session.shell` | Allowed shell path or login shell marker. |

`shell` is either `login` for the target user's login shell, or an exact
absolute path from sudo-broker's approved shell path list, such as `/bin/zsh`
or `/bin/bash`. It is not basename-based, is not a command string, and must not
include arguments.

## Command Catalog

Commands are declared outside policy. Policy grants access to command ids, not
raw argv strings.

Example:

```json
{
  "commands": {
    "restart-myapp": {
      "run_as": "deploy",
      "argv": ["/usr/bin/systemctl", "restart", "myapp"],
      "cwd": "/",
      "timeout_seconds": 30,
      "env": {}
    }
  }
}
```

Rules:

- `argv[0]` must be an absolute executable path on the host, and symlinks must
  be resolved before shell checks.
- The stored command shape must use the resolved `argv[0]`, not the original
  symlink path. The broker must return that command shape only after an
  allow/active-grant decision; requestable and denied decisions return no
  command template.
- `argv` must not invoke a shell or shell-capable launcher, including BusyBox
  shell applets, unless the command id is explicitly a shell command and is
  treated as equivalent to a shell grant.
- Environment is allowlisted, never inherited wholesale.
- Command digests must not include env values. They may include env key names
  and other non-secret command metadata only.
- Working directory must be absolute and must exist before execution.
- Command ids are stable policy-facing names and must not be reused for a
  different command shape without an operator-visible config change.
- `exec.command` grant requests and evaluations must be reclassified against
  the command catalog and must exactly match the catalog-derived request.
- Host-scoped `user` target policies match only when the classified request
  includes the same host identity and the daemon confirms that identity is its
  own.
- Every `user` target request must validate the target as a local Unix user
  name before policy evaluation, including attach and terminate operations.
- Approval messages for host-scoped `user` targets must include both the user
  and host identity.

## Shell Sessions

`session.shell` grants are identity grants.

A shell session means:

```text
client may act as target user until expiry or termination
```

It does not mean:

```text
client may run only these commands inside the shell
```

The approved duration and use count are grant-policy fields. They are not
matched as `session.shell` attrs.

Implementation requirements:

- allocate a broker-managed session id
- enforce maximum TTL at the broker and executor layer
- terminate the session when the grant expires
- record session start and end in audit
- optionally record TTY transcripts only when explicitly configured and
  documented as sensitive data

The implementation covers approved grant consumption, session id allocation,
start/list/terminate API and CLI, expiry-bounded process lifetime, audit
metadata, and authenticated interactive PTY attach. PTY input/output is
streamed only to the attached client and is not retained as a transcript.

## Execution Backends

Initial Linux backend preference:

1. root-owned sudo-broker daemon installed through `sudo-broker setup systemd`
2. direct user-switch execution or a small root-owned helper
3. `systemd-run --uid` when systemd session semantics are useful
4. tightly scoped `sudo -u` only as a compatibility executor, not as policy

Initial macOS backend preference:

1. launchd-backed privileged helper
2. tightly scoped `sudo -u` as a development executor

The selected backend must be explicit in audit records.

## Linux Service Setup

`sudo-broker setup systemd` owns the Linux production service layout.

It writes:

```text
/etc/sudo-broker/env
/etc/sudo-broker/secrets
/etc/sudo-broker/operator-secrets
/etc/sudo-broker/policy.json
/etc/sudo-broker/catalog.json
/var/lib/sudo-broker/grants.json
/etc/systemd/system/sudo-broker.service
```

The environment file contains only non-secret paths and runtime settings:

```text
SUDO_BROKER_POLICY_FILE=/etc/sudo-broker/policy.json
SUDO_BROKER_CATALOG_FILE=/etc/sudo-broker/catalog.json
SUDO_BROKER_SECRETS_FILE=/etc/sudo-broker/secrets
SUDO_BROKER_OPERATOR_SECRETS_FILE=/etc/sudo-broker/operator-secrets
SUDO_BROKER_GRANTS_FILE=/var/lib/sudo-broker/grants.json
SUDO_BROKER_BIND_ADDR=127.0.0.1:8082
SUDO_BROKER_RUNNER=setuid
```

Telegram is configured by token file path and chat id, not by embedding the bot
token in the environment file.

The Linux setup uses `SUDO_BROKER_RUNNER=setuid` by default. The service runs as
root, switches to the catalog-declared local user with OS credentials, and execs
the catalog argv directly without sudo or shell evaluation. Hosts may opt into
`SUDO_BROKER_RUNNER=sudo` only as a compatibility backend, in which case they
must install matching non-interactive sudoers rules for declared catalog
commands.

## Local Isolation Doctor

Add `sudo-broker doctor isolation`.

It should check:

- agent user is not root
- agent user is not in root-equivalent groups such as `sudo`, `wheel`, `admin`,
  `docker`, `lxd`, or `incus`
- agent user cannot read broker config, secrets, sockets, or process environment
- target user cannot modify broker config or command catalogs
- broker daemon owns its privileged socket and state directory safely
- command catalog and policy files are root/broker owned and not writable by the
  agent or target user

Unsafe results fail closed.

## API And CLI

Minimum CLI:

```text
sudo-broker run <command-id>
sudo-broker request exec <command-id> --reason <reason> --minutes 5
sudo-broker request shell --as <user> --reason <reason> --minutes 5
sudo-broker shell --as <user> [--shell login|/bin/bash] [--tty=false]
sudo-broker sessions
sudo-broker terminate <session-id>
sudo-broker grants
sudo-broker doctor isolation
```

Minimum local API:

```text
POST /api/exec
POST /api/sessions
GET  /api/sessions
POST /api/sessions/{id}/terminate
POST /api/grants
GET  /api/grants
GET  /api/grants/{id}
POST /api/grants/{id}/approve
POST /api/grants/{id}/deny
POST /api/grants/{id}/revoke
GET  /healthz
```

Operator approval endpoints must be reachable only from the trusted operator
channel or host-local admin channel.

## Implementation Order

1. Import brokerkit packages as they land:
   - `auth`
   - `policy`
   - `grants`
   - approval workflow
   - `audit`
   - `notify` and Telegram approval transport
   - storage/config helpers

2. Define sudo-broker provider registry:
   - operations
   - target kinds
   - attrs
   - grantability
   - validation fixtures

3. Implement command catalog:
   - strict JSON parser
   - absolute argv validation
   - environment allowlist
   - timeout validation
   - target user validation

4. Implement request classifier:
   - `exec.command`
   - `session.shell`
   - `catalog.read`
   - grant request shape
   - fail-closed errors

5. Implement grant flow:
   - pending request
   - approval
   - expiry
   - revocation
   - use budget
   - audit
   - Telegram approval through the shared brokerkit adapter

6. Implement Linux executor:
   - fixed command execution
   - timeout enforced at the OS process-group boundary
   - target user switch
   - exit code capture
   - no inherited untrusted environment
   - active grants bound to the exact normalized command template by digest
   - declared environment preserved by key name through sudo, without exposing
     values in argv
   - command digests never expose env values or other hidden command material
   - sudo compatibility uses a non-cached non-interactive auth probe before
     list-mode command preflight; this is intentionally conservative until the
     root-owned daemon/helper backend exists
   - sudo compatibility command preflight uses `sudo -l` without `-D`, because
     real sudo rejects cwd changes in list mode
   - sudo compatibility preflights cwd separately with a harmless
     `sudo -D <cwd> -u <target> -- /usr/bin/pwd` style probe; compatibility
     sudoers setup must allow `CWD=*` for this probe and for catalog commands
   - sudo compatibility never uses target stderr to decide whether a command
     failed before execution
   - sudo compatibility applies cwd through sudo, not by chdir as the broker
     user before invoking sudo
   - sudo compatibility must preflight privileged process-group cleanup by
     killing a real temporary process group with the same dynamic `kill -KILL
     -- -<pgid>` shape used on timeout; if cleanup is not allowed, fail before
     execution
   - sudo compatibility preflight is covered by the declared command timeout
   - broker orchestration reserves grant use before execution and commits or
     releases it according to whether the backend accepted work

7. Implement shell sessions:
   - session creation
   - TTL enforcement
   - terminate
   - audit
   - interactive attach as a follow-up transport slice

8. Implement doctor:
   - Linux checks first
   - macOS checks second
   - JSON output

9. Implement installer:
   - global binary install
   - dedicated service user
   - root-owned config
   - systemd service on Linux
   - launchd helper plan on macOS

10. Add release workflow:
    - GitHub Release publishes binaries
    - install script downloads release tarballs
    - no package-manager dependency for v1

## Current Implementation Status

The first cutover slice is implemented.

Implemented now:

- `internal/sudopolicy` defines sudo-broker's brokerkit registry and request
  helpers for `exec.command`, `session.shell`, `session.attach`,
  `session.terminate`, and `catalog.read`
- sudo-broker rejects multi-value target fields and attrs at its provider
  boundary because Unix user, host, shell, TTY, command, cwd, and timeout
  selectors are all scalar even though brokerkit supports value sets
- the sudo-broker HTTP API keeps target fields and attrs scalar and translates
  them to brokerkit value lists only inside the daemon; responses never expose
  brokerkit's internal list representation for scalar sudo selectors
- `internal/catalog` parses and validates declared command catalogs, rejects
  shell launchers and unsafe environment keys, and classifies command ids into
  brokerkit policy requests
- `internal/broker` evaluates brokerkit policy with active grants, creates
  requestable grants, sends approval notifications through brokerkit's notifier
  interface, approves/denies grants, and reserves/commits use budgets before an
  executor would run
- `internal/executor` orchestrates approved fixed-command execution with a
  pluggable runner, brokerkit audit events, grant reserve/commit/release
  handling, fake-runner end-to-end tests, and a non-interactive `sudo -u`
  compatibility runner that preflights with sudo list mode, probes sudo `-D`
  cwd support separately with `pwd`, preserves declared target env by key name
  without putting values in argv, binds grants to the normalized non-secret
  command template digest, applies cwd through sudo, applies the declared
  timeout to auth/list/cwd/cleanup preflight and execution, preflights
  privileged cleanup by killing a temporary process group with the dynamic
  timeout cleanup argv shape, clears inherited environment from local probes,
  kills the sudo process group on timeout, treats preflight rejection as a
  no-start failure, consumes grants after the target runner starts, and records
  execution start/end metadata plus explicit exit-code metadata for started
  executions in audit extensions
- `sudo-broker serve` exposes a local authenticated HTTP broker API for
  fixed-command execution, grant creation, grant listing, grant status, and
  optional local admin approve/deny/revoke endpoints
- `sudo-broker run`, `sudo-broker request exec`, and `sudo-broker grants` are
  broker clients that read `~/.config/sudo-broker/client.env` or
  `SUDO_BROKER_URL` / `SUDO_BROKER_SHARED_SECRET`
- `sudo-broker request shell`, `sudo-broker shell`, `sudo-broker sessions`, and
  `sudo-broker terminate` provide the client side of approved shell session
  lifecycle
- `internal/session` starts broker-managed shell sessions only from active
  grants, consumes one grant use after the runner accepts work, tracks sessions
  by client-owned id, terminates them by request or expiry, and records
  start/end audit metadata
- `internal/executor` includes direct and Linux setuid shell session runners;
  session processes outlive the admission HTTP request context but are bounded
  by grant expiry
- Telegram approval uses brokerkit's shared Telegram transport and is tested
  with a fake Bot API server; tests do not send real messages
- approval send claims, editable message references, and delivered status
  revisions are stored with the grant; lifecycle delivery resumes after a
  daemon restart
- a process loss after Telegram accepts a message but before its reference is
  stored leaves the claim unresolved through its lease; a later retry rotates
  the one-time decision token before another send
- verified Telegram callbacks atomically commit the decision and editable
  message reference; durable write failures leave the update pending for retry
- every API grant request requires `client_request_id`
- request CLI commands generate an idempotency key by default and accept an
  explicit key for retrying the same logical request
- retained grants report `status: retained` and zero usable capacity
- the durable status sweeper is the sole owner of Telegram message edits;
  callback handling only records the decision and answers the callback
- pre-start command and shell failures release reserved uses; started work
  commits a use, and uncertain post-start settlement retains the reservation
  and revokes the grant instead of reopening access
- crash-stale reservation recovery waits 65 minutes, five minutes beyond the
  catalog's maximum one-hour command runtime, so a live long-running command is
  not mislabeled as ambiguous
- `sudo-broker setup systemd` writes the Linux root-owned service layout,
  validates policy/catalog input, stores client/operator/Telegram secrets in
  private files, and renders a non-secret environment file for the daemon
- `setuid` is the default Linux service runner; it requires euid 0, switches to
  the declared target user's uid/gid/supplementary groups, execs only
  catalog-validated argv, discards command output by default, and kills the
  process group on timeout
- `install.sh`, `scripts/release.sh`, and the release workflow follow the
  broker-family binary-only release asset shape
- mutation tooling remains checked in but is disabled and non-blocking; the CI
  hook is opt-in through `RUN_MUTATION=true`, and
  `SUDO_BROKER_FULL_MUTATION=1` selects full execution when opted in

The Unix implementation is complete:

- Linux and macOS root-owned credential-switch execution
- authenticated interactive PTY attach with resize and disconnect cleanup
- Linux/macOS isolation doctor
- Brokerkit-owned Linux service installation and common operational checks

The binary-only installer does not create a launchd job. macOS operators run
the root daemon directly or manage the same command with a root-owned launchd
plist; this does not create a second helper protocol or execution path.

Default tests simulate approvals with brokerkit's in-memory notifier. They do
not require root and do not send Telegram messages.

## Implementation Readiness

sudo-broker is ready to implement when the first slice can satisfy this
contract:

- sudo-broker imports brokerkit for shared auth, policy, grants, approval state,
  notification interfaces, Telegram transport, audit helpers, and
  storage/config helpers from the start
- sudo-broker keeps only Unix user/group lookup, host checks, command catalog
  validation, request classification, executor/session backends, local doctor
  checks, install/service files, audit extension fields, and approval summary
  text
- there is no temporary sudoers-only runtime, second policy engine, or local
  duplicate grant store
- generated grants are evaluated by the brokerkit policy decision path before
  any executor is called
- Telegram approval is covered with a fake Bot API server or fake notifier in
  automated tests; CI must not require a live bot token or send real messages
- end-to-end broker tests use fake executors, fake session managers, fake
  notifiers, and temporary catalogs by default; privileged Linux executor tests
  require an explicit opt-in flag

## Test Requirements

- brokerkit auth accepts valid clients and rejects missing or invalid clients
- policy registry rejects unknown operations, targets, and attrs
- deny overrides active grant
- active grant enables exactly one approved request
- grant idempotency returns the same request for the same body and conflicts on
  a different body
- approval tokens are single-grant, single-use, and rejected for the wrong
  approver
- Telegram approval uses the shared brokerkit adapter once it exists
- notification references and delivered status revisions survive daemon
  restart without sending a second approval message
- failed status edits remain due and are retried without rolling back the
  recorded grant decision
- command catalog rejects shells, relative paths, inherited environment, and
  unsafe working directories unless explicitly configured
- `exec.command` cannot run undeclared command ids
- `session.shell` expires and terminates the session
- audit never contains broker secrets, approval tokens, raw command input, or
  command output, or Telegram bot tokens by default
- doctor fails for root-equivalent agent users
- Linux executor integration tests run behind an explicit privileged test flag

End-to-end tests should include:

- fixed command grant approved through a fake notifier and fake executor
- fixed command grant approved through a fake Telegram Bot API server
- authenticated HTTP client can create grants, list grants, and run direct
  same-user commands
- approved fixed command grant stops matching if the catalog command template
  changes before execution
- direct allow command reaches the fake executor without a grant
- executor preflight failure releases the grant use reservation
- executor cleanup preflight failure happens before execution and releases the
  grant use reservation
- executor cwd preflight failure happens before execution and releases the
  grant use reservation
- executor preflight timeout releases the grant use reservation
- executor accepted work commits grant use even when the command times out
- executor commit ambiguity retains the use and closes a multi-use grant
- shell grant approved through a fake notifier and fake session manager
- authenticated HTTP client can start, list, and terminate an approved shell
  session
- direct shell session runner outlives caller request cancellation and stops at
  grant expiry
- denied command request that never reaches the executor
- expired grant that terminates or refuses the session
- fake Telegram callback plus durable sweeper updates the persisted message
  exactly once, including after reconstructing the broker from the same grant
  file
- callback recovery after an ambiguous send stores the callback-carried message
  reference without a duplicate send
- durable callback write failure leaves the Telegram update offset unchanged
  and succeeds when the same callback is retried

## Merge Gates

Every sudo-broker implementation slice must pass:

```sh
go fmt ./...
go vet ./...
go test -race ./...
./scripts/check-go-coverage.sh
golangci-lint run
slophammer-go dry .
slophammer-go crap .
slophammer-go check .
```

Slophammer is mandatory for sudo-broker from the first implementation slice.
Keep DRY, CRAP, and check gates in CI. Keep mutation tooling checked in behind
the opt-in `RUN_MUTATION=true` hook, but disabled and non-blocking until a later
explicit decision re-enables it. Privileged Linux executor tests remain
explicit opt-in tests outside the default gate.

## Cutover Rule

There is no legacy runtime to preserve. If an early prototype exists, replace it
with the brokerkit-based design rather than carrying both paths.
