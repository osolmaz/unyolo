# brokerkit Architecture

brokerkit is the shared layer for broker-style access-control services. It
should make the repeated broker machinery reusable without hiding the dangerous
provider-specific boundary.

`hf-broker`, `gh-broker`, and `sudo-broker` should all depend on brokerkit for
the shared control plane. The migration model is cutover, not backward
compatibility: once a broker adopts a brokerkit package, the old local copy of
that behavior should be removed.

## Broker Shape

Every broker using brokerkit should follow this request path:

```text
authenticate client
classify request
evaluate policy
check active grant
optionally create approval request
execute provider-specific action
write audit entry
```

The shared code should help with authentication, policy decisions, grant
lifecycle, approval workflow, reusable notification transports, audit-safe
metadata, storage/config primitives, generic Git parsing helpers, and HTTP
safety helpers.

The consuming broker should own request classification, provider credentials,
provider-specific message wording, and execution.

## Package Boundaries

Current and planned package boundaries:

```text
brokerkit/
├── auth/       # Broker-client authentication.
├── policy/     # Generic rules, registries, decisions, grant overlays.
├── grants/     # Durable short-lived grant records.
├── audit/      # Secret-safe audit event helpers.
├── httpx/      # Header filtering and body-limit helpers.
├── notify/     # Approval notification interfaces and adapters.
├── store/      # Atomic local stores and locks.
└── gitx/       # Generic Git smart-HTTP parsing helpers.
```

The implemented package names are the initial brokerkit API surface.

The canonical ownership boundary is [OWNERSHIP.md](OWNERSHIP.md).

## What Belongs Here

brokerkit may contain:

- bearer/basic shared-secret authentication for named clients
- minimum secret length checks
- policy rule parsing and matching
- operation, target, and attr registry mechanics
- effect ordering: deny, active grant, allow, request, no match
- grant policy bounds
- pending, active, expired, consumed, denied, and revoked grant states
- grant idempotency, expiry, use budgets, and reservations
- approval request, decision-token, callback, and revocation workflow
- approval notifier interfaces
- reusable Telegram transport and callback handling
- safe audit field helpers
- strict config decoding helpers
- atomic file storage and lock helpers
- proxy-safe HTTP header filters
- generic Git pkt-line, receive-pack command, ref update classification, and
  pack/body redaction helpers

## What Does Not Belong Here

brokerkit must not contain:

- Hugging Face Git/LFS behavior
- GitHub REST or Git smart-HTTP behavior
- sudo, systemd, launchd, PAM, or TTY execution behavior
- provider-specific operation names as built-in global behavior
- provider-specific target kinds as built-in global behavior
- provider-specific approval wording
- command parsing for Unix shells
- broad framework wiring that makes simple brokers harder to understand

## Provider Responsibilities

Each broker must register its own vocabulary.

`hf-broker` owns:

- operations such as `git.push.append`, `git.push.force`, and
  `repo.contents.read`
- target kinds such as `repo` and `bucket`
- attrs such as `ref`, `path`, `max_bytes`, and object keys
- Hugging Face-specific approval text

`gh-broker` owns:

- operations such as `pr.create`, `contents.read`, and
  `git.push.fast_forward`
- target kinds such as `repo` and `installation`
- attrs such as `ref`, `base_ref`, `head_ref`, and `path`
- GitHub-specific approval text

`sudo-broker` owns:

- operations such as `exec.command` and `session.shell`
- target kinds such as `user`, `group`, and `host`
- attrs such as `command_id`, `cwd`, `tty`, and `timeout_seconds`
- command catalogs, shell sessions, and OS-specific execution backends
- Unix-specific approval text

## Security Invariants

brokerkit must preserve these invariants:

- A broker client secret is not the protected upstream credential.
- Upstream credentials and privilege tokens are never returned to clients.
- Auth, policy, grant, and audit code must fail closed.
- Unknown operations, target kinds, and attrs are rejected unless the provider
  registry explicitly allows them.
- Audit records must not contain secrets, request bodies, pack contents, shell
  input, raw upstream responses, or token metadata.
- Grant records must be scoped to one client, one operation, one target, and the
  attrs approved by policy.

## First Extraction Rule

Do not extract a package because two repositories have similar names or files.
Extract only when the same behavior has the same tests in at least two brokers
and the third broker design can use the same API without special cases.

When extraction happens, do not keep compatibility layers indefinitely. The
consumer broker should move to the brokerkit API, delete its local duplicate,
and keep provider-specific adapters at the edge.
