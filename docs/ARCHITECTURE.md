# brokerkit Architecture

brokerkit is the shared layer for broker-style access-control services. It
should make the repeated broker machinery reusable without hiding the dangerous
provider-specific boundary.

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
lifecycle, audit-safe metadata, and HTTP safety helpers.

The consuming broker should own request classification and execution.

## Package Boundaries

Planned package boundaries:

```text
brokerkit/
├── auth/       # Broker-client authentication.
├── policy/     # Generic rules, registries, decisions, grant overlays.
├── grants/     # Durable short-lived grant records.
├── audit/      # Secret-safe audit event helpers.
├── httpx/      # Header filtering and body-limit helpers.
└── notify/     # Approval notification interfaces.
```

The package names are tentative until the first implementation PR.

## What Belongs Here

brokerkit may contain:

- bearer/basic shared-secret authentication for named clients
- minimum secret length checks
- policy rule parsing and matching
- effect ordering: deny, active grant, allow, request, no match
- grant policy bounds
- pending, active, expired, consumed, denied, and revoked grant states
- approval notifier interfaces
- safe audit field helpers
- proxy-safe HTTP header filters

## What Does Not Belong Here

brokerkit must not contain:

- Hugging Face Git/LFS behavior
- GitHub REST or Git smart-HTTP behavior
- sudo, systemd, launchd, PAM, or TTY execution behavior
- provider-specific operation names as built-in global behavior
- provider-specific target kinds as built-in global behavior
- command parsing for Unix shells
- broad framework wiring that makes simple brokers harder to understand

## Provider Responsibilities

Each broker must register its own vocabulary.

`hf-broker` owns:

- operations such as `git.push.append`, `git.push.force`, and
  `repo.contents.read`
- target kinds such as `repo` and `bucket`
- attrs such as `ref`, `path`, `max_bytes`, and object keys

`gh-broker` owns:

- operations such as `pr.create`, `contents.read`, and
  `git.push.fast_forward`
- target kinds such as `repo` and `installation`
- attrs such as `ref`, `base_ref`, `head_ref`, and `path`

`sudo-broker` owns:

- operations such as `exec.command` and `session.shell`
- target kinds such as `user`, `group`, and `host`
- attrs such as `command_id`, `cwd`, `tty`, and `timeout_seconds`

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
