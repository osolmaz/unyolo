# unYOLO architecture

unYOLO is the shared layer for broker-style access-control services. It
makes repeated broker machinery reusable without hiding the dangerous
provider-specific boundary.

The accepted next grant contract makes every grantable operation default to
window mode while preserving exact, single-use execution mode. See
[ADR 0002](adr/0002-universal-reusable-grants.md) and the
[reusable grants specification](REUSABLE_GRANTS_SPEC.md). Released binaries
retain their current provider classifications until that plan is implemented.

`hf-broker`, `gh-broker`, and `sudo-broker` use unYOLO for the shared control
plane. Provider directories contain only their platform-specific behavior.

## Broker shape

Every broker using unYOLO follows this request path:

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

## Package boundaries

unYOLO groups shared packages by product domain:

```text
unyolo/
|-- agent/         # Agent API, clients, runtime, MCP bridge, and wire adapters.
|-- approval/      # Decision presentation and notification lifecycle.
|-- authorization/ # Admission, policy, grants, decisions, and use budgets.
|-- broker/        # Shared control-plane assembly and conformance.
|-- credential/    # Provider credential contracts, storage, and lifecycle.
|-- git/           # Git client, server boundary, and protocol mechanics.
|-- mcp/           # Strict MCP transport and operation projection.
|-- operation/     # Capabilities, plans, payloads, and execution runtime.
|-- operator/      # Operator API, auth, clients, inbox, and wire adapters.
|-- telemetry/     # Audit and operational metrics.
|-- transport/     # Endpoint and HTTP transport profiles.
`-- internal/      # Module-private host, config, storage, and tooling code.
```

The complete layout and package placement rules are in
[DIRECTORY_STRUCTURE.md](DIRECTORY_STRUCTURE.md). The canonical ownership
boundary is [OWNERSHIP.md](OWNERSHIP.md).

## Shared package scope

unyolo may contain:

- bearer/basic shared-secret authentication for named clients
- minimum secret length checks
- policy rule parsing and matching
- operation, target, and attr registry mechanics
- effect ordering: deny, active grant, allow, request, no match
- grant policy bounds
- pending, active, expired, consumed, denied, and revoked grant states
- grant idempotency, expiry, use budgets, and reservations
- approval request, decision-token, callback, and revocation workflow
- bounded semantic approval presentation and notifier interfaces
- reusable canonical Telegram rendering, transport, and callback handling
- safe audit field helpers
- strict config decoding helpers
- atomic file storage and lock helpers
- proxy-safe HTTP header filters
- generic Git pkt-line, receive-pack command, ref update classification, and
  pack/body redaction helpers
- exact user-level Git URL rewrites, credential-helper protocol handling, and
  a route-restricted Git listener boundary
- provider-neutral Agent Operations V1 wire types and schemas
- strict MCP stdio protocol handling and Agent Operations lifecycle projection
- bounded authenticated sealed-payload and stream transfer clients
- exact generated Agent and Operator contract identities;
- signed immutable host release activation and rollback; and
- a durable encrypted Telegram callback inbox.

## Provider exclusions

unyolo must not contain:

- Hugging Face Git/LFS behavior
- GitHub REST or Git smart-HTTP behavior
- sudo, systemd, launchd, PAM, or TTY execution behavior
- provider-specific operation names as built-in global behavior
- provider-specific target kinds as built-in global behavior
- provider-specific approval wording
- command parsing for Unix shells
- broad framework wiring that makes simple brokers harder to understand

The systemd and launchd exclusion concerns provider operation execution.
unYOLO does own the narrow native service-manager adapters required to
activate and roll back its own immutable host bundle.

## Provider responsibilities

Each broker must register its own vocabulary.

MCP-enabled brokers also register provider-owned schemas, projections, and
runtime adapters. `mcp/server` owns JSON-RPC mechanics, `agent/mcp` owns durable
operation submission and recovery, and `agent/client` owns authenticated wire
transport. Authorization mode remains policy data; it never selects a
provider-specific MCP dispatch path. Under the accepted reusable-grant
contract, every grantable operation supports both modes and defaults to window.
Execution remains available for one exact immutable plan.

`hf-broker` owns:

- operations such as `git.push.append`, `git.push.force`, and
  `repo.contents.read`
- target kinds such as `repo` and `inference`
- attrs such as `ref`, `path`, `max_bytes`, and object keys
- Hugging Face-specific approval text

`gh-broker` owns:

- operations such as `pr.create`, `contents.read`, and
  `git.push.fast_forward`
- target kinds such as `repo` and `installation`
- attrs such as `ref`, `base_ref`, `head_ref`, and `path`
- GitHub-specific approval text

`sudo-broker` owns:

- the V1 `exec.command` operation
- the V1 `user` target kind
- attrs such as `command_id` and bounded typed argument values
- exact command catalogs and OS-specific execution backends
- Unix-specific approval text

## Security Invariants

unyolo must preserve these invariants:

- A broker client secret is not the protected upstream credential.
- Upstream credentials and privilege tokens are never returned to clients.
- Auth, policy, grant, and audit code must fail closed.
- Unknown operations, target kinds, and attrs are rejected unless the provider
  registry explicitly allows them.
- Audit records must not contain secrets, request bodies, pack contents, shell
  input, raw upstream responses, or token metadata.
- Grant records must be scoped to one client, one operation, one target, and the
  attrs approved by policy.
- A persistent callback consumer must match the exact Operator contract of
  every broker it can call before it consumes another update.
- A managed host is healthy only when every running executable belongs to the
  active signed bundle.

## Shared-Package Rule

Shared packages must expose provider-neutral behavior and tests. Provider
classifiers, credentials, execution, and wording remain in their broker.

## Native Git path

Git-speaking brokers use three distinct listeners: Agent V1, Operator V1, and
Git data plane. The Git listener is an explicit deployment-selected TCP
endpoint. unYOLO defines no default port. Its shared route gate exposes only
an authenticated identity handshake and provider-approved smart-HTTP and LFS
routes; agent operations, grants, webhooks, browser sessions, and operator
routes are unreachable on that listener.

`<broker> git install` writes exact user-level `url.*.insteadOf` mappings and a
credential helper scoped to that listener. Remotes keep their normal provider
URLs, provider credentials remain server-side, and an unavailable broker fails
closed instead of falling back to the provider.

GitHub and Hugging Face LFS action URLs are rewritten to bounded broker-local
capabilities, so upstream signed URLs and headers never cross the trust
boundary. Hugging Face Xet negotiation is explicitly refused until its custom
transfer can satisfy the same confinement and conformance requirements.
