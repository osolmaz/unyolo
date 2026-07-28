---
title: Architecture
description: The shared control plane, the provider boundary, and the package layout that enforces it.
---

unYOLO is the shared layer beneath `hf-broker`, `gh-broker`, and `sudo-broker`. Its job is to
make the repeated broker machinery reusable without hiding the dangerous provider-specific
boundary. This page describes the request path, what belongs on each side of that boundary, and how
the Go package tree keeps the two apart.

## Request path

Every broker follows the same sequence:

```text
authenticate client
classify request
evaluate policy
check active grant
optionally create approval request
execute provider-specific action
write audit entry
```

Only two of those stages know anything about a provider. Classification turns a raw input into a
tuple, and execution performs the upstream action. The rest is shared code that could not name a
Hugging Face repository if it wanted to.

## Shared layer ownership

The shared packages cover authentication for named clients, policy parsing and matching, the effect
ordering, grant bounds and lifecycle states, grant idempotency and use budgets, the approval
request and decision-token workflow, the bounded presentation model operators see, the canonical
Telegram rendering and callback handling, audit field helpers, strict config decoding, atomic file
storage, proxy-safe HTTP header filters, and the generic Git mechanics for pkt-line parsing,
receive-pack command reading, ref update classification, and pack redaction.

It also owns things that are easy to assume are provider concerns but are not. Exact user-level Git
URL rewrites and credential-helper protocol handling are shared, because the failure mode of
getting them wrong is identical for every provider. So are the provider-neutral Agent Operations V1
wire types, the strict MCP stdio protocol handling, signed immutable host release activation and
rollback, and the durable encrypted Telegram callback inbox.

## Broker ownership

The shared layer must not contain Hugging Face Git or LFS behaviour, GitHub REST or smart-HTTP
behaviour, sudo, systemd, launchd, PAM, or TTY execution behaviour, provider-specific operation
names or target kinds as global built-ins, provider-specific approval wording, or shell command
parsing.

One exclusion has a subtlety worth stating. The systemd and launchd exclusion is about provider
operation execution. unYOLO does own the narrow native service-manager adapters it needs to
activate and roll back its own host bundle, because that is host lifecycle rather than a brokered
operation.

Each broker registers its own vocabulary. `hf-broker` owns operations such as `git.push.append`,
`git.push.force`, and `repo.contents.read`, target kinds such as `repo` and `inference`, and attrs
such as `ref`, `path`, and `max_bytes`. `gh-broker` owns `pr.create`, `contents.read`,
`git.push.fast_forward`, the `repo` and `installation` target kinds, and attrs such as `base_ref`
and `head_ref`. `sudo-broker` owns the single `exec.command` operation, the `user` target kind, and
`command_id` plus bounded typed argument values.

## Package layout

The Go tree is organised by product domain rather than by layer:

```text
unyolo/
|-- agent/         # Agent V1 API, clients, runtime, MCP bridge, wire adapters
|-- approval/      # Decision presentation and notification lifecycle
|-- authorization/ # Admission, policy, grants, decisions, use budgets
|-- auth/          # Shared broker-client authentication primitives
|-- broker/        # Shared control-plane assembly and conformance suites
|-- brokers/       # The GitHub, Hugging Face, and sudo brokers
|-- cmd/           # Provider-neutral entrypoints and release tools
|-- credential/    # Provider credential contracts, storage, lifecycle
|-- git/           # Git client, server boundary, protocol mechanics
|-- install/       # Canonical standalone installer
|-- mcp/           # Strict MCP transport and operation projection
|-- operation/     # Capabilities, plans, payloads, execution runtime
|-- operator/      # Operator API, auth, clients, inbox, wire adapters
|-- plugins/       # Packaged integrations such as the OpenClaw plugin
|-- protocol/      # Canonical OpenAPI, generated wire code, fixtures
|-- telemetry/     # Secret-safe audit and bounded operational metrics
|-- transport/     # Endpoint and HTTP transport profiles
`-- internal/      # Module-private host, config, storage, tooling
```

Placement follows a fixed order. Provider-specific behaviour goes under `brokers/<provider>/`. A
reusable public contract goes in its existing domain directory. Shared implementation that only
this module needs goes under `internal/`. Canonical wire definitions go under `protocol/`.
Entrypoints stay thin and live in `cmd/` or the provider's own `cmd/`.

The tree deliberately has no `pkg/`, `src/`, `common/`, `shared/`, or `utils/` directory, and
adding a new top-level directory requires a durable product domain rather than code that did not
fit the first package someone considered.

## Dependency direction

Dependencies point inward:

```text
commands and plugins
        ↓
provider brokers
        ↓
public unYOLO domains
        ↓
internal infrastructure and protocol artifacts
```

Shared domains never import `brokers/`. One provider never imports another provider, which Go
enforces through each broker's own `brokers/<provider>/internal/` directory. Protocol packages
define wire contracts and do not depend on execution code. `scripts/check-architecture.sh` runs
this check in CI.

## Listener separation

A Git-speaking broker runs three distinct listeners, and conflating them is the mistake the design
is built to prevent.

The **Agent V1** listener is client-scoped. It carries operation submission, grant requests, sealed
payloads, and streams, authenticated with the broker client secret.

The **Operator V1** listener carries the approval inbox, lifecycle events, and Prometheus metrics.
It uses a separate credential that no agent holds, and reusing a client secret here is rejected at
startup.

The **Git data plane** is an explicit deployment-selected TCP endpoint with its own route gate. It
exposes an authenticated identity handshake plus provider-approved smart-HTTP and LFS routes.
Agent operations, grants, webhooks, browser sessions, and operator routes all return not found on
that listener, so a Git endpoint cannot be repurposed into a broad agent API.

unYOLO defines no default port for any of them. Production setup on Linux uses
permission-restricted Unix sockets for the agent and operator listeners; the Git listener needs a
TCP endpoint because standard Git clients require one.

## Security invariants

The shared layer is required to preserve these properties, and the conformance suite tests them:

- A broker client secret is never the protected upstream credential.
- Upstream credentials and privilege tokens are never returned to clients.
- Auth, policy, grant, and audit code fails closed.
- Unknown operations, target kinds, and attrs are rejected unless the provider registry allows them.
- Audit records contain no secrets, request bodies, pack contents, shell input, raw upstream
  responses, or token metadata.
- A grant is scoped to one client, one operation, one target, and the attrs policy approved.
- A persistent callback consumer matches the exact Operator contract of every broker it can call
  before consuming another update.
- A managed host is healthy only when every running executable belongs to the active signed bundle.

## Native Git

Git support is the part of the architecture that most affects daily use. `<broker> git install`
writes exact user-level `url.*.insteadOf` mappings plus a credential helper scoped to the broker's
listener origin. Remotes keep their ordinary provider URLs, no credential is stored in Git config,
and an unavailable broker fails closed instead of falling back to the provider.

LFS action URLs from GitHub and Hugging Face are rewritten to bounded broker-local capabilities, so
upstream signed URLs and headers never cross the trust boundary. Hugging Face Xet negotiation is
refused outright until its custom transfer can meet the same confinement requirements, rather than
being enabled by exporting the Hub token.

A receive-pack request is treated as one authorization transaction. Every ref is classified before
a single byte is forwarded. A deny rejects the whole batch, and requestable refs produce one
approval bound to the exact body digest and ordered command set. Atomic and multi-ref pushes are
never split into separately authorized updates.
