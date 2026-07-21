# BrokerKit Directory Structure

BrokerKit uses a domain-first Go package tree. Top-level directories represent
stable product domains or repository-level deliverables. Implementation details
that are not part of the reusable Go surface belong under `internal/`.

## Canonical Tree

```text
brokerkit/
|-- agent/           # Agent V1 API, client, runtime, MCP bridge, and wire adapters.
|-- approval/        # Decisions, safe presentation, notifications, and channels.
|-- auth/            # Shared broker-client authentication primitives.
|-- authorization/   # Admission, policy, grants, decisions, and use budgets.
|-- broker/          # Shared broker assembly and black-box conformance suites.
|-- brokers/         # Provider-specific GitHub, Hugging Face, and sudo brokers.
|-- cmd/             # Provider-neutral process entrypoints and release tools.
|-- credential/      # Provider credential contracts, storage, and lifecycle.
|-- git/             # Git client integration, listener boundary, and protocol helpers.
|-- install/         # Canonical standalone installer and its tests.
|-- internal/        # Host, config, storage, validation, and tooling internals.
|-- mcp/             # Provider-neutral MCP transport and operation projection.
|-- operation/       # Capability metadata, plans, payloads, and execution runtime.
|-- operator/        # Operator V1 API, auth, client, inbox, and wire adapters.
|-- plugins/         # Packaged integrations such as the OpenClaw plugin.
|-- protocol/        # Canonical OpenAPI, generated wire code, and protocol fixtures.
|-- telemetry/       # Secret-safe audit and bounded operational metrics.
|-- transport/       # Shared endpoint and HTTP transport profiles.
|-- docs/            # Maintained contracts and dated implementation records.
|-- scripts/         # Repository quality, generation, and maintenance commands.
|-- go.mod
`-- README.md
```

Subpackages make ownership explicit. Agent V1 code lives under `agent/`, Git
mechanics live under `git/`, and authorization state and policy live under
`authorization/`. Do not add another concatenated root package such as
`agentclient` or `gitserver`.

## Placement Rules

Use these rules in order:

1. Provider-specific behavior belongs under `brokers/<provider>/`.
2. A reusable public contract belongs under its existing domain directory.
3. Shared implementation needed only inside this module belongs under
   `internal/`.
4. Canonical wire definitions and generated protocol artifacts belong under
   `protocol/`.
5. Executable entrypoints stay small and belong under `cmd/` or the owning
   provider's `brokers/<provider>/cmd/` directory.
6. Standalone installation assets belong under `install/`; service rendering
   and setup implementation belong under `internal/host/`.

Host-wide immutable activation lives in `internal/host/bundle`. Native
service-manager mechanics stay in platform-suffixed files in that package. The
operator-facing entrypoint is `cmd/brokerkit`; individual broker setup commands
must not duplicate bundle staging, protocol identity, rollback, or host doctor
logic.

Do not create `pkg/`, `src/`, `common/`, `shared/`, or `utils/`. A new top-level
directory requires a durable product domain, not merely code that does not fit
the first package considered.

## Public And Internal Packages

Every shared Go package outside `internal/` and `brokers/` is an intentional
reusable surface. Keep it provider-neutral, documented, bounded, and
independently tested. Provider packages are product implementation boundaries,
not shared APIs. Move a package into `internal/` when only BrokerKit binaries
consume it.

Go enforces the `internal/` boundary. All packages in this module may use root
`internal/` packages, while external modules cannot import them. Provider-local
implementation remains under `brokers/<provider>/internal/`, which prevents one
provider from importing another provider's private code.

## Dependency Direction

Dependencies point inward:

```text
commands and plugins
        v
provider brokers
        v
public BrokerKit domains
        v
internal infrastructure and protocol artifacts
```

Shared domains must never import `brokers/`. One provider must never import
another provider. Protocol packages define wire contracts and must not depend
on provider execution code.

## Generated And Local Output

Generated source stays beside its owning contract or under
`protocol/generated/`. Local coverage, build, package-manager, and Slophammer
output is ignored and is not part of the repository structure.
