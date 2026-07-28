# ADR 0001: unYOLO Monorepo Boundaries

Date: 2026-07-11

Status: accepted

## Decision

The existing `github.com/osolmaz/unyolo` repository is the authoritative
monorepo for the shared unYOLO runtime, Hugging Face broker, GitHub broker,
sudo broker, and independently packaged OpenClaw plugin.

Shared Go packages remain at the module root. Provider code lives only under
`brokers/huggingface`, `brokers/github`, or `brokers/sudo`. The OpenClaw plugin
lives under `plugins/openclaw`.

Every broker remains a separate process with separate credentials, listeners,
state, policy, execution, audit, and release artifacts. Repository colocation
does not merge runtime trust boundaries.

## Dependency Direction

```text
protocol artifacts -> generated bindings
shared Go runtime  -> provider-neutral dependencies only
provider brokers   -> shared Go runtime
OpenClaw plugin    -> Operator V1 bindings and released OpenClaw public APIs
```

Shared packages must not import a provider. Providers must not import one
another. The plugin must not import broker executors or contain provider- or
channel-specific behavior.

## Authority

unYOLO owns the common request, decision, grant, event, and audit lifecycle.
Each provider broker exclusively owns upstream credentials, request
classification, immutable executable plans, activation validation, execution,
provider backstops, and provider audit extensions. A trusted host may present
and deliver safe projections but never becomes an authority store.

`protocol/` owns the Operator V1 HTTP, SSE, OpenAPI, JSON Schema, examples, and
fixtures. Breaking wire changes require a coordinated major release. Only one
operator wire major is served.

## Releases

The root uses one Go module and supports the current configuration and state
schemas.

The root module uses `vX.Y.Z`. Component artifacts use qualified tags:
`hf-broker/vX.Y.Z`, `gh-broker/vX.Y.Z`, `sudo-broker/vX.Y.Z`, and
`openclaw-unyolo/vX.Y.Z`.
