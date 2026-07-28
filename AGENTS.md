# AGENTS.md

These instructions apply to the unYOLO repository. More specific
instructions under a component directory may add stricter requirements.

## Project Rules

- Root packages are shared infrastructure for broker-style access-control
  services. Keep them provider-neutral and small.
- Provider-specific Hugging Face, GitHub, and Unix privilege logic is allowed
  only under the matching `brokers/` directory.
- Provider directories may import shared root packages. Shared root packages
  must not import `brokers/`, and one provider must not import another.
- Every broker remains a separate process, listener, credential domain, state
  directory, release artifact, and audit stream.
- The OpenClaw plugin lives under `plugins/openclaw`, consumes only Operator V1
  artifacts and released public OpenClaw APIs, and must not import provider
  executors or contain provider/channel-specific branches.
- `protocol/` is the canonical source for Operator V1 wire artifacts. Storage
  structs and UI models are not wire specifications.
- Secret material must never be returned by APIs, logs, errors, tests, or debug
  helpers.
- Policy code must stay generic. Provider-specific operations, target kinds, and
  attrs must be registered by the consuming broker.
- Do not add dependencies unless they remove real complexity.
- Do not add legacy routes, old-state readers, aliases, converters, dual reads,
  or dual writes. This repository uses a fresh-state coordinated cutover.
- Until the first public release, every unYOLO-owned wire API, persisted
  state format, plan schema, manifest, and protocol stays at version 1. Make
  incompatible pre-release changes by replacing v1 in place through the
  coordinated fresh-state cutover; do not introduce v0, v2, compatibility
  readers, or migrations. Package release versions are separate from format
  versions.
- Build approval-gated client workflows as durable blocking waits. After
  submission, the client must keep waiting or polling the same operation until
  the user records a decision and execution reaches a terminal state. A poll,
  transport, or tool timeout is an internal retry boundary, not a successful
  pending return. Reuse the same operation ID and return control only for a
  terminal result, explicit user cancellation, or unrecoverable error. This
  keeps agent turns alive so work continues automatically after the user clicks.
- Mutation tooling stays checked in but is disabled and non-blocking. Run it
  only when explicitly requested.

## Required Checks

- Do not report work as complete until the original user-visible workflow has
  been reproduced and verified end to end in its real target environment.
  Tests, mocks, CI, health checks, successful builds, and deployments are
  supporting evidence, not substitutes. If full verification is impossible,
  state that clearly and report the work as unverified.

Run these before finishing code changes:

```sh
go fmt ./...
go vet ./...
go test ./...
golangci-lint run
```

When `slophammer-go` is available, also run:

```sh
slophammer-go check .
```
