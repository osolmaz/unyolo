# AGENTS.md

These instructions apply to this repository.

## Project Rules

- brokerkit is shared infrastructure for broker-style access-control services.
- Keep the library small. Do not add provider-specific Hugging Face, GitHub, or
  Unix privilege execution logic.
- Secret material must never be returned by APIs, logs, errors, tests, or debug
  helpers.
- Policy code must stay generic. Provider-specific operations, target kinds, and
  attrs must be registered by the consuming broker.
- Do not add dependencies unless they remove real complexity.

## Required Checks

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
