# AGENTS.md

These instructions apply to this repository.

## Project Rules

- This is a Go backend for gh-broker, a GitHub credential broker for coding agents.
- Use Echo for HTTP routing. Do not introduce Gin.
- Do not add credential management endpoints. Server-side GitHub credentials must be configured manually and must not have a readback path.
- Secret material must be write-only inside gh-broker. Do not add APIs, repository methods, logs, errors, tests, or debug helpers that return original credentials.
- `scope.json` is the authorization source of truth. Keep policy decisions inside `internal/policy`.
- Handlers may reject malformed transport requests, but they must not independently authorize valid broker operations.
- Keep broker routes compatible with Git smart HTTP and the generated typed Agent V1 operation surface.
- Do not add broad GitHub API proxying or arbitrary local shell execution.
- High-risk operations must remain explicit, narrowly typed, and policy-gated.
- Each invocation must retain its own immutable plan; execution-mode grants remain one-use.
- Keep package APIs small and explicit. Keep interfaces near their consumers.
- Do not add dependencies unless they remove real complexity.

## Required Checks

Run these before finishing code changes:

```sh
go fmt ./...
go vet ./...
go test ./...
go build ./cmd/gh-broker
```

When `golangci-lint` and `slophammer-go` are available, also run:

```sh
golangci-lint run
slophammer-go check .
```
