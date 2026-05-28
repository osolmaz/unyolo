# AGENTS.md

These instructions apply to this repository.

## Project Rules

- This is a Go backend for CBA, Credential Broker for Agents.
- Use Echo for HTTP routing. Do not introduce Gin.
- Keep domain behavior in `internal/credential` independent from HTTP, process state, databases, and network clients.
- Secret material must be write-only at the CBA API boundary. Do not add APIs, repository methods, logs, errors, tests, or debug helpers that return original credentials.
- Credential storage adapters may accept secret material only to hand it to a write-only external sink and return an opaque handle.
- Repository policies must be deny-by-default allowlists. Do not add broad GitHub API proxying, arbitrary `git`, organization admin, workflow admin, member management, or repository deletion operations.
- Keep package APIs small and explicit. Keep interfaces near their consumers.
- Do not add dependencies unless they remove real complexity.

## Required Checks

Run these before finishing code changes:

```sh
go fmt ./...
go vet ./...
go test ./...
go build ./cmd/cba-server
```

When `golangci-lint` and `slophammer-go` are available, also run:

```sh
golangci-lint run
slophammer-go check .
```
