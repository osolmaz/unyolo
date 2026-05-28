# AGENTS.md

These instructions apply to this repository.

## Project Rules

- This is a Go backend for CBA, Credential Broker for Agents.
- Use Echo for HTTP routing. Do not introduce Gin.
- Do not add credential management endpoints. Server-side GitHub credentials must be configured manually and must not have a readback path.
- Secret material must be write-only inside CBA. Do not add APIs, repository methods, logs, errors, tests, or debug helpers that return original credentials.
- GitHub access config is only a PAT-like selection of owners and explicit repositories. Keep all operation rules hardcoded until the project needs more.
- Keep broker routes compatible with Git smart HTTP and the narrow GitHub REST endpoints being brokered.
- Do not add broad GitHub API proxying, arbitrary local shell execution, organization admin, workflow admin, member management, or repository deletion operations.
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
