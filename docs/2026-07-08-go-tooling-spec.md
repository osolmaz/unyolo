---
title: Go Tooling Spec
author: Bob <dutifulbob@gmail.com>
date: 2026-07-08
---

# Go Tooling Spec

Goal: make local and CI checks reproducible while using a patched Go
toolchain.

## Tool Versions

| Tool | Version | Reason |
|------|---------|--------|
| Go language version | `go.mod` `go 1.25.0` | Required by current Echo and `golang.org/x/*` modules. |
| Go toolchain | `go1.26.4` | Patched toolchain for standard-library vulnerability fixes. |
| Echo | `v4.15.4` | HTTP routing framework. |
| `golangci-lint` | `v2.12.2` | Pinned CI linter version. |
| `govulncheck` | `v1.5.0` | Pinned vulnerability scanner version. |
| `slophammer-go` | `v0.4.0` | Existing pinned CI version. |

Do not use `@latest` in CI for Go tools. Upgrade tool versions in their own
commit with a note about the required Go version.

The Go language version and toolchain are intentionally separate. The code
uses Go 1.25 language/module semantics, while CI and local auto-toolchain use
Go 1.26.4 for patched standard-library builds and `govulncheck` results.

## Local Merge Gate

Run this before merging code changes:

```sh
go mod tidy
git diff --exit-code -- go.mod go.sum
go mod verify
gofmt -l .
go vet ./...
go test -race ./...
go build ./cmd/hf-broker
golangci-lint run
govulncheck ./...
/home/bob/go/bin/slophammer-go dry .
/home/bob/go/bin/slophammer-go crap .
./scripts/check-go-coverage.sh
./scripts/check-mutation.sh
/home/bob/go/bin/slophammer-go check .
```

If a tool is installed outside `PATH`, run it by absolute path and report
that in the final note.

## CI Requirements

The main CI workflow must:

- set up Go toolchain `1.26.4`
- run `go mod download`
- run `go mod tidy` and fail if `go.mod` or `go.sum` changes
- run `go mod verify`
- run `gofmt -l .`
- run `go vet ./...`
- run `go test -race -coverprofile=coverage.out ./...`
- run `go build ./cmd/hf-broker`
- install and run pinned `golangci-lint`
- install and run pinned `govulncheck`
- install and run pinned `slophammer-go`
- run Slophammer DRY, CRAP, the coverage script, the mutation script, and
  non-executing checks

`scripts/check-mutation.sh` defaults to mutation scan mode for CI. Set
`HF_BROKER_FULL_MUTATION=1` to run the current full mutation target; that is
intentionally a manual hardening path until the target has no survivors.

The release workflow must at least run:

- `go mod download`
- `go mod verify`
- `go test ./...`
- release packaging script

## Dependency Rules

Echo is the only approved HTTP framework dependency. Keep Echo use inside
`internal/httpapi`.

Do not add new runtime dependencies casually. A new dependency should either
remove meaningful complexity or enforce a security boundary that would be
riskier to hand-roll.

Slophammer dependency boundaries cover internal package relationships. The
human rule for external dependencies is: feature/domain packages must not
depend on Echo or other HTTP framework types.

## Upgrade Policy

Upgrade Go or tooling intentionally:

- check the tool module's declared `GoVersion`
- keep the repo's Go language version unchanged unless the upgrade is
  deliberate
- keep the CI toolchain on a patched Go release
- update this spec, CI, and `AGENTS.md` in the same commit
- run the full local merge gate
