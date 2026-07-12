# AGENTS.md

These instructions apply to this repository.

## Project Rules

- sudo-broker is a brokered Unix privilege-transition service.
- Do not build a sudo clone. Use mature local privilege primitives for the
  actual user switch.
- Use `github.com/osolmaz/brokerkit` for shared auth, policy, grant, audit, and
  notification primitives as those packages land.
- Secret material, approval tokens, session logs, command input, and command
  output that may contain secrets must not be returned through diagnostics or
  logged by default.
- Fixed commands must use declared command ids and exact argv templates. Resolve
  `argv[0]` before shell checks, and do not authorize arbitrary shell strings.
- Direct `exec.command` requests must be rejected unless they exactly match the
  request reclassified from the command catalog.
- Shell grants are time-bounded identity grants. Do not pretend they are
  command-scoped.
- Fail closed when a command, target user, host, policy rule, grant, executor,
  or audit path cannot be classified safely.

## Required Checks

Run these before finishing code changes:

```sh
go fmt ./...
go vet ./...
go test -race ./...
./scripts/check-go-coverage.sh
golangci-lint run
slophammer-go dry .
slophammer-go crap .
slophammer-go check .
```

Mutation tooling remains checked in but is disabled and non-blocking. Do not
run it unless explicitly requested.
