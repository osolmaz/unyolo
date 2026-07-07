# AGENTS.md

These instructions apply to this repository.

## Project Rules

- This is hf-broker: a self-hosted append-only credential broker for
  Hugging Face repos. The full design is `docs/SPECIFICATION.md`; read it
  before changing enforcement, routing, or configuration behavior.
- Secret material is write-only inside the broker. No API, log line,
  error, test helper, or debug path may return or print the upstream
  Hugging Face token, broker client secrets, or token metadata.
- Scope configuration (`scope.json`) is a manually edited file. Do not add
  endpoints that read, reload, or change it.
- Do not add generic Hub API proxying, arbitrary command execution, or
  repo/bucket administration operations (create, delete, settings,
  members) in any mode.
- Every endpoint except `GET /healthz` requires authentication.
- Fail closed: a request the policy engine cannot classify is refused.
- Audit log lines never contain secrets, request bodies, or pack contents.
- Use Echo for HTTP routing. Do not add other dependencies unless they
  remove real complexity.
- Keep domain logic (parsing, policy decisions, ancestry) free of
  `net/http` so it stays unit-testable without a server.

## Required Checks

Run these before finishing code changes:

```sh
gofmt -l .            # must print nothing
go vet ./...
go test -race ./...
go build ./cmd/hf-broker
```

When `golangci-lint` and `slophammer-go` are available, also run:

```sh
golangci-lint run
slophammer-go dry .
slophammer-go crap .
slophammer-go check .
```

Hard targets: coverage >= 85, CRAP <= 8, production DRY findings = 0.
