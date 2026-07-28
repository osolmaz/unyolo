# AGENTS.md

These instructions apply to the Hugging Face broker subtree of the BrokerKit
repository. Root `AGENTS.md` and root quality gates also apply.

## Project Rules

- This is hf-broker: the Hugging Face provider adapter for BrokerKit and a
  self-hosted append-only credential broker for
  Hugging Face repos. The full design is `docs/SPECIFICATION.md`; read it
  before changing enforcement, routing, or configuration behavior.
- Secret material is write-only inside the broker. No API, log line,
  error, test helper, or debug path may return or print the upstream
  Hugging Face token, broker client secrets, or token metadata.
- Scope configuration (`scope.json`) is a manually edited file. Do not add
  endpoints that read, reload, or change it.
- Do not add generic Hub API proxying or arbitrary command execution.
  Repository administration is allowed only through fixed typed operations
  whose exact target and arguments are policy checked, approval bound, and
  executed by hf-broker.
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
go mod tidy
git diff --exit-code -- go.mod go.sum
go mod verify
gofmt -l .            # must print nothing
go vet ./...
go test -race ./brokers/huggingface/...
go build ./brokers/huggingface/cmd/hf-broker
golangci-lint run
govulncheck ./...
slophammer-go dry .
slophammer-go crap .
slophammer-go check .
```

If a tool is installed outside `PATH`, run it by absolute path and report
that in the final note.

Hard targets: coverage >= 85, CRAP <= 8, production DRY findings = 0.
