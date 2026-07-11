# Extraction Plan

This plan keeps brokerkit small while `hf-broker`, `gh-broker`, and
`sudo-broker` prove the shared shape.

The migration strategy is cutover. We do not need backward compatibility between
local broker internals and brokerkit internals. If brokerkit owns a behavior,
the consuming broker should delete its local copy and use brokerkit directly.

## Goal

Create a shared Go module for repeated broker primitives without turning it
into a broad framework.

The first implementation should reduce duplication, not hide domain logic.

## Phase 1: Lock The Shared Contract

Define the shared API from the three broker designs before moving code.

Use this phase to compare:

- `hf-broker/internal/auth`
- `gh-broker/internal/security`
- `hf-broker/internal/policy`
- `gh-broker/internal/policy`
- `hf-broker/internal/grants`
- `hf-broker/internal/audit`
- `hf-broker/internal/notify`
- `gh-broker` audit helpers inside HTTP handlers
- `gh-broker/internal/shared`
- generic Git receive-pack parsing in `hf-broker` and `gh-broker`
- `sudo-broker` grants and command catalog behavior

Exit criteria:

- same behavior is needed by all three brokers, or by two brokers with a clear
  third-broker path
- the API has no provider-specific vocabulary baked into brokerkit
- tests can be moved with the behavior

## Phase 2: Extract Auth

Extract named-client shared-secret auth first.

The package should support:

- bearer token auth
- basic auth password auth
- multiple named clients
- constant-time comparison
- clear missing versus invalid errors

It should not depend on Echo, net/http middleware, or provider code. Brokers can
wrap it in their own HTTP middleware.

Cutover rule: after a broker imports `brokerkit/auth`, delete its local
duplicate auth package.

## Phase 3: Extract Policy Core

Status: implemented. The provider registry owns operation/target/attr
vocabulary, field and attr matcher semantics, grantability, and grant mode.
The core owns strict parsing, validation, ambiguity checks, precedence, and
active-grant overlays. Classified target fields and attrs use canonical string
lists so providers do not need a second matcher for multi-ref or multi-path
requests.

Extract policy only after the provider registry API is clear.

The first policy package should provide:

- rule parsing
- provider registry validation
- target and attr matching
- deny / grant / allow / request / no-match decision order
- audit-safe decision objects

It should not include built-in Hugging Face, GitHub, or Unix operations.

Cutover rule: after a broker imports `brokerkit/policy`, remove its local policy
engine and keep only provider registry, request classification, and tests for
provider-specific behavior.

## Phase 4: Extract Grant Records

Status: implemented for the shared pending/active/denied/expired/consumed/
revoked/canceled lifecycle, idempotency, decision tokens, expiry, use
reservation, crash-stale reservation recovery, durable notification
correlation, notification-send claims, retryable status discovery, and policy
overlays. Only provider-specific notification presentation remains in
consuming brokers.

Extract grant lifecycle types and store behavior after the policy request,
decision, and generated-rule overlay model is clear.

The package should support:

- pending
- active
- expired
- consumed
- denied
- revoked
- request TTL
- approved access duration
- use budget
- reservation, commit, and release of uses
- fail-closed retention of ambiguous or crash-stale reservations
- idempotency key
- generated temporary allow rules
- durable notification references and delivered-status keys
- leased notification-send claims and conditional cancellation
- durable unresolved-delivery claims for ambiguous sends, with retry only after
  the original lease expires
- fresh one-time approval tokens on every claimed delivery attempt, with only
  token verifiers persisted
- restart-safe discovery of notification updates that are still due

It should not own provider-specific notification text, transport delivery, or
provider execution.

Cutover rule: after a broker imports `brokerkit/grants`, grant storage and state
transitions should have one runtime implementation.

## Phase 5: Extract HTTP Helpers

Status: initial `brokerkit/httpx` package is implemented for provider-neutral
header filtering, bounded body reads, and no-store response headers. Brokers
still own provider-specific credential metadata names and upstream behavior.

Extract only tiny helpers:

- hop-by-hop header filtering
- auth/credential metadata header filtering
- bounded body reading
- no-store response headers

Do not extract a generic reverse proxy. Each broker needs provider-specific
forwarding behavior.

## Phase 6: Extract Approval, Notify, And Telegram

Extract the generic approval workflow after grants are stable.

Status: `brokerkit/notify` and `brokerkit/notify/telegram` are implemented as a
stateless transport. They provide provider-neutral approval messages, callback
answers, explicit Telegram send/status-edit behavior, inline approve/deny
callback data, long polling, and configured-chat filtering. Durable delivery,
pending/active/use/expiry state, and status retries belong exclusively to
`brokerkit/grants`, so they survive process restarts. Consuming brokers must cut
over and delete local Telegram transports and trackers.

Callback decisions use one shared transaction: token verification, the grant
transition, and recovery of a callback-carried message reference commit
together. If that transaction fails, Telegram polling must not acknowledge the
callback or advance past its update.

The package should support:

- approval request and decision models
- decision tokens
- callback verification
- approve, deny, cancel, and revoke actions
- status updates
- generic notifier interfaces
- reusable Telegram Bot API adapter
- Telegram inline approve/deny buttons
- Telegram chat/user allowlists
- Telegram callback payload parsing

It should not own broker-specific message text. `hf-broker`, `gh-broker`, and
`sudo-broker` should compose their own approval summaries and pass them to the
shared notification adapter. The broker verifies the parsed decision token
against the durable grant before changing grant state.

Cutover rule: after a broker imports `brokerkit/notify` and the Telegram
adapter, delete its local Telegram transport and callback implementation.

## Phase 7: Extract Audit, Config, And Store Helpers

Extract shared durability and audit support when it is used by grants and at
least one broker.

The packages should support:

- JSONL audit writer
- secret-safe audit fields
- grant/request/approval audit records
- strict config decoding helpers
- secret-safe validation errors
- atomic file writes
- lock handling
- test clocks and deterministic ids

They should not own provider-specific audit extension fields or broker-specific
config structs.

## Phase 8: Extract Generic Git Helpers

Extract only Git behavior that is provider-neutral across `hf-broker` and
`gh-broker`.

The package may support:

- pkt-line parsing
- receive-pack command parsing
- ref update classification
- safe Git request limits
- Git body and pack redaction helpers

It should not own Hugging Face mirror management, Hugging Face ancestry checks,
GitHub branch protection checks, GitHub App credentials, or provider forwarding.

## Phase 9: Add Versioned Releases

After at least one broker depends on brokerkit, use normal Go module releases:

```sh
git tag v0.1.0
gh release create v0.1.0 --generate-notes
```

Until then, keep the repository at pre-release design stage.

## Implementation Order

Implement brokerkit in this order:

1. `brokerkit/auth`
2. `brokerkit/policy`
3. `brokerkit/grants`
4. approval workflow
5. `brokerkit/notify` and the Telegram adapter
6. `brokerkit/audit`
7. storage and config helpers
8. generic Git helpers, only after comparing `hf-broker` and `gh-broker`
9. cut over `hf-broker`
10. cut over `gh-broker`
11. implement `sudo-broker`

The first brokerkit implementation should stop after auth and policy if the
grant overlay API is not yet clean. Do not add a grants package that cannot be
evaluated by the same policy engine.

## Implementation Readiness

brokerkit is ready to implement when the first slice can satisfy these
conditions:

- shared auth, policy, grants, notify, Telegram, audit, storage, and Git helper
  APIs stay provider-neutral
- every provider-specific operation, target, attr, classifier, executor, audit
  extension, and approval summary remains in the consuming broker
- every package has pure unit tests with deterministic clocks and ids where
  time or generated values matter
- Telegram is tested with a fake Bot API server or in-memory notifier in
  automated tests; CI must not require a live bot token or send real messages
- generated grants are evaluated by the same policy decision path as static
  rules
- no package exposes upstream credentials, approval tokens, Git pack contents,
  command input, command output, or Telegram bot tokens in errors, logs, audit
  records, or test failures
- at least one consuming broker can delete its local duplicate in the same
  cutover PR that imports the brokerkit package

## Test Matrix

Auth tests:

- bearer auth succeeds for the configured client
- basic auth succeeds for Git clients when the password is the client secret
- missing auth is distinguishable from invalid auth
- invalid auth fails closed
- multiple named clients are supported
- secret comparison uses constant-time comparison where practical

Policy tests:

- unknown operation is rejected
- unknown target kind is rejected
- unknown attr is rejected
- attrs on multi-operation rules must be supported by every operation in the rule
- duplicate rule ids are rejected
- deny beats allow
- deny beats active grant
- active grant beats static allow
- request rules do not allow execution
- no match denies
- generated grants cannot use wildcard clients
- attrs match exactly according to registry rules

Grant tests:

- request creates a pending grant
- request returns the raw decision token separately from the durable grant
- serialized grants and grant state files do not contain raw decision tokens
- same idempotency key and body returns the same grant
- same idempotency key with a different body conflicts
- approve activates a grant
- deny denies a grant
- expiry closes a grant
- use budget reserves, commits, and releases correctly
- ambiguous use fails closed

Approval tests:

- approval token matches only one grant
- replayed decision is rejected
- wrong approver is rejected
- expired pending request is rejected
- revoke closes an active grant

Telegram tests:

- approval send builds the expected generic Bot API payload
- buttons carry the correct grant id and decision token
- callback from the wrong chat is rejected
- callbacks never cause implicit message edits
- callback payloads preserve the opaque decision token for broker verification
- status update edits the expected message
- bot token is never included in errors, logs, or audit metadata

Consuming-broker tests must reject wrong, stale, and replayed decision tokens
through the durable grant store.

Audit tests:

- JSONL shape is stable
- secret fields are redacted
- request bodies, Git pack bodies, command output, and approval tokens are absent
- grant id and matched rule ids are present when available

## Merge Gates

Every brokerkit implementation slice must pass:

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

Slophammer is mandatory for brokerkit and for every broker that cuts over to
brokerkit. Keep DRY, CRAP, and check gates in CI, not just in local developer
notes. Keep mutation tooling checked in but disabled and non-blocking; it must
not run in the default required workflow unless a later explicit decision
re-enables it.

## Non-Goals

brokerkit should not provide:

- a CLI
- a daemon
- a generic broker server
- provider SDK wrappers
- sudo wrappers
- broker-specific Telegram message text
- command execution
- GitHub API proxying

Those belong in the consuming brokers.
