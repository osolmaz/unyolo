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
- idempotency key
- generated temporary allow rules

It should not own notification delivery or provider execution.

Cutover rule: after a broker imports `brokerkit/grants`, grant storage and state
transitions should have one runtime implementation.

## Phase 5: Extract HTTP Helpers

Extract only tiny helpers:

- hop-by-hop header filtering
- auth/credential metadata header filtering
- bounded body reading
- no-store response headers

Do not extract a generic reverse proxy. Each broker needs provider-specific
forwarding behavior.

## Phase 6: Extract Approval, Notify, And Telegram

Extract the generic approval workflow after grants are stable.

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
- Telegram callback-token validation

It should not own broker-specific message text. `hf-broker`, `gh-broker`, and
`sudo-broker` should compose their own approval summaries and pass them to the
shared notification adapter.

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
- callback with the wrong token is rejected
- stale or replayed callback is rejected
- status update edits the expected message
- bot token is never included in errors, logs, or audit metadata

Audit tests:

- JSONL shape is stable
- secret fields are redacted
- request bodies, Git pack bodies, command output, and approval tokens are absent
- grant id and matched rule ids are present when available

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
