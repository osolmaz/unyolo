# Extraction Plan

This plan keeps brokerkit small while `hf-broker`, `gh-broker`, and
`sudo-broker` prove the shared shape.

## Goal

Create a shared Go module for repeated broker primitives without turning it
into a broad framework.

The first implementation should reduce duplication, not hide domain logic.

## Phase 1: Copy Nothing Yet

Keep this repository mostly documentation until the package boundaries are
clear.

Use this phase to compare:

- `hf-broker/internal/auth`
- `gh-broker/internal/security`
- `hf-broker/internal/policy`
- `gh-broker/internal/policy`
- `hf-broker/internal/grants`
- planned `sudo-broker` grants and command catalog behavior

Exit criteria:

- same behavior is identified in at least two brokers
- the third broker can use the same API without special cases
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

## Phase 3: Extract Grant Records

Extract grant lifecycle types and store behavior after `sudo-broker` confirms
the same states are useful.

The package should support:

- pending
- active
- expired
- consumed
- denied
- revoked
- expiry
- use budget
- idempotency key

It should not own notification delivery or provider execution.

## Phase 4: Extract Policy Core

Extract policy only after the provider registry API is clear.

The first policy package should provide:

- rule parsing
- provider registry validation
- target and attr matching
- deny / grant / allow / request / no-match decision order
- audit-safe decision objects

It should not include built-in Hugging Face, GitHub, or Unix operations.

## Phase 5: Extract HTTP Helpers

Extract only tiny helpers:

- hop-by-hop header filtering
- auth/credential metadata header filtering
- bounded body reading
- no-store response headers

Do not extract a generic reverse proxy. Each broker needs provider-specific
forwarding behavior.

## Phase 6: Add Versioned Releases

After at least one broker depends on brokerkit, use normal Go module releases:

```sh
git tag v0.1.0
gh release create v0.1.0 --generate-notes
```

Until then, keep the repository at pre-release design stage.

## Non-Goals

brokerkit should not provide:

- a CLI
- a daemon
- a generic broker server
- provider SDK wrappers
- sudo wrappers
- Telegram-specific approval logic
- command execution
- Git packet parsing
- GitHub API proxying

Those belong in the consuming brokers.
