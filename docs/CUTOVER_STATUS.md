# Broker Cutover Status

This is the implementation handoff for the Brokerkit cutover across
`brokerkit`, `hf-broker`, `gh-broker`, and `sudo-broker`. The migration is a
direct cutover. Backward compatibility with broker-local control-plane code is
not required, and duplicated implementations must be deleted when the shared
package replaces them.

## Required End State

Brokerkit is the single implementation of shared auth, policy evaluation,
grant lifecycle, notification delivery state, Telegram transport, audit
primitives, common client configuration, and provider-neutral helpers. Each
broker keeps only provider classification, provider execution, credentials,
provider-specific approval wording, and edge protocol behavior.

Telegram has one lifecycle:

1. The broker claims a durable notification send from `brokerkit/grants`.
2. The Brokerkit Telegram adapter sends the message and returns a reference.
3. The broker commits that reference to the grant store.
4. Telegram polling returns a parsed callback and answers the callback query.
5. The broker verifies the token and applies the durable grant transition.
6. The broker claims due status updates and asks the adapter to edit the stored
   message reference.
7. The broker commits delivery only after the edit succeeds.

The Telegram adapter does not retain grant state, expiry timers, message
references, or delivery progress in memory.

## Implementation Order

### 1. brokerkit

- Done: provider-neutral policy registry and evaluation.
- Done: durable grants, send claims, message references, due status updates,
  retained reservations, and refreshed overlapping-reservation clocks.
- Current: persist ambiguous notification sends as unresolved claims so callers
  fail promptly while retry remains lease-bound and restart-safe.
- Done: removed the optional in-memory Telegram lifecycle and made the
  stateless transport contract the only API.
- Gate: race tests, coverage, vet, lint, Slophammer checks, mutation checks,
  review, and CI must pass before consumers pin the final API.

### 2. hf-broker

- Pin the final Brokerkit revision.
- Delete the broker-local Telegram transport and expiry tracker.
- Use Brokerkit notify and Telegram APIs directly.
- Drive send claims, callbacks, expiry, and status edits from durable grant
  state, including restart and retry tests.
- Remove every shared compatibility runtime that Brokerkit now replaces.
- Finish review, CI, merge, and a live Hugging Face plus Telegram test before
  moving to the remaining brokers.

### 3. gh-broker

- Keep the already implemented durable notification lifecycle.
- Pin the final stateless Telegram API and remove obsolete Telegram options.
- Re-audit for remaining shared auth, grant, notification, audit, config, or
  Git helper duplication and delete it where Brokerkit owns the behavior.
- Verify GitHub read, request, approval, execution, denial, and default-branch
  policy behavior end to end.

### 4. sudo-broker

- Continue pull request #7 for the durable notification lifecycle.
- Finish fail-closed quarantine and recovery after settlement-write failures.
- Retain unresolved send claims when Telegram delivery is ambiguous.
- Report remaining uses after subtracting live reservations.
- Pin the final Brokerkit API, remove legacy Telegram lifecycle code, and pass
  review, CI, and restart/retry tests.
- Verify allowed, denied, requested, approved, expired, and use-budgeted Unix
  execution without giving the client root-equivalent membership.

## Final Integration Work

After all code cutovers merge:

- Unify installer, setup, doctor, service, client-config, and uninstall
  behavior under the shared contract while keeping OS-specific privilege work
  in sudo-broker.
- Install all broker CLIs globally and ensure both `onur` and `bob` can invoke
  them without exposing upstream credentials.
- Keep persistent broker processes only where explicitly configured by the
  installer and validate restart behavior.
- Run live Telegram approval tests for all three brokers.
- Run real Hugging Face, GitHub, and Unix request flows from `bob`, including
  fail-closed and default-branch denial cases.
- Re-run cross-repository review, CI, documentation, secret-leak, and duplicate
  implementation audits before declaring the cutover complete.
