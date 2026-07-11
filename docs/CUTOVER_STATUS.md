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
4. Telegram polling returns a parsed callback to the broker.
5. The broker atomically verifies the token, applies the grant transition, and
   records the callback message reference when it was missing.
6. The Telegram adapter answers and advances the callback only after that
   transaction succeeds. A transient failure remains pending for retry.
7. The broker claims due status updates and asks the adapter to edit the stored
   message reference.
8. The broker commits delivery only after the edit succeeds.

The Telegram adapter does not retain grant state, expiry timers, message
references, or delivery progress in memory.

## Implementation Order

### 1. brokerkit

- Done: provider-neutral policy registry and evaluation.
- Done: durable grants, send claims, message references, due status updates,
  retained reservations, and refreshed overlapping-reservation clocks.
- Done: persist ambiguous notification sends as unresolved claims so callers
  fail promptly while retry remains lease-bound and restart-safe.
- Done: atomically recover a missing notification reference from an accepted
  callback without overwriting a concurrently recorded send result.
- Done: commit callback decisions and missing message references in one durable
  transaction, with unacknowledged offset-preserving retry on failure.
- Done: removed the optional in-memory Telegram lifecycle and made the
  stateless transport contract the only API.
- Done: canonical binary installer runtime with checksum and platform tests.
- Done: shared client setup, secret input, systemd option/rendering, and local
  doctor primitives.
- Done: shared privileged systemd installation for account creation,
  managed files, ownership, atomic unit installation, and service activation.
- Done: race tests, 85% coverage, vet, lint, Slophammer checks, secret scanning,
  vulnerability scanning, and CI pass. The final review and publication gate
  remains. Mutation tooling remains checked in but is disabled and non-blocking
  for this cutover.

### 2. hf-broker

- Done: final durable Brokerkit Telegram lifecycle pinned and merged.
- Done: adopt the first shared operations runtime and remove the duplicated
  installer, setup parser, unit renderer, and generic doctor helpers.
- Done: adopt shared privileged systemd installation and remove duplicated
  account, managed-file, ownership, and systemctl helpers.
- Done: a live request from `bob` reached the shared operator inbox and Telegram
  transport, then was canceled through Operator V1.

### 3. gh-broker

- Done: final durable Brokerkit Telegram lifecycle pinned and merged.
- Done: adopt the shared operations runtime and add GitHub-specific doctor
  checks on top of Brokerkit.
- Done: live GitHub installation listing and repository reads work from `bob`;
  a default-branch force-push request is denied before authority is created.
  Provider mutation is intentionally not part of this cutover gate.

### 4. sudo-broker

- Done: exact-command catalog, immutable plans, shared policy/grants/operator
  inbox/Telegram, durable fail-closed settlement, and the authenticated root
  helper are implemented in the monorepo.
- Done: shared setup-client, typed two-unit systemd installation, Unix-specific
  doctor checks, companion-binary release packaging, and global installer are
  implemented and tested.
- Done: Linux descriptor-safe execution uses `openat2` plus `execveat`; macOS
  uses the documented immediate-revalidation fallback.
- Gate: the monorepo Slophammer repository rules and sudo-broker's zero-finding
  DRY check are blocking. The CRAP report for privileged syscall and process
  orchestration code is retained as a refactoring baseline, but is not a
  release blocker for this security-sensitive cutover; broad metric-driven
  rewrites require their own focused review.
- Done: the isolated root helper executed the approved exact command as `onur`,
  consumed its one-shot approval, and rejected replay. `bob` remains outside
  the `sudo` and `docker` groups.

## Final Integration Work

After code review and CI pass:

- Done: unify installer, setup, doctor, service, client-config, and uninstall
  behavior under the shared contract while keeping OS-specific privilege work
  in sudo-broker.
- Done: install all broker CLIs globally and ensure both `onur` and `bob` can
  invoke them without exposing upstream credentials.
- Done: keep persistent broker processes only where explicitly configured by
  the installer and validate restart behavior.
- Done: verify the common Telegram lifecycle in every broker's integration
  suite and run a live credential-backed HF Telegram smoke test. Concurrent
  live GH and sudo delivery requires separately provisioned bot credentials;
  one Telegram bot token must not be polled by multiple broker processes.
- Done: run real Hugging Face, GitHub, and Unix request flows from `bob`,
  including fail-closed, one-shot replay, and default-branch denial cases.
- Gate: complete the final repository review, merge, reinstall from the merged
  revision, and confirm CI remains green.
