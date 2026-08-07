---
date: 2026-08-07
author: Onur Solmaz <osolmaz@users.noreply.github.com>
title: Make approvals and runtime boundaries reliable
tags: [approvals, hugging-face, telegram, mlclaw, runtime]
---

# Make approvals and runtime boundaries reliable

## Goal

Every unYOLO approval must either succeed or tell the user why it could not
succeed. MLClaw must also keep broker credentials isolated, store model
selection in one durable place, accept supported reasoning messages, expose a
small policy-relevant broker tool list, preserve owner tools for an authenticated
Telegram owner, and provide a protected way to list Hugging Face Jobs.

A live approval click on 2026-08-07 reached HF Broker. HF Broker left the grant
pending and returned only `decision_failed`. The current code does not preserve
a safe error category for plan, credential, notification, and storage failures,
so the exact production failure is still unknown. A matching local approval
with a 30-minute duration and two-use budget passed, which rules out a general
Telegram or reusable-grant failure.

## Repositories

The work belongs in these repositories:

- unYOLO owns approval state, Operator V1 errors, Telegram callback retries, HF
  plan validation, the inference proxy, broker tool discovery, and protected
  Jobs operations.
- MLClaw owns process environments, durable deployment settings, Telegram owner
  configuration, version pins, runtime packaging, and deployment checks.
- OpenClaw changes are allowed only if a test proves that MLClaw supplies the
  correct owner identity and OpenClaw still drops it before tool assembly.

This document is the canonical plan. MLClaw implementation notes should link to
it rather than copy it.

## Requirements

- Keep each deployment's provider credential inside its HF Broker process.
- Never give OpenClaw a broad Hugging Face token.
- Do not weaken plan, notification, credential, or unknown-field validation.
- Do not log raw errors, request bodies, credentials, Telegram callback data,
  chat IDs, paths, targets, or reasons.
- Keep one durable decision path for browser and Telegram approvals.
- Treat permanent failures as terminal and retry only failures that can recover.
- Preserve exact idempotency for repeated clicks and process restarts.
- Use version 1 contracts and state formats in place. Do not add compatibility
  readers, aliases, or dual writes.
- Do not launch paid compute while verifying these changes.

## Non-goals

- No manual database edits or manual approval bypass.
- No browser or Chrome dependency for broker operations.
- No generic HTTP forwarding to Hugging Face.
- No broad Hub token inside the OpenClaw process.
- No attempt to infer active Jobs from logs, health checks, or failed CLI calls.
- No rewrite of the broker, Telegram ingress, or OpenClaw.

## Interface and data-model review gate

Review and freeze the changed interfaces before implementation. The review must
cover these contracts together so one layer cannot invent a private meaning for
another layer's state:

- `authorization/activation.Failure`, including closed codes, stages,
  retryability, a private cause, and `Unwrap` behavior;
- `grants.Grant`, grant status validation, lifecycle events, status groups, and
  durable decision records;
- Operator V1 `Status`, `BrokerEvent`, `Error`, and generated client types;
- Telegram `DecisionResult`, callback inbox rows, terminal status rendering,
  and duplicate-tap behavior;
- OpenClaw plugin and web UI request models, error models, and terminal waiting
  behavior;
- MLClaw's canonical runtime-settings schema and generation check;
- the policy-aware operation-discovery interface; and
- the existing `job.list` and `job.read` request and result schemas.

Record the final field names, enum values, state transitions, retry ownership,
and persistence rules in this plan before changing code. Regenerate every
checked-in wire artifact from its canonical schema rather than hand-editing
generated files.

## Approval failure contract

### Typed internal failures

Add a provider-neutral typed failure type under `authorization/activation`:

```go
type Failure struct {
    Code      Code
    Stage     Stage
    Retryable bool
    cause     error
}

func (f *Failure) Unwrap() error { return f.cause }
```

Construct failures through a validating constructor. `Error` returns only the
safe closed code. The private cause supports `errors.Is` inside the process but
must never be serialized, logged, persisted, or used as a metric label. Code
must compare sentinels or typed values, never error strings.

Use this closed code set:

| Code | Stage | Retry | Meaning |
| --- | --- | --- | --- |
| `invalid_notification` | notification | no | A well-formed callback message failed snapshot or digest integrity checks. |
| `plan_unavailable` | plan | no | The immutable plan is missing or unreadable. |
| `plan_mismatch` | plan | no | The grant and immutable plan do not match. |
| `credential_changed` | credential | no | The current provider credential differs from the credential bound into the plan. |
| `credential_insufficient` | credential | no | The credential cannot perform the approved operation on the target. |
| `constraint_exceeded` | constraints | no | The operator tried to widen the requested grant. |
| `storage_unavailable` | storage | yes | The durable decision could not be read or committed. |
| `temporarily_unavailable` | dependency | yes | A required local dependency timed out or was unavailable. |
| `internal_error` | internal | yes | An unclassified defect occurred. This remains fail-closed. |

Malformed notification shape, missing required fields, and out-of-bounds input
remain `invalid_request` and return `400`. `invalid_notification` is reserved
for a structurally valid callback whose stored presentation or rendered digest
fails integrity validation; it returns `409`.

Existing codes such as `not_found`, `revision_conflict`,
`idempotency_conflict`, `invalid_transition`, and `invalid_decision_token`
remain distinct.

### Classify errors where they start

Make these source changes:

- `authorization/grants/notifications.go`: keep malformed or out-of-bounds
  message references under `invalid_request`, and wrap only snapshot or digest
  integrity failures as `invalid_notification` while preserving the private
  cause in memory.
- `brokers/huggingface/internal/hfplan/plan.go`: return `plan_unavailable`,
  `plan_mismatch`, `credential_changed`, or `credential_insufficient` from the
  exact failing branch.
- `authorization/grants` and `internal/storage/state`: mark durable load and
  save failures as `storage_unavailable`.
- `authorization/decision/service.go`: map typed failures to stable audit and
  Operator V1 codes. Remove the generic fallback for every known branch.
- Add table tests that force every branch and prove that no raw cause appears
  in API responses, audit JSON, diagnostics, or metrics.

### Operator V1 response

Extend the version 1 Operator error enum in
`protocol/openapi/operator-v1.yaml` and regenerate the checked-in Go types.
Each failed request keeps the existing opaque `correlation_id` and returns one
safe code from the table above.

Pass the request correlation ID through the decision service and include it in
the safe diagnostic record and audit extension. Do not add the raw error to a
protected log. The correlation ID and closed code are enough to connect the
HTTP response, decision audit, Telegram retry, and metric.

Use these HTTP classes:

- `400` for malformed decision or notification input;
- `404` for a missing request;
- `409` for revision, idempotency, token, constraint, plan, notification
  integrity, and credential conflicts;
- `503` with bounded `Retry-After` for storage or dependency failures; and
- `500` for `internal_error`, which remains an explicitly retryable closed code.

## Terminal activation failures

Add `failed` as a terminal grant status in the existing version 1 state and
Operator V1 contract. Add only these safe fields to a failed grant:

```text
failure_code
failure_reference
failed_at
```

`failure_reference` is the bounded correlation ID from the terminal attempt.
Do not persist a raw failure message or private cause. `failed` means the broker
could not safely activate the grant. It is different from `denied`, `canceled`,
and `expired`.

Update every closed status surface in the same change:

- `grants.Status`, persisted-state validation, lifecycle reconciliation,
  retention, and history status grouping;
- a durable `request.failed` lifecycle event and the Operator V1
  `BrokerEvent.kind` enum;
- Operator V1 `Status`, request projection, allowed actions, event streaming,
  OpenAPI, generated Go and TypeScript clients, and conformance fixtures;
- notification lifecycle updates, Telegram terminal answers and renders, and
  browser-initiated failure reconciliation;
- the OpenClaw plugin and delegated web UI models; and
- all agent wait and polling paths, which must treat `failed` as terminal and
  return its safe code instead of continuing to wait.

The decision transaction should behave as follows:

- `invalid_notification`, `plan_unavailable`, `plan_mismatch`,
  `credential_changed`, and `credential_insufficient` atomically move the grant
  from `pending` to `failed`, append `request.failed`, and write a decision
  record containing the safe failure code and correlation ID.
- The durable decision record stores no raw error. Exact replay of the same
  idempotency scope and command hash returns the same failed grant and the same
  typed failure. A different command hash returns `idempotency_conflict`.
- `constraint_exceeded` leaves the grant pending because a browser operator may
  submit narrower constraints.
- `storage_unavailable`, `temporarily_unavailable`, and `internal_error` leave
  the grant pending because no safe terminal transaction was committed.
- A stale revision returns the current safe grant without applying a second
  decision.

This is a coordinated fresh-state change. Replace the version 1 state in place
and start the deployed broker with fresh grant, plan, and callback state. Keep
OpenClaw workspace and conversation state.

## Telegram behavior

Update `approval/notifier/telegram/dispatcher.go`, the durable inbox, and the
renderer so the user sees the real outcome.

### Retry rules

- Retry only explicit retryable codes: `storage_unavailable`,
  `temporarily_unavailable`, and `internal_error`.
- Use bounded exponential backoff with jitter and honor a bounded
  `Retry-After` value.
- Stop retrying when the grant becomes terminal or the callback expires.
- Treat `409` plan, credential, notification-integrity, idempotency, and
  transition failures as terminal.
- Treat `revision_conflict` specially. When its safe `current` grant is still
  pending, refresh the expected revision and retry the same logical callback.
  When `current` is terminal, render that terminal state and stop.
- Build and persist one canonical notification decision for the logical
  callback. Reuse its exact rendered text, snapshot, digests, action, and
  idempotency key across retries. Only the expected revision may change after a
  pending revision conflict, before any decision record has committed.
- Emit one bounded diagnostic per attempt category.

### Repeated taps

Derive one logical callback key from route, grant ID, message ID, action, and
the decision-token verifier. Do not include Telegram's callback ID in the
broker idempotency key. Persist the logical key with a unique constraint so
several taps create one pending decision, not several retry loops.

The first tap owns the encrypted decision authority. A later tap with the same
logical key must still answer its distinct Telegram callback ID immediately:
return the current terminal answer when the grant is terminal, or `Approval is
already being processed` while the first decision remains pending. It must not
store a second copy of decision authority or start another retry loop.

The Telegram callback ID remains only for answering Telegram. The raw decision
token remains encrypted and is erased when the callback becomes terminal.

### User messages

Add fixed safe answers and terminal renders:

- `Approval received` after the callback is durably stored;
- `Grant approved` after commit;
- `Approval failed because the request is no longer valid. Create a new request.`
  for plan or credential failures;
- `Approval message could not be verified. Create a new request.` for
  notification integrity failures; and
- `Broker is temporarily unavailable. The approval will retry automatically.`
  for retryable failures.

A terminal failure removes both buttons in the same edit. It includes the short
correlation ID from the terminal attempt, but no target, path, token, or raw
error.

## Approval tests

Add tests at four levels.

### Unit tests

Test every failure code, HTTP status, retry flag, terminal transition, audit
record, and Telegram render. Include malformed snapshots, bad digests, missing
plans, changed credential bindings, insufficient capabilities, failed state
writes, revision conflicts, and exact idempotent replay.

### Shared integration test

Run the real Telegram dispatcher against the real Operator V1 HTTP handler and
durable grant store. Use the exact production-shaped request:

```text
operation: bucket.object.write
target: bucket/<owner>/artifacts
duration: 30 minutes
max uses: 2
```

Use a normalized user-scoped credential snapshot with `repo.write`. Assert that
one callback activates the grant, a repeated tap replays the result, the card
becomes approved, and no callback remains queued.

### Process test

Start `hf-broker` and `unyolo-telegram` as subprocesses with temporary SQLite
files and a fake Telegram API. Send a real callback update through the polling
loop. Assert the Operator V1 request, decision transaction, callback answer,
message edit, restart recovery, and final queue state.

### Fault test

Inject one failure at each decision stage. Prove that permanent failures stop,
transient failures retry, a pending revision conflict refreshes and retries,
duplicate taps each receive an answer, failed decisions replay exactly, restart
resumes one logical callback, and no test log contains a credential or raw
callback token.

## Evidence handling

The typed failure taxonomy is useful even if the 2026-08-07 failure never
reproduces. Ship classification and observability without making reproduction a
release gate. Treat identification and repair of that exact branch as
best-effort until a typed occurrence or safe existing evidence identifies it.
Do not claim that an unrelated local reproduction fixed the incident.

Do not download, copy, or persist another broker-state snapshot for forensics.
Before fresh-state replacement, retain only existing safe audit records,
correlation IDs, plan digests, timestamps, and protected provider records that
remain in their normal credential boundary. Do not move credential-bearing
state to a new local or remote store. If that evidence does not identify the
branch, report the cause as unknown and rely on the typed post-release result.

## Broker credential isolation

MLClaw currently copies the HF Broker agent secret into `HF_TOKEN` and
`HUGGINGFACE_HUB_TOKEN` before starting OpenClaw. Hugging Face CLI then mistakes
that internal broker credential for a Hub token.

Change `src/mlclaw-space-runtime/server.ts` as follows:

- Delete both generic environment assignments when `brokerAgentSecret` exists.
- Keep the broker secret only in the protected file named by
  `MLCLAW_HF_BROKER_AGENT_SECRET_FILE`.
- Keep the MCP subprocess environment limited to
  `HF_BROKER_AGENT_ENDPOINT` and `HF_BROKER_SHARED_SECRET_FILE`.
- Configure a dedicated OpenClaw file-backed `SecretRef` for the Hugging Face
  model provider. The reference points at the protected broker-agent secret
  file; `openclaw.json` contains only the reference, never the literal value.
- Do not use environment indirection for this credential because arbitrary
  OpenClaw tools can inspect the child environment.
- Keep legacy direct Router credentials separate and name their use explicitly;
  do not silently reuse a broker credential as a Hub credential.

Update workspace guidance so `hf auth whoami` reporting no login is expected.
Protected Hub work must use HF MCP or HF Broker. The agent must never call
`hf auth login` or ask for a token.

Tests must inspect the actual OpenClaw child environment and prove that
`HF_TOKEN`, `HUGGINGFACE_HUB_TOKEN`, and the broker secret value are absent.
Build a real state archive and scan every file and byte sequence to prove that
neither the broker secret nor a literal provider API key is present. Also prove
that the file-backed `SecretRef` resolves for model inference and that
`hf-broker mcp` still works.

Existing snapshots from affected deployments may already contain the narrow
broker agent secret through `openclaw.json`. Rotate that credential for every
affected deployment after the fixed runtime is ready, replace broker grant and
plan state, and verify that a post-rotation snapshot contains no old or new
secret value. Rotation uses the supported MLClaw credential workflow and still
requires the credential-store authorization required by the deployment.

## One durable model setting

The current runtime reads the snapshotted settings file before
`OPENCLAW_MODEL`. An old snapshot can therefore override a newer CLI model
change.

Replace the two-writer design with one canonical settings object outside the
OpenClaw snapshot:

```text
.mlclaw/runtime-settings.json
```

The trusted MLClaw wrapper owns this file. In Space mode it lives in the mounted
private control area. In local mode it lives in the deployment control
directory. OpenClaw receives the chosen model but cannot write this file.

Use this behavior:

1. Bootstrap creates the canonical file atomically from the deployment
   manifest.
2. The CLI and control UI update the same file through trusted MLClaw code.
3. The runtime reads only this file after bootstrap.
4. `OPENCLAW_MODEL` is a bootstrap input, not a competing runtime setting.
5. State snapshots exclude the file, so restoring a conversation cannot roll
   model selection backward.
6. A write uses a generation check, atomic replacement, `0600` mode, and a
   bounded schema.
7. `mlclaw doctor` compares the deployment manifest and canonical file and can
   repair drift only after showing which side will win.

Remove the old live `.mlclaw/settings.json` reader in the same release. Do not
keep a fallback or dual-read path.

Tests must cover CLI update, control-UI update, restart, snapshot restore,
concurrent generation conflict, and deployment-scoped model selection. The
final live test must restart the deployment and retain its selected model.

## Kimi reasoning messages

HF Broker's inference proxy currently rejects `reasoning_content` when
OpenClaw sends a prior assistant message back to the Router.

Update `brokers/huggingface/internal/httpapi/inference.go`:

- Add `reasoning_content` to the closed assistant-message field set.
- Accept it only on `assistant` messages.
- Accept the Router's documented string form and `null`; reject other types.
- Count a non-empty reasoning string as assistant content when ordinary
  `content` is null.
- Keep the total request-size limit and unknown-field rejection.
- Forward the accepted field unchanged. Do not invent or translate reasoning.

Add a two-turn regression test. The fake upstream returns Kimi-style
`reasoning_content` on turn one, and turn two sends that assistant message back
through HF Broker. Test both buffered and streaming responses, malformed field
types, and use on non-assistant roles.

## Smaller broker tool inventory

HF Broker should advertise only operations that the authenticated client could
possibly use under the loaded policy.

Add policy-aware operation discovery:

- Filter by authenticated client and exact operation name.
- Include an operation when at least one loaded `allow` or `request` rule names
  that authenticated client and exact operation. Do not build a target-schema
  satisfiability solver for discovery.
- Exclude operations covered only by deny rules or rules for other clients.
- Keep target and attribute checks at execution time. Tool visibility never
  grants authority.
- Always include bounded grant and operation lifecycle tools needed to recover
  pending work.
- Recompute the catalog after a policy reload and emit the existing MCP
  list-changed notification.

Do this in HF Broker, which owns the policy. Do not maintain a second list of
HF tool names in MLClaw. MLClaw may keep its user-supplied `toolFilter`, but the
broker-filtered catalog is the default.

Tests must compare the advertised catalog for two clients with different
policies and prove that visibility never grants authority. Include a policy in
which deny rules cover every tested target: the tool may remain visible from
name-level discovery, but every invocation must still be denied.

## Telegram owner tools

Logs from the affected deployment show that OpenClaw removes these 11 tools
because the Telegram turn is not marked as owner-authenticated:

```text
computer, conversations_list, conversations_send, conversations_turn, cron,
gateway, mobile_ui, nodes, openclaw, sessions, terminal
```

MLClaw supports one configured private Telegram user. Update
`scripts/configure-telegram.mjs` so the plain normalized user ID remains in the
Telegram `allowFrom` list and the provider-qualified form
`telegram:<user-id>` is written to OpenClaw's explicit
`commands.ownerAllowFrom` list. Preserve unrelated command settings, but manage
these owner IDs as deployment security configuration.

Add an integration test using the pinned OpenClaw package. A message from the
configured Telegram user must set `senderIsOwner: true` and retain the 11
owner-only tools. A different sender must be rejected before the agent runs and
must never gain those tools. Browser admin sessions must continue to use their
`operator.admin` scope.

If this test shows that OpenClaw receives the right owner list but loses the
owner bit in the Codex runner, fix that propagation in OpenClaw and pin the
released version in MLClaw. Do not work around it by making every sender an
owner or by disabling owner-only policy.

## Protected Hugging Face Jobs reads

The capability catalog already contains typed `job.list` and `job.read`
operations marked `blocked-upstream`. Implement and unblock those existing
entries instead of adding new operation names or schemas. Record the upstream
API or official SDK surface that removes the block, and update the catalog,
bindings, generated tools, and implementation status together.

`job.list` must use bounded pagination and filters. `job.read` must require one
exact Job ID. Results should expose only the safe fields needed to state
whether a Job is pending, running, completed, failed, canceled, or unknown.
They must include the observed timestamp and provider response identity.

Allow each deployment to list and read Jobs only in the owner scope granted by
its policy. Keep `job.run`, `job.cancel`, and other mutations approval-gated. A
failed list call must produce `unknown`; it must never be reported as zero
active Jobs.

## Release and deployment order

Use two release trains so unrelated broker features cannot delay the approval
and credential fixes.

### Reliability and security train

1. Freeze the interfaces and data models listed in the review gate.
2. Add typed activation failures, safe Operator V1 mappings, correlation, and
   tests in unYOLO. This work ships even if the original failure remains
   unknown.
3. Use only existing safe evidence to classify the original failure. If it is
   identified, fix that branch and add its regression test. Otherwise record it
   as unresolved and continue; do not invent a cause or download state.
4. Add the complete terminal `failed` state, durable failed-decision replay,
   retry classification, pending-revision refresh, callback deduplication,
   duplicate-tap answers, Telegram text, and process tests.
5. Run all unYOLO Go checks and Slophammer.
6. Publish one immutable HF Broker and unYOLO plugin release. Because Operator
   V1 and persisted-state behavior gain substantial new capability, use the
   repository's next pre-1.0 minor release unless release history requires
   another rule.
7. In MLClaw, remove generic HF token injection, replace the literal model API
   key with a file-backed `SecretRef`, add archive secret scanning, add the
   canonical runtime-settings file, and configure `telegram:<user-id>` as the
   owner.
8. Pin the exact released broker, plugin, and any required OpenClaw version in
   `package.json`, then run `npm run release:sync` and `npm run release:check`.
9. Run every MLClaw quality gate, package check, generated-bundle check, and
   runtime-image test.
10. Deploy first to a disposable MLClaw test Space with fresh broker grant and
    callback state, then run the reliability subset of live verification.
11. Release MLClaw, verify the multi-platform image digest, and update only the
    deployments selected for this rollout.
12. After the fixed runtime is active, rotate the broker agent credential for
    every affected deployment through the supported MLClaw workflow, replace
    broker grant and plan state, and verify a clean post-rotation snapshot.
13. Run the reliability subset again on every selected deployment.

### Broker feature train

1. Add bounded Kimi `reasoning_content` request support and its two-turn tests.
2. Add name-level policy-filtered tool discovery and authorization-separation
   tests.
3. Implement and unblock the existing `job.list` and `job.read` catalog
   operations and their result schemas.
4. Run all unYOLO checks, publish one immutable broker release, pin it in
   MLClaw, and run all MLClaw checks.
5. Deploy to a disposable test Space, run the feature subset of live
   verification, then release and update only selected deployments.

Do not publish an intermediate MLClaw image with mismatched Operator V1,
plugin, and HF Broker versions. Do not begin the feature train until the
reliability and security train passes its live verification.

## Live verification

The change is complete only after this exact user-visible workflow passes in a
test deployment and then in every deployment selected for rollout:

1. `mlclaw doctor <owner/space>` is clean.
2. A direct typed `hf-broker` metadata read with Codex `_meta.threadId`
   succeeds without Chrome.
3. The deployment starts with its selected model, restarts, restores state, and
   keeps the same model.
4. `hf auth whoami` inside the agent has no generic Hub credential and does not
   call the broker credential stale.
5. A two-turn Kimi fixture succeeds through the same broker image.
6. The configured Telegram owner receives the complete intended owner tool set;
   an unconfigured sender is denied.
7. The agent requests a 30-minute, two-use `bucket.object.write` grant for two
   harmless test objects.
8. The user taps Approve once. Telegram says it received the tap, HF Broker
   moves the grant to active, the card becomes approved, and no retry remains.
9. The agent writes both objects, reads them back through a typed broker
   operation, and verifies their expected hashes.
10. The agent calls `job.list` and reports the observed Job counts and
    timestamp. A failed read is reported as unknown.
11. Restart the deployment once and confirm callback, grant, model, and
    operation state recover correctly.
12. Confirm logs, audit records, metrics, snapshots, and Telegram state contain
    no raw credentials or callback tokens.

No paid Job is launched during this verification.

## Acceptance criteria

- One Telegram tap produces one logical decision.
- A successful approval becomes active and continues the waiting agent work.
- A permanent failure becomes terminal and tells the user to create a new
  request.
- A transient failure retries automatically without asking the user to tap
  again.
- Every approval failure has a safe code, stage, and correlation ID.
- No production surface contains a raw internal error or secret.
- OpenClaw receives no generic Hugging Face token when HF Broker is enabled.
- Model changes survive restart and snapshot restore without an environment
  workaround.
- Kimi reasoning messages survive a second turn through HF Broker.
- HF Broker advertises only policy-relevant operation tools.
- The configured Telegram user retains owner-only tools; other users do not.
- Each configured deployment can list Jobs through a protected typed read and
  makes no unsupported active-compute claim.
- The exact approval, write, read-back, and restart workflow passes on every
  deployment selected for rollout.
