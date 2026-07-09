---
title: Next Implementation Spec
author: Bob <dutifulbob@gmail.com>
date: 2026-07-08
---

# Next Implementation Spec

Goal: turn the cutover policy/API specs into working code without widening
the broker's authority model by accident.

This document specifies the next implementation slices after the Echo router
migration. Each slice should be merged only with tests that prove the broker
still fails closed and does not leak credentials.

Update: brokerkit is now the long-term shared base for broker-family control
plane code. hf-broker should treat its current auth, policy, grant, approval,
audit, notification, Telegram transport, shared storage/config, and generic Git
parsing code as reference material to cut into brokerkit, then cut back over to
the brokerkit packages. There is no backward-compatibility requirement for old
internal APIs or old policy formats.

## Ground Rules

- Do not give agents the upstream Hugging Face token.
- Do not add generic Hub API proxying.
- Do not add repo administration, bucket administration, settings, members,
  delete, or create operations until the project rule forbidding them is
  deliberately changed.
- Do not keep old and new policy runtimes alive together after policy cutover.
- Do not keep local and brokerkit policy, grant, auth, approval, notify,
  Telegram, storage, or audit runtimes alive together after brokerkit cutover.
- Do not keep a broker-local Telegram transport once the shared brokerkit
  Telegram adapter exists.
- Do not add converters or compatibility loaders for old `scope.json` formats.
  Operators should edit the new rule file directly.
- Keep Git smart-HTTP responses Git-shaped. Use JSend only for `/api/*`.
- Keep policy, grant matching, path normalization, and ancestry logic free of
  Echo types.

## Brokerkit Cutover Slices

These slices replace local generic code with brokerkit packages. Each cutover
should remove the old local implementation in the same PR that adopts
brokerkit.

1. Extract and adopt `brokerkit/auth`.
   - Move named-client bearer/basic shared-secret auth to brokerkit.
   - Keep hf-broker HTTP middleware local.
   - Delete the old local auth implementation after cutover.

2. Extract and adopt `brokerkit/grants`.
   - Move durable grant status, expiry, use budgets, and idempotency to
     brokerkit.
   - Keep HF operation classification and grant request API shape local.
   - Delete the old local grant store after cutover.

3. Extract and adopt `brokerkit/policy`.
   - Move generic rule parsing, registry validation, matching, and decision
     ordering to brokerkit.
   - Keep HF operation registry, repo/bucket targets, attrs, and request
     classification in hf-broker.
   - Delete `internal/policy` once hf-broker uses the brokerkit policy core.

4. Extract and adopt `brokerkit/audit` and `brokerkit/notify`.
   - Move secret-safe audit field helpers, notifier interfaces, approval
     workflow, and Telegram transport/callback handling to brokerkit.
   - Keep HF-specific audit extension fields and approval message wording local.

5. Extract and adopt shared storage/config helpers.
   - Move atomic file writes, lock handling, strict config decoding, test
     clocks, and deterministic ids to brokerkit where they are generic.
   - Keep HF-specific config fields and token loading local.

6. Extract generic Git helpers only where provider-neutral.
   - Move pkt-line parsing, receive-pack command parsing, ref update
     classification, request-size limits, and Git body redaction helpers to
     brokerkit if `gh-broker` can use the same API.
   - Keep HF commits-only mirrors, ancestry checks, LFS/Xet behavior, and Hub
     forwarding local.

## Current Cutover Status

`brokerkit/auth` is now adopted. `internal/auth` is only a small hf-broker
adapter that preserves the existing server API while delegating bearer/basic
shared-secret authentication to brokerkit with hf-broker's 32-byte secret
minimum.

`brokerkit/store` is now adopted for the local grant store's durable JSON file.
hf-broker still owns the HF-specific grant model, notification leases, retained
reservations, execution/window modes, and API response shape, but JSON reads and
atomic writes go through the shared brokerkit storage helper.

`brokerkit/notify/telegram` is now adopted for Telegram send, callback polling,
configured-chat filtering, status editing, and tracked pending/active expiry.
`internal/notify` keeps only HF-specific approval message text and the small
adapter that maps brokerkit callback decisions to hf-broker's grant store.

The remaining local `policy`, `grants`, `audit`, and Git proxy
packages still contain HF-specific behavior or richer local state than the
current brokerkit packages. Move them only when the brokerkit API can preserve
HF repo/bucket targets, numeric attrs, grant modes, reservation recovery,
Git push-options handling, pack preservation, and HF-specific audit fields
without introducing a parallel runtime.

## Brokerkit Cutover Test Gates

Every brokerkit cutover PR must prove:

- the replaced local implementation is deleted in the same change
- all valid auth, policy, grant, approval, and audit decisions go through
  brokerkit
- HF-specific code only registers operations, targets, attrs, request
  classifiers, upstream execution, audit extensions, and approval wording
- malformed or unclassified HF Git/LFS/API requests fail closed before upstream
  forwarding
- deny still overrides active grants
- active grants match only the approved client, operation, target, attrs,
  duration, and use budget
- Telegram approval uses the brokerkit adapter once it exists
- a force-push grant flow is tested end to end with a fake notifier and fake
  upstream
- audit output contains no broker secrets, upstream tokens, request bodies, Git
  pack contents, approval tokens, or Telegram bot tokens

## Implementation Readiness

The brokerkit cutover is ready to implement when the slice can satisfy this
contract:

- hf-broker imports brokerkit for shared auth, policy, grants, approval state,
  notification interfaces, Telegram transport, audit helpers, storage/config
  helpers, and provider-neutral Git parsing
- hf-broker keeps only Hugging Face operation registration, Git/LFS/API request
  classification, upstream forwarding, mirror/ancestry checks, audit extension
  fields, and approval summary text
- the replaced local runtime is deleted in the same PR as the brokerkit import
- generated grants are tested through the brokerkit policy decision path, not a
  second grant-specific allow path
- Telegram approval is covered with a fake Bot API server or fake notifier in
  automated tests; CI must not require a live bot token or send real messages
- end-to-end broker tests use fake upstream Hub servers and fake notifiers by
  default; live Hub checks are explicit manual or milestone probes

## Slice 1: Policy Engine Cutover

Build `internal/policy` from `docs/POLICY_RULES_SPEC.md`.

This slice is the reference implementation for `brokerkit/policy`. After the
brokerkit policy core lands, hf-broker should cut over and delete this local
engine rather than maintaining both.

Scope:

- Parse rule-based `scope.json` with top-level `rules`.
- Reject the old exact-entry `repos[]` and `buckets[]` runtime format.
- Validate the operation registry, target matchers, rule effects, grant
  policies, attrs, hard limits, and unknown fields.
- Implement glob matching exactly as specified.
- Implement conservative request-rule overlap validation.
- Add the `policy.Request` and decision object.
- Implement precedence:

```text
deny > active generated grant allow > static allow > request > no match
```

Acceptance tests:

- deny overrides static allow
- deny overrides active generated grant
- no match denies
- unknown operation denies
- malformed target denies
- repo listing allow does not imply content read
- content read does not imply git push
- request rule is requestable but not executable
- overlapping request rules with identical grant policy load
- overlapping request rules with different grant policy fail at startup
- generated grant with `clients: ["*"]` is rejected

## Slice 2: Handler Classification

Make handlers classify requests into `policy.Request` before enforcement.

Scope:

- Route all handler authorization through `policy.Decide`.
- Classify Git fetch, append push, force push, ref delete, tag update, LFS
  read/write, grant requests, and future `/api/*` routes.
- Preserve the append-only Git enforcement path before forwarding upstream.
- Audit the final classified operation, target, decision reason, and matched
  rule ids.
- Refuse every request the handler cannot classify.

Acceptance tests:

- existing Git/LFS proxy tests keep passing
- force push is classified separately from append push
- branch delete is classified separately from tag update
- malformed or unsupported Git/LFS routes do not reach upstream
- audit output does not contain request bodies, pack contents, tokens, or
  secrets

## Slice 3: JSend `/api/*`

Add a small JSend response package for JSON APIs.

Scope:

- Add explicit Echo routes under `/api/*`.
- Return only JSend envelopes from `/api/*`.
- Keep Git smart-HTTP routes outside JSend.
- Add stable `fail.data.reason` and `error.code` values from the policy spec.
- Reject unknown JSON request fields.
- Cap API request body sizes.
- Do not include raw upstream responses or request bodies in JSON errors.

Acceptance tests:

- success envelope shape
- fail envelope shape
- error envelope shape
- missing auth is JSend on `/api/*`
- Git auth failures remain Git/plain compatible
- malformed JSON returns `400` with `malformed_json`
- policy denial returns `403` with `policy_denied`
- approval-required execution returns `403` with `approval_required`

## Slice 4: Grant API Cutover

Move grants to the cutover API shape.

Scope:

- Implement `POST /api/grants`.
- Implement `GET /api/grants`.
- Implement `GET /api/grants/{id}`.
- Keep operator decisions out of the agent-authenticated API surface.
- Use `client + client_request_id` idempotency.
- Store grants as generated allow rules evaluated by `internal/policy`.
- Separate pending request TTL from approved access duration.
- Start approved access at approval time.
- Reserve window-grant uses before forwarding upstream.
- Retain ambiguous reservations fail-closed.

Non-goal:

- Do not keep `/grants` as a long-term route after cutover.

Acceptance tests:

- requestable grant creates pending grant
- non-requestable grant returns `not_requestable`
- same idempotency key and same body returns the same grant
- same idempotency key and different body returns `409`
- approved grant allows exactly the requested client, operation, target, attrs,
  duration, and use budget
- expired grant is refused
- consumed grant is refused
- active grant does not override deny
- pending grant is not executable
- decision token never appears in API responses

## Slice 5: Repo Listing API

Implement metadata-only repository listing.

Scope:

- Add `GET /api/repos`.
- Support `type`, `owner`, `limit`, and reserved `cursor`.
- Return only type, owner, and name for exact repo targets that have both
  `repo.list` and `repo.metadata.read` allowed for the authenticated client.
- Do not call the Hub list API or expand wildcard policy targets in the
  cutover endpoint.
- Return `invalid_cursor` for any non-empty cursor.
- Keep file paths, refs, commits, README/card text, blobs, LFS metadata, and
  file-tree listings out of listing responses.

Acceptance tests:

- listing returns exact policy targets only
- listing does not return file paths or commit ids
- invalid cursor returns `invalid_cursor`
- public repo still requires broker policy when accessed through broker

## Slice 6: Doctor Polish

Make `hf-broker doctor` easier to act on.

Scope:

- Keep the current JSON schema stable unless a change is explicitly
  documented.
- Improve text output for `safe`, `unsafe`, and `inconclusive`.
- Show exact remediation commands when possible.
- Report missing helper tools and searched paths.
- Detect tools in common local paths such as `~/go/bin` even when `PATH` is
  incomplete.
- Never print secret values or token file contents.

Acceptance tests:

- doctor output never includes token values
- root-equivalent agent is unsafe
- unreadable token file passes
- readable token file fails
- helper tool detection covers `$PATH`, `~/go/bin`, and `~/.local/bin`
- macOS unsupported or unknown checks remain clearly inconclusive, not safe

## Slice 7: Echo Route Cleanup

Make Echo routing explicit after the API cutover lands.

Scope:

- Keep `/healthz` as an explicit public `GET`.
- Add explicit `/api/grants`, `/api/grants/:id`, and `/api/repos` routes.
- Keep Git smart-HTTP behind a catch-all route.
- Keep route handlers thin; domain decisions stay in internal packages.
- Avoid Echo middleware that reads or buffers Git pack bodies.

Acceptance tests:

- `GET /healthz` is public
- `HEAD /healthz` requires auth or is refused
- every non-health route requires auth
- Git clone/push still works through Echo
- large Git pack bodies are not buffered by framework middleware

## Deferred Work

These are intentionally not next:

- repo creation
- repo delete
- repo settings update
- repo member update
- namespace transfer
- billing, quota, paid hardware, or storage tier changes
- generic Hugging Face API proxying
- arbitrary command execution

Those require a separate product decision and an explicit change to the
repository rules before implementation.

## Merge Gates

Every implementation slice must pass:

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
slophammer-go dry .
slophammer-go crap .
./scripts/check-mutation.sh
slophammer-go check .
```

When a tool is installed outside `PATH`, use its absolute path and say so in
the final report.
