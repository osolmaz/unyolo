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

## Ground Rules

- Do not give agents the upstream Hugging Face token.
- Do not add generic Hub API proxying.
- Do not add repo administration, bucket administration, settings, members,
  delete, or create operations until the project rule forbidding them is
  deliberately changed.
- Do not keep old and new policy runtimes alive together after policy cutover.
- Keep Git smart-HTTP responses Git-shaped. Use JSend only for `/api/*`.
- Keep policy, grant matching, path normalization, and ancestry logic free of
  Echo types.

## Slice 1: Policy Engine Cutover

Build `internal/policy` from `docs/POLICY_RULES_SPEC.md`.

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

- Replace direct `scope.DecideRepo` calls with `policy.Decide`.
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
- Support `type`, `owner`, `private`, `limit`, and `cursor`.
- Return only metadata allowed by `repo.list` and `repo.metadata.read`.
- Filter upstream-visible repos through policy before returning them.
- Use broker-owned opaque cursors.
- Bind cursors to client and query shape.
- Keep file paths, refs, commits, README/card text, blobs, LFS metadata, and
  file-tree listings out of listing responses.

Acceptance tests:

- broad listing returns only policy-matching repos
- listing does not return file paths or commit ids
- invalid cursor returns `invalid_cursor`
- cursor cannot be reused by another client
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
gofmt -l .
go vet ./...
go test -race ./...
go build ./cmd/hf-broker
golangci-lint run
/home/bob/go/bin/slophammer-go dry .
/home/bob/go/bin/slophammer-go crap .
/home/bob/go/bin/slophammer-go check .
```

When a tool is installed outside `PATH`, use its absolute path and say so in
the final report.
