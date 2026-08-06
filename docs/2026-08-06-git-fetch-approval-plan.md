---
title: "Git Fetch Approval Plan"
author: "Onur Solmaz"
date: "2026-08-06"
---

# Git Fetch Approval Plan

Date: 2026-08-06

## Context

An agent tried to clone a repository it had no rule for and got
`git.fetch denied: no matching policy rule`. It could not even ask for
permission, because fetch is deny-only by design: only push has an approval
flow. The operator's expectation is that agents should be able to request
`git fetch` regardless of repository, with each request scoped to one
repository and approved explicitly, exactly like push approvals today.
A requestable fetch must not give standing read access to anything; deny
stays the default until the operator clicks approve.

## Scope

- gh-broker: make `git.fetch` (upload-pack discovery and upload-pack) and
  `git.lfs.write` (LFS upload batch) honor `request` decisions with a
  server-side approval transaction that mirrors the receive-pack flow.
- hf-broker: make `git.fetch` honor `request` decisions the same way.
- Both presets: emit default `request` rules with grant bounds for these
  operations so new deployments get requestable fetch out of the box.
- Documentation: update the integration plan and policy docs that say fetch
  is not requestable.

## Non-goals

- `git.push.advertise` stays allow-or-deny; Git needs discovery before it can
  compute a pack, so a request there adds a click with no information.
- sudo-broker stays catalog-only.
- Force push and ref deletion stay hard-denied for agent clients by explicit
  deny rules.
- No deployment changes in this PR. Existing deployments keep their current
  scope files; operators opt in by adding request rules (the deployed broker
  must run a build that contains this change for the rules to take effect).

## Design

Mirror the receive-pack approval transaction on the read paths:

1. Evaluate the operation. An allow (rule or active grant) proceeds exactly
   as today, including grant-use reservation and settlement.
2. A non-allowed decision is evaluated as a grant request. When the matching
   rule has effect `request` with grant bounds, the broker creates an
   idempotent grant request (same client request ID across Git's retries),
   notifies the operator inbox, and waits for the decision while holding the
   Git connection, bounded by the rule's request TTL.
3. On approval the broker revalidates policy, then proxies the request with
   the grant, accounting one use. On denial, expiry, or revocation it returns
   a stable Git-readable error naming the approval status and grant ID.
4. The grant is a window grant: duration and bounds come from the rule's
   `grant_policy`, so one approval covers discovery, upload-pack, and LFS
   traffic for that repository within the window.
5. Without an approval channel, or with incompatible bounds, the broker
   fails closed with the same errors the push flow uses.

The same client request ID derivation as receive-pack (digest of target,
attributes, and rule IDs, with pending/active generation reuse) keeps Git's
automatic retries idempotent: a retry during a pending approval attaches to
the same grant request instead of creating duplicates.

## Steps

1. gh-broker: add a shared fetch-approval path and wire it into upload-pack
   discovery, upload-pack, and the LFS batch/verify routes (download rides on
   `git.fetch`, upload on `git.lfs.write`).
2. hf-broker: add the same approval path for `git.fetch` in the forwarding
   flow.
3. Presets: append transport request rules (`git.fetch`, `git.lfs.write` for
   GitHub; `git.fetch` for Hugging Face) with grant bounds to the rendered
   default policy, and refresh shipped scope artifacts and fingerprints.
4. Docs: update `docs/2026-07-19-native-git-client-integration-plan.md` and
   any broker policy docs that state fetch is not requestable.
5. Tests: approval granted, approval denied, expiry, no approval channel,
   retry idempotency, grant-use accounting, and policy validation for the new
   preset rules.

## Acceptance criteria

- With a `request` rule for `git.fetch`, `git clone` of an unlisted
  repository waits, appears in the operator inbox, and completes after
  approval; a second fetch in the same window needs no new approval.
- Denial and expiry surface as stable Git-readable errors.
- Without any rule, fetch remains a hard deny with the same error as today.
- Push, LFS write, advertise, and HTTP API behavior are unchanged except for
  the new request paths.

## Verification

- `GOWORK=off go test ./...` with focused new tests in both brokers'
  `internal/httpapi` packages.
- `GOWORK=off go vet ./...`, `golangci-lint run`, `slophammer-go check .`,
  `scripts/check-architecture.sh`, `scripts/check-go-coverage.sh`.
- Local end-to-end against a test broker: clone with approval, deny path,
  retry idempotency.
- Not verified in this PR: behavior on the production host, which runs an
  older broker build and needs an upgrade plus scope rules to opt in.
