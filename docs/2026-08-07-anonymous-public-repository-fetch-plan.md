---
title: Anonymous Public Repository Fetch Plan
author: Onur Solmaz <osolmaz@users.noreply.github.com>
date: 2026-08-07
tags: [authorization, git, github, hugging-face]
---

# Anonymous public repository fetch plan

## Goal

Public GitHub and Hugging Face repositories should be fetchable without an
approval. Private repository access must remain fail-closed and approval-gated.
The broker must prove public access by completing the real request anonymously;
it must never trust a caller-provided visibility value.

The implementation must also stop provider credentials from being attached to
public Git and Git LFS requests. Public access is an anonymous execution path,
not a weaker form of credentialed access.

## Current behavior

Both default broker presets apply a `request` rule to every `git.fetch`, so a
public clone waits for approval. Hugging Face repository content and metadata
operations use separate typed operation paths and are outside this Git transport
change.

## Scope

- Add a provider-neutral policy field named `credential_use` with `none` and
  `managed` values.
- Treat omitted `credential_use` as `managed` so existing rules keep their
  credential boundary.
- Allow providers to declare which credential-use values an operation supports.
- Add explicit anonymous `allow` rules for `git.fetch` in the GitHub and Hugging
  Face request-all presets. Keep the existing managed `request` rules.
- Attempt the real Git smart HTTP or Git LFS read request anonymously when the
  anonymous rule allows it.
- Fall back to the managed policy path only when a provider response means that
  credentials might help.
- Keep request bodies replayable across the anonymous attempt and approved
  managed retry.
- Audit the selected credential-use path without recording credentials, signed
  URLs, or response bodies.
- Regenerate shipped policy artifacts and update policy and native Git docs.

## Non-goals

- Writes never receive an anonymous execution path.
- Repository listing, typed content reads, snapshots, account data, Jobs, and
  administrative operations do not change in this work. The policy primitive
  can support a later typed-operation implementation without changing its wire
  shape.
- The broker does not cache repository visibility. Each request proves anonymous
  access again.
- The broker does not add arbitrary forwarding, provider fallback, or a direct
  network bypass.
- A public repository does not bypass existing body, response, redirect, LFS,
  Xet, or resource limits.

## Policy contract

`credential_use` is part of policy evaluation context. The broker selects it;
agent requests and provider payloads cannot set it.

```json
{
  "rules": [
    {
      "id": "allow-anonymous-fetch",
      "effect": "allow",
      "clients": ["agent"],
      "operations": ["git.fetch"],
      "targets": [{"kind": "repo", "owner": "*", "name": "*"}],
      "credential_use": ["none"]
    },
    {
      "id": "request-managed-fetch",
      "effect": "request",
      "clients": ["agent"],
      "operations": ["git.fetch"],
      "targets": [{"kind": "repo", "owner": "*", "name": "*"}],
      "credential_use": ["managed"],
      "grant_policy": {
        "mode": "window",
        "default_minutes": 5,
        "max_minutes": 10080,
        "request_ttl_minutes": 10,
        "default_max_uses": 1000000,
        "max_uses": 1000000
      }
    }
  ]
}
```

Rules without `credential_use` match `managed` only. Request rules cannot select
`none`, because an anonymous request must never create a credential grant.
Active grants are considered only for `managed` evaluation.

The policy registry defaults operations to `managed`. `git.fetch` explicitly
supports both values. Policy loading rejects unsupported values and rules that
select a value unsupported by one of their operations.

## Request flow

For `git.fetch`, the broker follows this order:

1. Evaluate policy with `credential_use=none`.
2. If allowed, replayably send the actual request through an anonymous transport.
3. Return any successful response directly.
4. If the provider returns `401`, `403`, or `404`, discard that response and
   evaluate the normal managed path.
5. If managed policy returns `request`, create or reuse one durable approval and
   keep waiting through the existing transaction.
6. After approval, replay the unchanged request with the managed credential.
7. Return timeouts, transport failures, `429`, and `5xx` responses without
   creating an approval.

A `404` does not prove that a repository is private or missing. Before approval,
the broker reports only that managed access was requested. It does not expose
whether the managed credential can see the repository.

## Credential isolation

The anonymous path must use request construction that cannot acquire, mint, or
attach a provider credential:

- Remove incoming `Authorization`, `Proxy-Authorization`, and cookie headers.
- Do not call the GitHub credential manager or Hugging Face token provider.
- Keep upstream origins fixed and preserve the current redirect policy.
- Treat signed LFS action headers as response-derived capabilities; never add a
  broker credential to an anonymous action request.
- Do not write an authentication failure response to the client before deciding
  whether to enter the managed path.

GitHub App installation tokens are minted only after managed authorization.
Hugging Face tokens are attached only by the managed request builder.

## Request replay

Anonymous POST attempts consume their request body. The broker must buffer each
eligible Git or LFS request under a fixed limit before the first upstream call,
then restore the exact bytes for every attempt. Oversized bodies fail before any
upstream call. The buffer is released when the request finishes.

## Provider boundaries

The shared policy core owns credential-use values, matching, validation, and
defaults. Each provider owns:

- which operations support anonymous access;
- which fixed upstream request is sent anonymously;
- which status codes mean managed credentials might help;
- provider-specific request and response handling; and
- provider audit details.

The shared root must not import either provider.

## Acceptance criteria

- A public GitHub clone and fetch complete without an approval.
- A public Hugging Face clone and fetch complete without an approval.
- No provider credential is acquired or attached on either public path.
- A private fetch makes one anonymous attempt, then creates one durable managed
  approval and completes after approval.
- A denied or expired private approval remains terminal and stable.
- Duplicate Git retries reuse one pending approval.
- A repository that changes access between discovery and upload-pack remains
  fail-closed; each request proves anonymous access independently.
- Network errors, `429`, and `5xx` responses do not create approval cards.
- Cross-origin redirects cannot receive credentials.
- Git LFS reads follow the same rule; writes remain managed-only.
- Existing managed-only policy rules preserve their behavior.

## Verification

Run the focused policy and broker tests first:

```sh
GOWORK=off go test ./authorization/policy
GOWORK=off go test ./brokers/github/internal/policy ./brokers/github/internal/policypreset
GOWORK=off go test ./brokers/github/internal/httpapi
GOWORK=off go test ./brokers/huggingface/internal/policy ./brokers/huggingface/internal/policypreset
GOWORK=off go test ./brokers/huggingface/internal/httpapi
```

Then run all required checks:

```sh
go fmt ./...
go vet ./...
go test ./...
golangci-lint run
slophammer-go check .
npx -y @simpledoc/simpledoc check
```

Before deployment, build the exact release images and run public-clone smoke
tests without provider credentials. Production verification must cover one
public GitHub repository, one public Hugging Face repository, and one private
approval. A successful build, health check, or mock test does not replace these
real workflows.

## Rollout

This is a hard replacement of the current policy behavior. The policy wire
format remains version 1 and gains the new field in place. Regenerate all
shipped policy profiles, manifests, scopes, and fingerprints. Release GitHub and
Hugging Face brokers independently. Deploy only explicitly selected deployments
after their exact release images pass the smoke tests.
