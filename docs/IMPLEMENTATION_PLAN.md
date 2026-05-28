# Implementation Plan

## Security Invariants

- Original credentials are never returned by HTTP handlers, service methods, logs, errors, or audit records.
- CBA stores credential metadata and opaque handles only.
- Agents receive operation results, not tokens.
- Every operation is policy checked before a credential handle can be used.
- High-risk operations require explicit approval hooks before execution.

## Phase 1: Foundation

- Keep the Echo server small and authenticated.
- Add persistent metadata storage with migrations.
- Replace the development discarding sink with a real write-only backend.
- Add structured audit events that redact all request bodies and secret-derived values.
- Add CI gates for tests, vet, lint, build, and Slophammer.

## Phase 2: GitHub Broker

- Add GitHub repository read operations first: repo metadata, file read, tree listing, and pull request diff read.
- Add branch and pull request creation only after policy checks exist for owner, repo, branch name, base branch, and file path allowlists.
- Do not expose generic `git` or arbitrary GitHub API proxying.
- Do not expose token introspection or token export.
- Require protected-branch assumptions in repository policy documentation.

## Phase 3: Policy Engine

- Model policies as explicit allowlists for tenants, agents, credential handles, tools, repositories, operations, and paths.
- Deny by default.
- Add approval states for write operations.
- Add replay protection and request IDs for operation execution.
- Add rate limits per tenant, agent, and credential handle.

## Phase 4: Production Secret Boundary

- Evaluate a backend that can use secrets without returning them to CBA callers, such as a dedicated signer/executor service, cloud KMS-backed broker, or hardware-backed module.
- Keep the CBA application database free of reversible secret blobs.
- Make credential rotation and revocation first-class operations.
- Add break-glass procedures that revoke handles rather than reveal credentials.

## Phase 5: Hardening

- Add integration tests for prompt-injection-style operation requests.
- Add fuzz tests for policy parsing and route input validation.
- Add security headers, request body size limits, and strict content-type checks.
- Add tamper-evident audit log export.
- Threat model agent OS-user separation, local socket access, Docker group access, and browser automation access.

