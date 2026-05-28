# Implementation Plan

## Security Invariants

- Original credentials are never returned by HTTP handlers, service methods, logs, errors, audit records, or policy responses.
- CBA stores credential metadata and opaque handles only.
- Repositories are configured explicitly before any credential-backed operation can run.
- Policies are allowlists. Missing policy means deny.
- Agents receive approved operation results, not tokens.
- Write operations require an approval path before execution.
- CBA never exposes generic `git`, shell, or arbitrary GitHub API proxying.

## Current Scope

- Register a GitHub credential through a write-only boundary.
- Configure repositories that may use that credential.
- Keep policy simple and repo-scoped:
  - tenant id
  - repository owner and name
  - private/public marker
  - credential id
  - allowed agents
  - allowed operations
  - allowed branches
  - allowed paths
  - approval required for writes
- Support read-oriented GitHub operations first: repository metadata, content reads, tree listings, and pull request diff reads.
- Add write-oriented GitHub operations only behind policy and approval: branch creation, pull request creation, and content writes.

## Near-Term Work

- Persist credentials and repository configuration with migrations.
- Replace the development discarding sink with a production write-only credential backend.
- Add a policy decision function that answers one question: whether an agent may perform an operation on a configured repo path/branch.
- Add GitHub execution adapters for the narrow allowed operation set.
- Add audit events that record decisions and operation ids while redacting request bodies and secret-derived values.
- Add approval records for write operations.
- Add rate limits per tenant, agent, repository, and credential handle.
- Add prompt-injection regression tests for malicious repo content, issue text, PR text, and README instructions.

## Non-Goals

- No credential retrieval endpoint.
- No token introspection endpoint.
- No broad GitHub API proxy.
- No arbitrary local `git` command execution.
- No organization administration, secret management, workflow administration, member management, or repository deletion operations.

