# Implementation Plan

## Security Invariants

- Original credentials are never returned by HTTP handlers, service methods, logs, errors, audit records, or API responses.
- CBA stores credential metadata and opaque handles only.
- GitHub access must be configured before a credential-backed operation can run.
- GitHub access config is only a PAT-like selection of owners and explicit repositories.
- Operation rules stay hardcoded for now.
- CBA never exposes generic `git`, shell, arbitrary GitHub API proxying, token introspection, or token export.

## Current Scope

- Register one or more GitHub credentials through a write-only boundary.
- Configure GitHub access for a credential with:
  - `owners`: blanket owner/org/user accounts, like selecting all repos under an owner for a PAT.
  - `repositories`: explicit `owner/name` repositories.
- Keep everything else hardcoded in code.
- Start with read-only GitHub operations when execution is added.

## Hardcoded For Now

- Agents allowed to call CBA.
- GitHub operations CBA may perform.
- Whether writes exist at all.
- Approval behavior for writes.
- Branch and path restrictions.
- Rate limits and audit detail.

## Next Work

- Persist credentials and GitHub access selections with migrations.
- Replace the development discarding sink with a production write-only credential backend.
- Add a small access check: given `owner/name`, decide whether it is covered by the configured owners or explicit repositories.
- Add narrow GitHub read adapters after the access check exists.
- Add audit events that record operation ids and redacted inputs.

## Non-Goals

- No credential retrieval endpoint.
- No token introspection endpoint.
- No broad GitHub API proxy.
- No arbitrary local `git` command execution.
- No organization administration, secret management, workflow administration, member management, or repository deletion operations.
