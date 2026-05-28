# Implementation Plan

## Security Invariants

- Original credentials are never returned by HTTP handlers, service methods, logs, errors, audit records, or API responses.
- CBA stores credential metadata and opaque handles only.
- GitHub access must be configured in a manually edited file before a credential-backed operation can run.
- GitHub access config is only a PAT-like selection of owners and explicit repositories.
- GitHub access config cannot be changed through the API.
- Operation rules stay hardcoded for now.
- CBA never exposes generic `git`, shell, arbitrary GitHub API proxying, token introspection, or token export.

## Current Scope

- Register one or more GitHub credentials through a write-only boundary.
- Configure GitHub access in `github-access.json` with:
  - `owners`: blanket owner/org/user accounts, like selecting all repos under an owner for a PAT.
  - `repositories`: explicit `owner/name` repositories.
- Keep everything else hardcoded in code.
- Agents may create pull requests for configured owners or repositories.
- Agents may push branches or forks only when the target owner is inside the configured GitHub access scope.
- Agents may force-push branches or forks only when the target owner is inside the configured GitHub access scope.

## Hardcoded For Now

- Agents allowed to call CBA.
- GitHub operation implementations.
- Approval behavior.
- Path restrictions.
- Rate limits and audit detail.

## Next Work

- Persist credentials with migrations.
- Replace the development discarding sink with a production write-only credential backend.
- Add a small access check: given `owner/name`, decide whether it is covered by the configured owners or explicit repositories.
- Use the same access check before PR creation, push, and force-push operations.
- Add narrow GitHub adapters after the access checks exist.
- Add audit events that record operation ids and redacted inputs.

## Non-Goals

- No credential retrieval endpoint.
- No token introspection endpoint.
- No broad GitHub API proxy.
- No arbitrary local `git` command execution.
- No organization administration, secret management, workflow administration, member management, or repository deletion operations.
