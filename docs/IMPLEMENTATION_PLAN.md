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
- Agents may push branches or forks only when the target account is in scope.
- Agents may force-push using the same target-account rule as normal pushes.
- A target account is in scope when it is listed in `owners`, or when it owns the explicitly configured repository being operated on.

## Hardcoded For Now

- Agents allowed to call CBA.
- GitHub operation implementations.
- Approval behavior.
- Path restrictions.
- Rate limits and audit detail.

## Next Work

- Persist credentials with migrations.
- Replace the development discarding sink with a production write-only credential backend.
- Add narrow GitHub adapters after the access checks exist.
- Use the access decision helper in the GitHub adapters.
- Add audit events that record operation ids and redacted inputs.

## Non-Goals

- No credential retrieval endpoint.
- No token introspection endpoint.
- No broad GitHub API proxy.
- No arbitrary local `git` command execution.
- No organization administration, secret management, workflow administration, member management, or repository deletion operations.
