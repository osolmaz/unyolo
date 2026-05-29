# Implementation Plan

## Security Invariants

- Original credentials are never returned by HTTP handlers, service methods, logs, errors, audit records, or API responses.
- GitCBA exposes no credential listing, registration, lookup, export, decrypt, or introspection API.
- GitHub access must be configured in a manually edited file before a credential-backed operation can run.
- GitHub access config is only a PAT-like selection of owners and explicit repositories.
- GitHub access config cannot be changed or read through the API.
- Clients authenticate with a manually configured shared secret.
- GitCBA uses a manually configured server-side GitHub token for outbound GitHub requests.
- Tailnet reachability is a network boundary only; every broker endpoint still requires auth.
- GitCBA binds to localhost by default and should only be exposed through a Tailnet or local-only proxy.
- `git-receive-pack` requests are capped before buffering.
- Outbound GitHub requests use explicit timeouts.
- Audit logs must not contain tokens, cookies, request bodies, pack contents, or raw credentials.
- GitCBA never exposes generic shell execution, arbitrary GitHub API proxying, token introspection, or token export.

## Current Scope

- Run as a Tailnet-oriented HTTP service.
- Bind to `CBA_BIND_ADDR`, defaulting to `127.0.0.1`.
- Accept `Authorization: Bearer <CBA_SHARED_SECRET>`.
- Accept Git-friendly Basic auth where the password is `CBA_SHARED_SECRET`.
- Load `CBA_GITHUB_TOKEN` at startup and use it only for outbound GitHub requests.
- Cap `git-receive-pack` request bodies with `CBA_MAX_RECEIVE_PACK_BYTES`.
- Use `CBA_GITHUB_HTTP_TIMEOUT` for outbound GitHub requests.
- Emit structured audit logs for broker operations.
- Configure GitHub access in `github-access.json` with:
  - `owners`: blanket owner/org/user accounts, like selecting all repos under an owner for a PAT.
  - `repositories`: explicit `owner/name` repositories.
- Keep everything else hardcoded in code.
- Mimic Git smart HTTP route shape for fetch and push.
- Mimic GitHub REST route shape for pull request creation.
- `git-upload-pack` is allowed for configured owners or repositories.
- `git-receive-pack` is allowed only when the target account is in scope.
- `git-receive-pack` rejects updates to `refs/heads/main` and to the repository's default branch.
- Pull request creation is allowed for configured owners or repositories.
- A target account is in scope when it is listed in `owners`, or when it owns the explicitly configured repository being operated on.

## Broker Routes

```text
GET  /healthz

GET  /{owner}/{repo}.git/info/refs?service=git-upload-pack
POST /{owner}/{repo}.git/git-upload-pack

GET  /{owner}/{repo}.git/info/refs?service=git-receive-pack
POST /{owner}/{repo}.git/git-receive-pack

POST /repos/{owner}/{repo}/pulls
```

## Hardcoded For Now

- One shared client secret.
- Approval behavior.
- Path restrictions.
- Rate limits and audit detail.

## Next Work

- Detect and audit non-fast-forward updates inside `git-receive-pack`.
- Add richer audit event identifiers and correlation ids.

## Non-Goals

- No credential API.
- No token introspection endpoint.
- No broad GitHub API proxy.
- No arbitrary local `git` command execution.
- No organization administration, secret management, workflow administration, member management, or repository deletion operations.
