# GitCBA

GitCBA is a small Git-compatible credential broker for agents. It is intended to run on a private Tailnet and broker a very limited set of GitHub operations without exposing the underlying GitHub credential to clients.

The central invariant is strict: GitCBA must not provide any API or internal service method that retrieves original credential material.

## Current Seed

- Echo HTTP server
- Shared-secret authentication for all broker endpoints
- Git smart HTTP route shape
- GitHub REST-compatible pull request route shape
- Server-side GitHub token forwarding
- GitHub access loaded from a manually edited JSON file
- No credential API
- No GitHub access config API
- Tests for auth, route shape, and access decisions
- Slophammer-oriented quality gates

## Local Development

```sh
cp .env.example .env
cp github-access.example.json github-access.json
# edit CBA_SHARED_SECRET to a generated value with at least 32 bytes
# set CBA_GITHUB_TOKEN to a GitHub token with the repo access GitCBA should broker
# edit github-access.json by hand
source .env
make check
make run
```

Health check:

```sh
curl http://localhost:8080/healthz
```

GitCBA accepts either Bearer auth:

```sh
curl -H "Authorization: Bearer $CBA_SHARED_SECRET" \
  "http://localhost:8080/dutifuldev/gitcba.git/info/refs?service=git-upload-pack"
```

Or Git-friendly Basic auth where the password is `CBA_SHARED_SECRET`:

```sh
git -c http.extraHeader="Authorization: Bearer $CBA_SHARED_SECRET" \
  ls-remote http://localhost:8080/dutifuldev/gitcba.git
```

The broker routes enforce auth and access policy before forwarding to GitHub with the server-side `CBA_GITHUB_TOKEN`.

## GitHub Access

Configure which GitHub owners or repositories are in scope by manually editing `github-access.json`. There is no API endpoint for changing or reading this file.

```json
{
  "owners": ["dutifuldev", "osolmaz"],
  "repositories": [{"owner": "openclaw", "name": "openclaw"}]
}
```

Hardcoded operation rules for now:

- `git-upload-pack` is allowed only for configured owners or repositories.
- `git-receive-pack` is allowed only when the target account is in scope.
- `POST /repos/{owner}/{repo}/pulls` is allowed only for configured owners or repositories.
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

There are intentionally no credential endpoints.

## Security Model

GitCBA should run behind Tailnet-only reachability, but Tailnet access is not treated as authorization. Clients must still submit the configured shared secret on every broker request.

The server-side GitHub credential is configured manually with `CBA_GITHUB_TOKEN` and is used only by narrow Git/GitHub adapters. Clients must never receive raw credentials, decrypted credentials, reversible encrypted credential blobs, token metadata, or credential identifiers.
