# CBA

CBA is a Credential Broker for Agents: a small Go service that lets agents use approved GitHub access without receiving the underlying credentials.

The central invariant is strict: CBA must not provide any API or internal service method that retrieves original credential material. Secrets enter through a write-only boundary, are handed to a secret sink, and the application keeps only metadata plus an opaque handle.

## Current Seed

- Echo HTTP server
- Bearer-token authentication for management endpoints
- Credential registration and metadata lookup
- GitHub access loaded from a manually edited JSON file
- Write-only secret sink interface with no read/decrypt method
- Tests that assert secret material is not returned from HTTP or domain responses
- Slophammer-oriented quality gates

## Local Development

```sh
cp .env.example .env
cp github-access.example.json github-access.json
# edit CBA_ADMIN_TOKEN to a generated value with at least 32 bytes
# edit github-access.json by hand
source .env
make check
make run
```

Health check:

```sh
curl http://localhost:8080/healthz
```

Register a GitHub token:

```sh
curl -X POST http://localhost:8080/v1/credentials \
  -H "Authorization: Bearer $CBA_ADMIN_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"name":"github-read","kind":"github_token","secret":"github_pat_example","scopes":["contents:read"]}'
```

The response intentionally contains metadata only. There is no credential retrieval endpoint.

Configure which GitHub owners or repositories are in scope by manually editing `github-access.json`. There is no API endpoint for changing this file.

```json
{
  "owners": ["dutifuldev", "osolmaz"],
  "repositories": [{"owner": "openclaw", "name": "openclaw"}]
}
```

Operation rules are hardcoded for now.

## Security Model

CBA should treat agents as untrusted callers. Agents may request operations, but they must never receive raw credentials, decrypted credentials, or reversible encrypted credential blobs.

For production, the secret sink should be backed by a service that can perform constrained operations or mint short-lived delegated credentials without returning the stored secret to CBA callers. Local development currently uses a discarding sink, which proves the API shape but cannot execute real downstream actions.
