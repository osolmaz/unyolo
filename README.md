# CBA

CBA is a Credential Broker for Agents: a policy-enforced Go service that lets agents request approved operations without receiving the underlying credentials.

The central invariant is strict: CBA must not provide any API or internal service method that retrieves original credential material. Secrets enter through a write-only boundary, are handed to a secret sink, and the application keeps only metadata plus an opaque handle.

## Current Seed

- Echo HTTP server
- Bearer-token authentication for management endpoints
- Credential registration and metadata lookup
- Repository configuration with repo-scoped allowlist policies
- Write-only secret sink interface with no read/decrypt method
- Tests that assert secret material is not returned from HTTP or domain responses
- Slophammer-oriented quality gates

## Local Development

```sh
cp .env.example .env
# edit CBA_ADMIN_TOKEN to a generated value with at least 32 bytes
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
  -d '{"tenant_id":"local","name":"github-read","kind":"github_token","secret":"github_pat_example","scopes":["contents:read","pull_requests:write"]}'
```

The response intentionally contains metadata only. There is no credential retrieval endpoint.

Configure a private repository to use that credential:

```sh
curl -X POST http://localhost:8080/v1/repos \
  -H "Authorization: Bearer $CBA_ADMIN_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "tenant_id": "local",
    "owner": "dutifuldev",
    "name": "gitcba",
    "private": true,
    "credential_id": "cred_from_registration_response",
    "policy": {
      "allowed_agents": ["openclaw"],
      "allowed_operations": ["contents_read", "pull_request_diff"],
      "allowed_branches": [],
      "allowed_paths": ["README.md", "internal/**"],
      "require_approval_for_writes": false
    }
  }'
```

Write operations such as `contents_write`, `branch_create`, and `pull_request_create` must set `require_approval_for_writes` to `true` and must include branch and path allowlists.

## Security Model

CBA should treat agents as untrusted callers. Agents may request operations, but they must never receive raw credentials, decrypted credentials, or reversible encrypted credential blobs.

For production, the secret sink should be backed by a service that can perform constrained operations or mint short-lived delegated credentials without returning the stored secret to CBA callers. Local development currently uses a discarding sink, which proves the API shape but cannot execute real downstream actions.
