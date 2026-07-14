# Import Provenance

- Source: `https://github.com/osolmaz/gh-broker` (private and archived)
- Frozen source commit: `7b7f5f11c9c3caf6471b5bc2d772fbea2c1c7532`
- Historical source tag: `v0.1.0`
- No-squash subtree merge: `6f75d6c83d8d06f93a5928b70b2b4738d9dde7c4`
- Destination: `brokers/github`

Verified during import:

```sh
git merge-base --is-ancestor 7b7f5f11c9c3caf6471b5bc2d772fbea2c1c7532 HEAD
git diff --exit-code 7b7f5f11c9c3caf6471b5bc2d772fbea2c1c7532^{tree} HEAD:brokers/github
go test -race ./...
```

## Official GitHub metadata

The stage 2–3 operation inventory is generated entirely from checked-in
official GitHub snapshots under `internal/upstream/snapshots`. It pins:

- stable REST OpenAPI 3.0 at `github/rest-api-description` commit
  `3b43edf675308c515b5e92a3eb89db17f6e6d806`, API `2026-03-10`;
- the full GitHub.com GraphQL introspection retrieved on 2026-07-14;
- GitHub App endpoint-permission metadata at `github/docs` commit
  `0e9fa09707cfbd5a88e508a5fc1b35c05bb53297`; and
- the official REST API version list at `github/docs` commit
  `573cdfa82f9cf4e4d56285b0472a6f8212a19d93`; and
- reconciliation-relevant webhook metadata from the same docs commit.

`internal/upstream/snapshots/provenance.json` records the source URL, commit or
schema fingerprint, retrieval time, SHA-256 digest, and license notice for each
artifact. `scripts/check-github-generated.sh` verifies both snapshot integrity
and generated-artifact drift without network access.

The scheduled capability monitor is intentionally separate from generation. It
resolves current official metadata to immutable source commits, records source
digests and retrieval time, classifies structural drift, and maintains one
actionable issue. It cannot change snapshots or generated artifacts. See
[`docs/GITHUB_CAPABILITY_MAINTENANCE.md`](../../docs/GITHUB_CAPABILITY_MAINTENANCE.md).
