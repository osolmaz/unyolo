# GitHub Capability Maintenance

unYOLO generates the GitHub operation catalog from reviewed, immutable
snapshots. A weekly read-only monitor compares those snapshots with current
official GitHub metadata and maintains one issue when structural drift exists.

## Monitor contract

The monitor fetches:

- the latest dated GitHub REST OpenAPI document;
- the full GitHub GraphQL introspection response;
- the latest GitHub App server-to-server permission matrix; and
- the official REST API version list.

Repository files are resolved to a 40-character commit before download. Every
input is downloaded only from `api.github.com` or `raw.githubusercontent.com`,
bounded to 32 MiB, hashed with SHA-256, and recorded with its retrieval time.
The GraphQL response is identified by its digest because it comes from a live
official endpoint.

The report classifies operation, schema, permission, authentication,
deprecation, and API-version changes. Descriptions and summaries are ignored so
documentation-only wording does not create capability drift.

The scheduled workflow may create, update, or close the single drift issue. It
cannot modify repository contents, refresh snapshots, open a pull request, or
merge changes.

Run the same comparison locally with an authenticated GitHub token:

```sh
GITHUB_TOKEN="$(gh auth token)" \
  go run ./brokers/github/cmd/check-github-drift
```

## Reviewed snapshot refresh

Treat a drift issue as a review prompt, not an update instruction.

1. Read the official changelogs and inspect every classified difference.
2. Fetch each accepted source at the exact commit recorded for the review.
3. Replace the REST, permission, GraphQL, and API-version snapshots together.
4. Update `brokers/github/internal/upstream/snapshots/provenance.json` with the
   immutable URL, commit where applicable, API version, SHA-256 digest,
   retrieval time, and license.
5. Update reviewed overrides and policy effects for every new or changed
   capability. Do not infer security policy from HTTP verbs alone.
6. Run `go run ./brokers/github/cmd/generate-github-surfaces` once and review
   every generated catalog, binding, schema, permission profile, MCP surface,
   CLI surface, and documentation change.
7. Run the complete local test and quality suite. Submit the snapshots,
   reviewed policy inputs, generated outputs, conformance fixtures, and
   provenance as one coherent pull request.

CI continues to reject snapshot digest failures and generated drift. No
automatic job is permitted to perform the refresh.
