# unYOLO rename implementation plan

## Decision

The visible product name is **unYOLO**. Source identifiers and machine-readable values use **unyolo**. This includes package names and commands as well as paths and URLs. Environment variables use **UNYOLO**.

This is a coordinated fresh-state rename. The repository will not retain aliases, fallback paths, old protocol values, dual readers, migration code, or wrapper commands. Existing installations must be removed before installing the renamed release.

This plan assumes `unyolo.io` is the canonical protocol namespace. Control of that domain and the required package names must be confirmed before implementation starts.

## Naming contract

| Surface | Name |
| --- | --- |
| Product and UI text | `unYOLO` |
| Repository | `osolmaz/unyolo` |
| Go module | `github.com/osolmaz/unyolo` |
| Root workspace package | `unyolo` |
| Documentation site package | `unyolo-web` |
| Main command and release prefix | `unyolo` |
| Telegram command and release prefix | `unyolo-telegram` |
| Git credential helper | `git-credential-unyolo` |
| OpenClaw npm package | `openclaw-unyolo` |
| OpenClaw plugin ID and command | `unyolo` and `/unyolo` |
| OpenClaw HTTP roots | `/plugins/unyolo` and `/trusted-host/api/unyolo` |
| Setup companion | `openclaw-unyolo-setup` |
| Environment prefix | `UNYOLO_*` |
| Wire API namespace | `unyolo.io/.../v1` |
| Discovery paths | `/.well-known/unyolo-agent` and `/.well-known/unyolo-operator` |
| Metrics and labels | `unyolo_*` and `unyolo-*` |
| Linux release root | `/opt/unyolo` |
| Linux host state | `/var/lib/unyolo-host` |
| Linux runtime sockets | `/run/unyolo/...` |
| macOS application root | `/Library/Application Support/unyolo` |
| Launchd namespace | `io.unyolo.*` |
| Local schema host | `unyolo.local` |

The provider process names `gh-broker`, `hf-broker`, `sudo-broker`, and `sudo-broker-exec` stay unchanged. Their provider-specific environment prefixes also stay unchanged. The product vocabulary still includes brokers and operators. It also includes agents and credential brokers.

All owned format versions remain at version 1. The namespace changes in place from the current value to `unyolo.io`; the rename does not introduce v2 schemas.

## Preconditions

Before changing source files:

- Confirm control of `unyolo.io` or choose another canonical domain. The protocol namespace and launchd namespace must derive from one controlled domain.
- Confirm that `osolmaz/unyolo` and `openclaw-unyolo` can be claimed.
- Record the repository settings, rulesets, Actions secrets, variables, environments, Pages configuration, npm trusted-publishing configuration, and ClawHub package metadata that must still work after the repository rename.
- Start from a clean branch based on the latest `main`. Preserve any unrelated local work before bulk renames.
- Capture the current generated-artifact checks and release dry-run output as a baseline.

A failed namespace claim blocks the implementation. Choose the replacement namespace before editing code. Temporary names are forbidden.

## Source and module rename

Rename `go.mod` to `github.com/osolmaz/unyolo` and update every first-party import. Rename command directories and files whose paths contain the former project name. This includes the main CLI, release helper, coverage helper, Telegram command, Git credential helper, OpenClaw setup helper, workflow filenames, and documentation routes.

Local Go aliases and identifiers derived from the former abbreviation should become descriptive `unyolo...` names or ordinary package names. Generic provider names and established domain terms should stay as they are. Run `go fmt ./...`, `go test ./...`, and the architecture check after this slice so module-boundary failures are fixed before protocol work begins.

## Protocol namespace

Change every owned API version, schema identifier, discovery path, authentication realm, metrics prefix, local schema URL, cryptographic domain-separation string, and generated compatibility manifest to the new namespace.

`protocol/` remains the canonical source. Update its OpenAPI files and JSON Schemas first, then regenerate Go and TypeScript clients with the checked-in generator. Generated files must not be edited independently. Update contract digests and fixtures only through the repository's normal generation flow.

Tests must prove that:

- Agent and Operator discovery use only the new well-known paths.
- Every owned API value uses `unyolo.io/.../v1`.
- Old API values and discovery paths are rejected.
- Cryptographic AAD and persisted format identifiers use the new namespace.
- Generated artifacts match their canonical specifications.

## Runtime layout

Replace installation roots, state directories, socket paths, service names, launchd labels, Unix account names, temporary-file prefixes, Git configuration sections, HTTP authentication realms, and deployment ownership markers.

Linux uses `/opt/unyolo`, `/var/lib/unyolo-host`, and `/run/unyolo`. macOS uses `/Library/Application Support/unyolo` and `io.unyolo.*` launchd labels. Product-owned accounts and groups use `unyolo` where their names currently contain the project name. Provider-owned identities such as `gh-broker` remain unchanged.

The installer must reject mixed layouts. It must not discover, import, remove, or rewrite an earlier installation. Test fixtures should model a clean host and verify that only the new paths are touched. Operator documentation must tell existing users to uninstall the earlier release and perform a fresh installation.

## Release tooling

Rename the main binary and its companion binaries. Update help text, executable discovery, archive contents, checksums, bootstrap scripts, release tags, release assets, provenance verification, workflow filters, and architecture assertions.

The new release families are:

- `unyolo/v0.5.0`, following `v0.4.2` of the main command
- `unyolo-telegram/v0.4.0`, following `v0.3.0`
- `openclaw-unyolo/v0.5.0`, following `v0.4.1`
- `gh-broker/v0.5.0`, following `v0.4.0`
- `hf-broker/v0.7.0`, following `v0.6.2`
- `sudo-broker/v0.4.0`, following `v0.3.1`

These are pre-1.0 minor releases because command names, package names, paths, environment variables, and wire values change incompatibly. Published versions remain immutable.

The release workflow should continue to publish from GitHub Releases and validate each release tag against package metadata. Dry runs must inspect archive member names and exercise the renamed bootstrap scripts before any release is published.

## OpenClaw plugin

Change the plugin ID to `unyolo`, the package to `openclaw-unyolo`, the chat command to `/unyolo`, and all direct and delegated web routes to their new roots. Rename configuration keys, generated Operator V1 clients, UI labels, browser fixtures, package tests, and deployment artifacts in the same slice.

The plugin must use only the new identifiers. It must not register the former command or serve the former routes. Package tests should install the packed tarball into a clean OpenClaw environment and verify command registration, direct UI access, delegated web access, approval decisions, and event resumption.

After the new package is published and verified, mark the earlier npm package as deprecated with a short pointer to `openclaw-unyolo`. Do not publish a runtime forwarding package or compatibility release.

## Documentation and visual identity

Replace product prose with the exact `unYOLO` casing. Code samples, paths, environment variables, repository links, badges, installer commands, diagrams, screenshots, alt text, metadata, SEO values, and navigation routes must use the naming contract.

Update the wordmark and any raster or SVG assets that contain text. Rename the “why” documentation route to `get-started/why-unyolo` and fix internal links. Historical implementation plans should be updated when they describe current contracts; obsolete plans that no longer help maintainers should be removed.

A documentation build must run after route renames so broken links and stale generated pages are caught before review.

## External repository change

Prepare and verify the full source rename before changing the GitHub repository name. Once the rename commit is ready:

1. Merge the rename on the default branch.
2. Rename the GitHub repository to `osolmaz/unyolo` with `gh` and update the local `origin` URL.
3. Recheck rulesets, Actions permissions, environments, secrets, variables, Pages, webhooks, GitHub App callbacks, and trusted-publishing subjects.
4. Run CI on `osolmaz/unyolo` and verify that badges, source links, raw installer URLs, provenance subjects, and release workflows resolve through the new repository directly.
5. Publish the new release families only after CI passes in the renamed repository.
6. Verify the new npm and ClawHub package records from a clean client.

GitHub's automatic repository redirect is outside the application compatibility contract. Source and documentation must link directly to the new repository. Installers and package metadata must do the same.

## Verification

Run the repository checks with Go 1.26.5:

```sh
go fmt ./...
go mod tidy
git diff --exit-code -- go.mod go.sum
go mod verify
./scripts/check-architecture.sh
./scripts/check-github-generated.sh
./scripts/check-sql.sh
go test ./protocol
go vet ./...
go test -race -timeout 20m ./...
./scripts/check-go-coverage.sh
golangci-lint run
govulncheck ./...
gitleaks git --no-banner --redact .
slophammer-go dry .
(cd brokers/huggingface && slophammer-go dry .)
(cd brokers/github && slophammer-go dry .)
(cd brokers/sudo && slophammer-go dry .)
slophammer-go crap . --max-score 8
(cd brokers/huggingface && slophammer-go crap . --max-score 8)
(cd brokers/sudo && slophammer-go crap . --max-score 8)
slophammer-go check .
```

Run the JavaScript and browser checks:

```sh
pnpm install --frozen-lockfile
pnpm check
pnpm test
pnpm build
pnpm --filter openclaw-unyolo exec playwright install --with-deps
pnpm --filter openclaw-unyolo test:browser
npm pack --dry-run --prefix plugins/openclaw
pnpm --filter openclaw-unyolo test:package
```

Run the host deployment test and installer tests in their documented clean environments. Reproduce a fresh Linux installation through the published installer, connect one agent and one operator, submit an approval-gated operation, approve it through OpenClaw, and observe the terminal result. Repeat the supported macOS installation workflow or report it as unverified with the exact blocker.

## Stale-name audit

The final source tree should contain no stale project identifiers in active code or documentation. Audit tracked text, tracked paths, generated files, archive contents, built JavaScript, package tarballs, and rendered documentation. Review every remaining match because a case-sensitive replacement is insufficient.

At minimum, the audit must cover:

```sh
git grep -In -i '<former-project-name>'
git ls-files | grep -i '<former-project-name>'
find dist plugins/openclaw/dist web/dist -type f -print0 | xargs -0 grep -In -i '<former-project-name>'
```

The first two commands must return no matches when the implementation plan itself is excluded. Generated output and packaged artifacts must return no matches. Release history on GitHub and registry records for already-published packages are expected to retain their immutable names.

## Completion criteria

The rename is complete when all of the following are true:

- Product surfaces display `unYOLO`, while machine-readable identifiers follow the naming contract.
- The module builds entirely under `github.com/osolmaz/unyolo`.
- Wire artifacts remain version 1 and use only the new namespace.
- Fresh Linux and macOS layouts contain no mixed project paths.
- The OpenClaw plugin installs and operates under `openclaw-unyolo` and `/unyolo`.
- CI passes in `osolmaz/unyolo`.
- Release archives, bootstrap verification, npm publication, ClawHub publication, and documentation links work from clean clients.
- No runtime compatibility code or stale active identifier remains.

If namespace ownership, registry publication, repository settings, or a real target environment blocks verification, stop before publishing. Record the failed command, gathered evidence, attempted fixes, and the external action needed to continue.
