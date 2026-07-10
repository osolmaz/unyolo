# Implementation Plan

This document tracks the implemented broker shape. The longer-term GitHub App
and service-account target is specified in
[PRODUCTION_ARCHITECTURE.md](PRODUCTION_ARCHITECTURE.md). The shared
broker-family install and setup cutover is specified in
[BROKERKIT_UNIFICATION.md](BROKERKIT_UNIFICATION.md).

Cutover direction: gh-broker now lives at `github.com/osolmaz/gh-broker` and
should use `github.com/osolmaz/brokerkit` for shared auth, policy, grants,
approval workflow, audit helpers, notification interfaces, Telegram approval
transport, shared storage/config helpers, and generic Git parsing helpers.
There is no backward-compatibility requirement for old import paths, old route
aliases, old policy formats, or local duplicate control-plane runtimes.

## Implemented Security Invariants

- Original GitHub credentials are never returned by HTTP handlers, service methods, logs, errors, audit records, or API responses.
- gh-broker exposes no credential listing, registration, lookup, export, decrypt, or introspection API.
- Clients authenticate with a manually configured shared secret.
- The authenticated request is assigned one configured client id, currently `GH_BROKER_CLIENT_ID`.
- `scope.json` is the authorization source of truth.
- Policy decisions are centralized in `internal/policy` until the brokerkit
  cutover, then in `brokerkit/policy`.
- Handlers may reject malformed requests, but valid broker operations are authorized through the policy engine.
- gh-broker uses a manually configured server-side GitHub token for outbound GitHub requests as the development fallback credential path.
- Tailnet reachability is a network boundary only; every broker endpoint still requires auth.
- gh-broker binds to localhost by default and should only be exposed through a Tailnet or local-only proxy.
- `git-receive-pack` requests are capped before buffering.
- Outbound GitHub requests use explicit timeouts.
- Audit logs must not contain tokens, cookies, request bodies, PR bodies, pack contents, diffs, raw upstream bodies, or raw credentials.
- gh-broker never exposes generic shell execution, arbitrary GitHub API proxying, token introspection, token export, organization administration, workflow administration, member management, or repository deletion operations.

## Implemented Scope

- Run as a Tailnet-oriented HTTP service.
- Bind to `GH_BROKER_BIND_ADDR`, defaulting to `127.0.0.1`.
- Accept `Authorization: Bearer <GH_BROKER_SHARED_SECRET>`.
- Accept Git-friendly Basic auth where the password is `GH_BROKER_SHARED_SECRET`.
- Load `GH_BROKER_SECRETS_FILE` for the configured client id so service installs
  do not need to place broker client secrets in the env file.
- Load `GH_BROKER_GITHUB_TOKEN` or `GH_BROKER_GITHUB_TOKEN_FILE` at startup and use it only for outbound GitHub requests.
- Load rule-based `GH_BROKER_SCOPE_FILE`, defaulting to `scope.json`.
- Cap `git-receive-pack` request bodies with `GH_BROKER_MAX_RECEIVE_PACK_BYTES`.
- Use `GH_BROKER_GITHUB_HTTP_TIMEOUT` for outbound GitHub requests.
- Emit structured audit logs for broker operations.
- Mimic Git smart HTTP route shape for fetch and push.
- Expose narrow `/api/repos`, `/api/repos/{owner}/{repo}/contents/{path}`, and `/api/repos/{owner}/{repo}/pulls` routes.
- List repositories through the GitHub user repositories endpoint for PAT-like tokens and the installation repositories endpoint for GitHub App installation-token-shaped credentials.
- Filter repository list responses through `repo.metadata.read` policy decisions.
- Authorize content reads through `contents.read` policy decisions, including the forwarded `ref` query when present.
- Validate pull request creation payloads and authorize through `pr.create` with head/base refs. Fork-qualified PR heads such as `owner:branch` are not forwarded; broker-managed branches must live in the target repository.
- Drop upstream credential metadata and pagination headers from filtered repository list responses.
- Parse `git-receive-pack` commands before forwarding.
- Authorize `git-receive-pack` discovery through `git.push.advertise`, not `git.fetch`.
- Classify branch creates, existing branch updates, ref deletes, tag updates, and unsupported ref updates before forwarding.
- Authorize existing branch updates as `git.push.force` unless the broker can prove fast-forward before forwarding. The seed implementation does not call GitHub compare before upload because new commits often exist only inside the pack at that point, so it must not claim fast-forward.
- Deny ref deletes and unsupported ref updates before forwarding.
- Deny default-branch pushes by absence of a matching allow rule, while allowing explicit direct-main rules for selected repositories.
- Keep GitHub branch protections or rulesets as the upstream enforcement layer that rejects actual non-fast-forward updates after GitHub receives the pack.

## Policy Model

A request is classified as:

```text
client + operation + target + attrs -> allow | request | deny | no_match
```

Decision precedence is:

```text
deny > active generated grant > allow > request > no_match
```

A rule matches only when the same rule matches the client, operation, target, and operation-relevant attributes. The broker does not combine an operation from one rule with a target from another rule. Attrs are operation-specific; a rule with attrs must only contain operations that support all of those attrs.

Supported initial operations:

```text
git.fetch
git.push.advertise
git.push.branch_create
git.push.fast_forward
git.push.force
git.ref.delete
git.tag.update
pr.create
pr.update
pr.merge
checks.read
repo.metadata.read
contents.read
installation.repos.list
webhook.github.receive
```

The default example profile in `scope.example.json` allows Bob to list repos, read contents, fetch repositories, push feature branches, update existing feature branches under the broker's conservative `git.push.force` classification, and open pull requests into `main`. It denies ref deletion everywhere and denies protected `gh-broker` main-branch updates before forwarding, while still showing a repository-specific direct-main branch-update exception that is not shadowed by the deny rule. GitHub rulesets or branch protections remain the upstream layer that rejects actual non-fast-forward pushes.

## Broker Routes

```text
GET  /healthz

GET  /api/repos
GET  /api/repos/{owner}/{repo}/contents/{path}
POST /api/repos/{owner}/{repo}/pulls

GET  /{owner}/{repo}.git/info/refs?service=git-upload-pack
POST /{owner}/{repo}.git/git-upload-pack

GET  /{owner}/{repo}.git/info/refs?service=git-receive-pack
POST /{owner}/{repo}.git/git-receive-pack
```

## Conditional Future Work

- Invalidate an installation cache from verified webhooks if an installation
  cache is introduced. There is no cache today.

## Brokerkit Cutover Tests

The brokerkit cutover is complete only when tests prove:

- old local auth, policy, grants, approval, Telegram, audit, and storage
  runtimes are gone
- all authorization decisions use brokerkit
- GitHub request classification stays local and fails closed
- a protected or dangerous Git operation grant can be approved through a fake
  brokerkit notifier
- generated grants are evaluated by the brokerkit policy decision path, not a
  second grant-specific allow path
- Telegram approval is covered with a fake Bot API server or fake notifier in
  automated tests; CI must not require a live bot token or send real messages
- end-to-end broker tests use fake GitHub upstreams, fake installation-token
  minting, and fake notifiers by default; live GitHub checks are explicit
  manual or milestone probes
- audit never contains GitHub credentials, request bodies, pack contents,
  approval tokens, or Telegram bot tokens

## Implementation Readiness

The brokerkit cutover is ready to implement when the slice can satisfy this
contract:

- gh-broker imports brokerkit for shared auth, policy, grants, approval state,
  notification interfaces, Telegram transport, audit helpers, storage/config
  helpers, and provider-neutral Git parsing
- gh-broker keeps only GitHub operation registration, Git/API request
  classification, GitHub App or PAT credential use, upstream forwarding,
  ruleset/branch-protection checks, audit extension fields, and approval
  summary text
- the replaced local runtime is deleted in the same PR as the brokerkit import
- GitHub-native behavior remains local: brokerkit must not learn GitHub App,
  installation token, PR, webhook, branch protection, or ruleset semantics

## Current Cutover Status

gh-broker now imports brokerkit for shared authentication, broker policy
evaluation, generated grants, approval state, notification interfaces, Telegram
approval transport, local durable grant storage, provider-neutral Git
receive-pack parsing, client and systemd setup, audit events, and common doctor
checks. The remaining `internal/security`, `internal/policy`, and
`internal/httpapi/receive_pack.go` code is GitHub-specific adapter code: Echo
middleware wiring, GitHub operation registration, target and attr normalization,
request classification, and audit-facing rule-id mapping.

Implemented in the current brokerkit cutover slice:

- `install.sh`
- release tarballs and checksums through `scripts/release.sh`
- `gh-broker setup client`
- `gh-broker setup systemd --dev-token-fallback`
- shared brokerkit privileged systemd account, directory, file, unit, and
  activation runtime with GitHub-owned credential and unit payloads
- GitHub App private-key authentication and installation token minting
- repo-scoped installation resolution through GitHub's repository installation
  endpoint
- App installation repository listing with policy filtering
- verified `POST /webhooks/github` with `X-Hub-Signature-256`,
  `X-GitHub-Event`, and `X-GitHub-Delivery` checks
- webhook audit metadata for event, delivery id, action, installation id, and
  repository name
- broker and webhook audit records use the brokerkit audit schema with
  GitHub-specific extension fields
- server-side named client secrets through `GH_BROKER_SECRETS_FILE`
- `POST /api/grants`
- `GET /api/grants`
- `GET /api/grants/{id}`
- requestable operations create brokerkit pending grants
- active grants are evaluated through brokerkit policy overlays
- grant use is reserved before upstream forwarding and committed after the
  proxy accepts the request
- approval notification claims, editable message references, and delivered
  status revisions are durable across process restarts
- unresolved notification claims remain blocked until the durable lease expires;
  reclaim rotates the one-time decision token before another send
- verified callbacks atomically commit the decision and editable Telegram
  message reference, and durable write failures retain the Telegram offset for
  retry
- every API grant request requires a `client_request_id`
- retained grants are quarantined and report no usable remaining capacity
- ambiguous upstream or grant-commit results retain the reservation or close
  the grant instead of making the approved use available again
- failures before the target GitHub request is dispatched release the reserved
  use because the requested operation cannot have reached GitHub
- deny rules still override active grants
- Telegram approval uses the shared brokerkit adapter and is tested with a fake
  Bot API server
- repo-scoped GitHub App installation tokens are minted only after broker policy
  allows the request and are not written to disk, returned to clients, or logged
- compatibility route aliases such as `POST /repos/{owner}/{repo}/pulls` are
  removed; JSON APIs live under `/api/*` and Git keeps Git smart-HTTP routes
- `gh-broker doctor github --repo owner/name` verifies local account and secret
  isolation, App JWT signing and installation-token minting, minimal App
  permissions, repository visibility, and default-branch rulesets or classic
  branch protection

The brokerkit control-plane and Linux host-runtime cutover described by this
plan is complete. GitHub-specific classifiers, credential use, upstream calls,
protection interpretation, and audit extensions intentionally remain local.

## Non-Goals

- No credential API.
- No token introspection endpoint.
- No broad GitHub API proxy.
- No arbitrary local `git` command execution.
- No organization administration, secret management, workflow administration, member management, or repository deletion operations.
