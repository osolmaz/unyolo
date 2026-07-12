# Production Architecture

`gh-broker` should become the GitHub counterpart to `hf-broker`: a
policy-gated credential broker for coding agents. It should not become a
generic GitHub proxy, a GitHub app platform, or a token management service.

The target architecture is intentionally the same as `hf-broker`, adapted for
GitHub's safer PR workflow, and should share its generic control-plane code
through `github.com/osolmaz/brokerkit`:

```text
authenticate client
classify request
evaluate one policy engine
execute or refuse
audit the decision
```

There should be no production phase where authorization is split between
handler-specific rules, owner allowlists, and separate API checks. The current
owner/repository access file is seed code only; the production cutover target
is a rule-based `scope.json`.

There is no backward-compatibility requirement for old import paths, old route
aliases, old owner/repository allowlists, or local policy/grant engines. Cut
over directly to the long-term shape and delete the old path in the same
change.

## brokerkit Cutover

gh-broker should use brokerkit for shared broker control-plane behavior:

- `brokerkit/auth` for named-client shared-secret authentication
- `brokerkit/policy` for generic rule parsing, matching, grant overlays, and
  decisions
- `brokerkit/grants` for generated temporary grants
- brokerkit approval workflow for request, decision-token, callback, status,
  revoke, and fail-closed approval state handling
- `brokerkit/audit` for secret-safe audit metadata helpers
- `brokerkit/notify` for approval notification interfaces and reusable
  Telegram approval transport
- brokerkit storage/config helpers for atomic local stores, locks, strict
  decoding, test clocks, and deterministic ids
- brokerkit generic Git helpers for pkt-line parsing, receive-pack command
  parsing, ref update classification, safe Git request limits, and Git body
  redaction when the API is shared cleanly with `hf-broker`

gh-broker keeps GitHub-specific behavior local:

- GitHub App JWT and installation token minting
- GitHub REST route classification
- Git smart-HTTP request classification
- pull request payload validation
- repository listing through GitHub visibility plus policy filtering
- contents proxying
- webhook verification
- GitHub ruleset and branch-protection checks
- GitHub-specific approval message wording

When a brokerkit package lands, remove the corresponding local duplicate. Do
not keep compatibility wrappers except thin provider adapters.

## Account Model

Recommended same-host deployment:

```text
onur      = admin account
bob       = agent account, no sudo and no docker
gh-broker = service account that can read GitHub App credentials
```

The agent should never receive the real GitHub credential. The agent receives
only a broker client secret. The broker service uses GitHub credentials only
for outbound GitHub requests that policy allows.

Production files:

```text
/usr/local/bin/gh-broker
/etc/gh-broker/github-app-id
/etc/gh-broker/github-app-private-key.pem
/etc/gh-broker/webhook-secret
/etc/gh-broker/scope.json
/etc/gh-broker/secrets
/etc/systemd/system/gh-broker.service
```

The GitHub App private key and webhook secret should be owned by
`gh-broker:gh-broker` with mode `0600`.

A long-lived token file may exist as a local development fallback:

```text
/etc/gh-broker/github-token
```

Production should prefer GitHub App installation tokens over a PAT.


## GitHub-Native Credential Model

The production credential model should be GitHub App first.

A PAT is acceptable for local development and smoke tests, but the long-term
production path should be:

```text
GitHub App private key -> short-lived installation token -> one allowed request
```

Runtime flow:

```text
broker authenticates client
broker classifies request
policy allows request
broker resolves the GitHub App installation for the target repo
broker mints a short-lived installation token
broker forwards the Git or GitHub API request
broker discards the token from memory after use
```

The installation token must never be written to disk, returned to the client,
logged, included in audit records, or exposed through debug output.

Configuration:

```text
GH_BROKER_GITHUB_APP_ID_FILE=/etc/gh-broker/github-app-id
GH_BROKER_GITHUB_APP_PRIVATE_KEY_FILE=/etc/gh-broker/github-app-private-key.pem
GH_BROKER_GITHUB_WEBHOOK_SECRET_FILE=/etc/gh-broker/webhook-secret
```

Development fallback:

```text
GH_BROKER_GITHUB_TOKEN_FILE=/etc/gh-broker/github-token
```

The fallback token path should be documented as non-preferred for production.
If production uses a PAT anyway, it should be fine-grained, repo-scoped, and
rotated like any other high-risk secret.

GitHub App permissions should be minimal. Start with only the permissions
needed for the first supported operations:

```text
Contents: read/write, only if Git push/fetch is brokered
Pull requests: read/write, only if PR creation/update is brokered
Checks: read, only if check status is brokered
Metadata: read
```

Do not request organization administration, secrets, workflows, members,
administration, or repository deletion permissions for the initial production
app.

## GitHub As Upstream Backstop

Broker policy is the first gate. GitHub-native protections should be the
second gate.

Production repositories should still use GitHub branch protections or rulesets:

```text
require pull requests before merging
require status checks
restrict pushes to default branches
prevent force pushes
prevent branch deletion
avoid GitHub App bypass on protected default branches
```

`gh-broker` should be correct on its own, but it should not rely on being the
only enforcement layer. If broker policy has a bug, GitHub rulesets should
still block the most dangerous default-branch and destructive operations.

## One Decision Engine

Every protected request must be classified before enforcement:

```text
client + operation + target + attrs -> allow | request | deny | no_match
```

Handlers should not contain authorization rules directly. Handlers classify
Git and API requests into a broker request object, then ask policy for a
decision. This keeps Git handling, pull request APIs, grants, and future
read-only APIs on the same authorization path.

This is the central production invariant after brokerkit cutover:

```text
no policy decision outside brokerkit/policy
```

HTTP handlers may reject malformed transport-level requests before
classification, but they must not independently decide whether a valid broker
operation is authorized.

Initial operation names:

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

The first production policy profile should be PR-workflow oriented:

```text
agents may fetch
agents may push feature branches
agents may update existing feature branches under the conservative git.push.force classification
agents may open pull requests
agents may not push default branches
agents may not force-push protected/default branches
agents may not delete refs
agents may not change repo settings, members, secrets, or workflows
```

This differs from `hf-broker`: Hugging Face direct append-only pushes are the
main workflow there; GitHub should default to "push a branch and open a PR."

## Rule-Based Scope

The production model uses a rule-based `scope.json` from the first real
policy cutover. Do not add another production owner/repository allowlist
format before rules; that only creates a second migration.

The current `github-access.json` format is allowed only as temporary seed
code. The cutover should replace it rather than keep both runtimes alive.
No converter or compatibility loader is required.

An explicit `{"rules":[]}` is a valid deny-all policy for staged setup and
emergency shutdown. Missing or null `rules` is invalid and prevents startup, so
an incomplete file cannot silently become a deny-all configuration.

Example:

```json
{
  "rules": [
    {
      "id": "deny-gh-broker-main-force",
      "effect": "deny",
      "clients": ["*"],
      "operations": ["git.push.force"],
      "targets": [
        {"kind": "repo", "owner": "osolmaz", "name": "gh-broker"}
      ],
      "attrs": {
        "refs": ["refs/heads/main"]
      }
    },
    {
      "id": "deny-ref-delete",
      "effect": "deny",
      "clients": ["*"],
      "operations": ["git.ref.delete"],
      "targets": [
        {"kind": "repo", "owner": "*", "name": "*"}
      ]
    },
    {
      "id": "bob-repo-read-osolmaz",
      "effect": "allow",
      "clients": ["bob"],
      "operations": [
        "git.fetch",
        "repo.metadata.read"
      ],
      "targets": [
        {"kind": "repo", "owner": "osolmaz", "name": "*"}
      ]
    },
    {
      "id": "bob-contents-read-osolmaz",
      "effect": "allow",
      "clients": ["bob"],
      "operations": ["contents.read"],
      "targets": [
        {"kind": "repo", "owner": "osolmaz", "name": "*"}
      ],
      "attrs": {
        "paths": ["*", "docs/*", "."]
      }
    },
    {
      "id": "bob-push-advertise",
      "effect": "allow",
      "clients": ["bob"],
      "operations": ["git.push.advertise"],
      "targets": [
        {"kind": "repo", "owner": "osolmaz", "name": "*"}
      ]
    },
    {
      "id": "bob-push-branches",
      "effect": "allow",
      "clients": ["bob"],
      "operations": [
        "git.push.branch_create",
        "git.push.force"
      ],
      "targets": [
        {"kind": "repo", "owner": "osolmaz", "name": "*"}
      ],
      "attrs": {
        "refs": ["refs/heads/bob/*", "refs/heads/agent/*"]
      }
    },
    {
      "id": "bob-pr-create-main",
      "effect": "allow",
      "clients": ["bob"],
      "operations": [
        "pr.create"
      ],
      "targets": [
        {"kind": "repo", "owner": "osolmaz", "name": "*"}
      ],
      "attrs": {
        "refs": ["refs/heads/bob/*", "refs/heads/agent/*"],
        "base_refs": ["refs/heads/main"]
      }
    },
    {
      "id": "direct-main-example",
      "effect": "allow",
      "clients": ["bob"],
      "operations": ["git.push.force"],
      "targets": [
        {"kind": "repo", "owner": "osolmaz", "name": "direct-main"}
      ],
      "attrs": {
        "refs": ["refs/heads/main"]
      }
    }
  ]
}
```

Rules must not be mixed together. A request matches a rule only when the same
rule matches the client, operation, target, and relevant attributes. The
broker must not combine the operation from one rule with the target from
another rule.

Attrs are operation-specific. If a rule has attrs, every operation in that rule
must support every attr in the rule. Split rules instead of relying on ignored
attrs.

Decision precedence:

```text
deny > active generated grant allow > static allow > request > no_match
```

Deny rules always win, including over temporary grants.

Rules should support exact values and small segment globs. Globs must not
silently match path separators unless the field is explicitly a path/ref field
that documents that behavior. Unknown rule fields, unknown operations, unknown
attributes, malformed refs, and ambiguous request classifications must fail
closed at startup or request time.

## Explicit API Surface

Expose only named broker operations. Do not forward arbitrary GitHub REST API
paths.

Git smart-HTTP routes stay Git-shaped. JSON APIs live under `/api/*` and use a
stable JSON envelope. Do not add new non-Git JSON routes outside `/api/*`.

Supported long-term route families:

```text
GET  /healthz

GET  /{owner}/{repo}.git/info/refs?service=git-upload-pack
POST /{owner}/{repo}.git/git-upload-pack

GET  /{owner}/{repo}.git/info/refs?service=git-receive-pack
POST /{owner}/{repo}.git/git-receive-pack

POST /api/repos/{owner}/{repo}/pulls
GET  /api/repos/{owner}/{repo}/pulls/{number}
GET  /api/repos/{owner}/{repo}/checks
GET  /api/repos
POST /api/grants
GET  /api/grants
GET  /api/grants/{id}
POST /webhooks/github
```

Do not add generic pass-through routes such as:

```text
/repos/*
/orgs/*
/user/*
/actions/*
```

Do not add endpoints for organization administration, repository deletion,
repository settings, repository members, Actions secrets, workflow
administration, billing, or arbitrary GitHub API access unless the project
rules are deliberately changed first.

Pull request creation should be a broker operation, not an arbitrary proxy to
GitHub's pull request API. It should validate title/body length, base branch,
head branch, maintainer-edit settings, draft state, and repo scope before
forwarding. Fork-qualified heads such as `owner:branch` should be rejected
unless a future policy model explicitly represents and authorizes the fork
owner.

`GET /api/repos` should be installation-scoped and policy-filtered. It should
return only repositories that are both visible to the GitHub App installation
and allowed by broker policy. Public repositories are not special when accessed
through the broker; broker-routed reads still require broker policy. Filtered
repository list responses must not forward upstream credential metadata or
unfiltered pagination headers.

## GitHub App Installations And Webhooks

GitHub App installation state should be treated as upstream authority. The
broker should not assume that a repo remains accessible just because it appears
in `scope.json`.

For each request, production code should either:

```text
resolve the installation for the target repo fresh
```

or use a cache that is invalidated by verified GitHub webhooks.

Webhook endpoint:

```text
POST /webhooks/github
```

The webhook route must verify:

```text
X-Hub-Signature-256
X-GitHub-Event
X-GitHub-Delivery
```

Useful webhook events:

```text
installation
installation_repositories
repository renamed/transferred/archived
pull_request
check_suite/check_run
```

Webhook handling should be narrow. It may update installation/repo metadata
caches and audit state. It must not become an unauthenticated control plane for
policy changes, credential changes, or grant decisions.

## Git Enforcement

Git smart HTTP routes should stay Git-compatible. They should not use a JSON
envelope.

`git-receive-pack` must be parsed before forwarding upstream so the broker can
classify the push:

```text
branch create
existing branch update
branch/ref delete
tag create
tag move
tag delete
```

The broker cannot safely use GitHub's compare API to distinguish
fast-forward and non-fast-forward updates before forwarding a normal push.
At that point, new commits often exist only inside the request pack and
GitHub cannot compare them yet. Until the broker has a verifier that can prove
fast-forward, it must classify existing branch updates as `git.push.force`, not
`git.push.fast_forward`. GitHub branch protections or rulesets must remain
active so GitHub rejects actual non-fast-forward updates after it receives and
unpacks the push.

The safe default is:

```text
branch create: allowed by policy
feature branch update: allowed by explicit git.push.force policy
default branch update: denied unless explicitly allowed
non-fast-forward update: rejected by GitHub rulesets/protections unless explicitly allowed upstream
ref delete: denied unless explicitly granted
tag move/delete: denied unless explicitly granted
```

Push request bodies and pack contents must not appear in logs, audit records,
errors, tests, or API responses.

Default branch protection must be policy-backed, not hardcoded forever. It is
fine for the seed implementation to hardcode `main` and the upstream default
branch, but production should classify the ref and let policy deny or allow it.

The broker should not execute local `git` commands to apply policy. It should
parse the Git smart-HTTP request enough to classify and enforce, then forward
only accepted requests upstream with the server-side GitHub token.

## Grants

Temporary grants should be added after static policy is solid.

Grant flow:

```text
agent requests a narrow exception
operator approves or denies
approved grant becomes a generated temporary allow rule
generated rule is bound to the requesting client
generated rule expires absolutely
generated rule has a small use budget
deny rules still override it
```

Example grant:

```text
allow bob to force-push refs/heads/agent/fix once for 5 minutes
```

Do not make grants broaden standing policy silently. A grant should cover only
the exact operation, repo, ref, attributes, client, duration, and use budget
that the operator approved.

Grant support should reuse the same policy engine. An approved grant is a
generated temporary allow rule evaluated after deny rules and before static
allow rules. Generated grants must never use wildcard clients.

## Audit

Audit every broker decision with structured fields:

```text
client
operation
owner
repo
ref
decision
reason
matched_rule_ids
grant_id
upstream_status
github_request_id
installation_id
```

Audit logs must not include:

```text
GitHub token
broker client secret
Authorization headers
cookies
request bodies
pull request bodies
pack contents
diffs
credential helper output
raw upstream response bodies
GitHub App installation tokens
```

## Doctor

GitHub-native deployment checks are implemented as:

```sh
sudo gh-broker doctor github \
  --repo owner/name \
  --agent-user bob \
  --service-user gh-broker
```

The doctor verifies:

```text
service user exists
agent user is not root-equivalent
GitHub App id loads successfully
GitHub App private key exists and is not readable by the agent
webhook secret exists and is not readable by the agent
broker client secret exists and is not readable by the agent
broker can sign a GitHub App JWT
broker can mint an installation token for a configured repo
GitHub App has the expected minimal permissions
configured repo is installed for the app
broker can reach api.github.com
branch protection or ruleset exists for default branch when policy expects it
```

Rulesets are inspected with the App's mandatory Metadata read permission.
Classic branch protection inspection requires Administration read; when the
minimal App does not have that permission, the classic-protection result is
inconclusive rather than falsely reported as absent.

Doctor output must never print private keys, webhook secrets, PATs,
installation tokens, JWTs, Authorization headers, or token metadata.
`--json` emits the brokerkit doctor report schema. Exit code `0` means safe,
`1` means unsafe, `2` means inconclusive, and `64` means invalid invocation or
configuration. The development PAT fallback is reported as a warning because
it cannot prove GitHub App installation permissions.

## Implementation Order

1. Public source identity is `github.com/osolmaz/brokerkit/brokers/github`.
   - module `github.com/osolmaz/brokerkit`
   - binary `gh-broker`
   - env vars `GH_BROKER_*`
   - docs and README use `gh-broker`

2. Cut over shared control-plane code to brokerkit:
   - `internal/security` -> `brokerkit/auth`
   - `internal/policy` -> `brokerkit/policy` plus a gh-broker provider registry
   - generated grants -> `brokerkit/grants`
   - approval request, callback, revoke, and status handling -> brokerkit
   - audit metadata helpers -> `brokerkit/audit`
   - approval interfaces and Telegram transport -> `brokerkit/notify`
   - generic storage/config helpers -> brokerkit
   - generic Git receive-pack parsing and ref classification -> brokerkit only
     if `hf-broker` can share the same API
   - delete local duplicate runtimes in the same changes

3. Add production service setup:
   - `GH_BROKER_GITHUB_APP_ID_FILE`
   - `GH_BROKER_GITHUB_APP_PRIVATE_KEY_FILE`
   - `GH_BROKER_GITHUB_WEBHOOK_SECRET_FILE`
   - `GH_BROKER_GITHUB_TOKEN_FILE` as a dev fallback only
   - `gh-broker setup systemd`
   - dedicated `gh-broker` user
   - protected GitHub App credentials, webhook secret, broker secrets, scope,
     and systemd unit files

4. GitHub App installation-token support is implemented:
   - sign GitHub App JWTs
   - resolve installation ids by repo
   - mint short-lived installation tokens
   - keep PAT fallback for local development only
   - include installation ids in audit metadata
   - still add GitHub request ids from upstream responses to audit metadata

5. Cut over to rule-based scope:
   - request classifier
   - rule parser and validator
   - deny/allow/request decisions
   - delete `github-access.json`
   - no dual policy runtimes after cutover
   - fail startup on old owner/repository allowlist once rules land

6. Move Git and PR handlers onto the policy engine:
   - classify fetch and push shapes
   - classify PR creation
   - keep Git responses Git-shaped
   - keep JSON APIs under `/api/*`
   - remove hardcoded "protected branch" authorization from handlers after
     policy covers the same behavior

7. Installation-scoped repo listing and verified webhook support are implemented:
   - `GET /api/repos`
   - verified `POST /webhooks/github`
   - policy filtering after GitHub visibility filtering
   - still add app installation cache invalidation if a cache is introduced

8. Compatibility route aliases are removed:
   - keep `/api/repos/{owner}/{repo}/pulls`
   - removed the GitHub-shaped `POST /repos/{owner}/{repo}/pulls` route
   - do not preserve old local route contracts

9. Add installer and release workflow:
   - `install.sh`
   - the root qualified-tag release workflow
   - `gh-broker --version`
   - GitHub release assets for Linux/macOS amd64/arm64
   - brokerkit-aligned `setup systemd` and `setup client` behavior described
     in [2026-07-11-brokerkit-unification-plan.md](2026-07-11-brokerkit-unification-plan.md)

10. Add grants only after static policy and request classification are
   well-tested.

Avoid shipping broad intermediate abstractions. Each slice should move toward
the final `hf-broker`-style shape rather than preserving old and new control
planes side by side.

## Brokerkit Cutover Test Gates

Every brokerkit cutover PR must prove:

- the replaced local implementation is deleted in the same change
- all valid auth, policy, grant, approval, and audit decisions go through
  brokerkit
- GitHub-specific code only registers operations, targets, attrs, request
  classifiers, upstream execution, audit extensions, and approval wording
- malformed or unclassified GitHub Git/API requests fail closed before upstream
  forwarding
- deny still overrides active grants
- active grants match only the approved client, operation, target, attrs,
  duration, and use budget
- Telegram approval uses the brokerkit adapter
- a dangerous Git operation grant is tested end to end with a fake notifier and
  fake GitHub upstream
- generated grants are evaluated by the brokerkit policy decision path, not a
  second grant-specific allow path
- Telegram approval is covered with a fake Bot API server or fake notifier in
  automated tests; CI must not require a live bot token or send real messages
- notification delivery is claimed once, its editable message reference is
  stored with the grant, and lifecycle updates resume after process restart
- a crash between provider acceptance and message-reference persistence leaves
  the claim unresolved through its lease; a later retry rotates the one-time
  decision token before another send
- a timeout, transport failure, or uncertain upstream result never releases a
  reserved grant use back into the available budget
- end-to-end broker tests use fake GitHub upstreams, fake installation-token
  minting, and fake notifiers by default; live GitHub checks are explicit
  manual or milestone probes
- audit output contains no broker secrets, GitHub tokens, installation tokens,
  request bodies, Git pack contents, approval tokens, or Telegram bot tokens

## Merge Gates

Every production slice should pass:

```sh
go fmt ./...
go vet ./...
go test ./...
go build ./cmd/gh-broker
```

After the rename, update this to:

```sh
go fmt ./...
go vet ./...
go test ./...
go build ./cmd/gh-broker
```

```sh
golangci-lint run
slophammer-go dry .
slophammer-go crap .
slophammer-go check .
slophammer-go check . --execute
```

Slophammer's DRY, CRAP, and check gates are mandatory for GitHub broker slices.
Mutation configuration remains checked in for explicit training or hardening
runs, but mutation testing is not part of the default local or CI gate.
