# gh-broker

gh-broker is a small GitHub credential broker for coding agents. It gives an agent a broker secret, keeps the real GitHub credential server-side, and allows only the Git and GitHub API operations matched by `scope.json`.

The central invariant is strict: gh-broker must not provide an API, log path, error path, or helper that returns original GitHub credential material.

The shared install, setup, policy, approval, and release contract is in
[BrokerKit's unified broker contract](../../docs/UNIFIED_BROKER_CONTRACT.md).

## Current Shape

- Echo HTTP server
- `gh-broker --version`
- `gh-broker setup client`
- `gh-broker setup github-user enroll|rotate|revoke` for protected local
  enrollment of expiring GitHub App user credentials
- `gh-broker setup systemd` for Linux service file/config generation
- `gh-broker doctor github` for local isolation, GitHub App, repository, and
  default-branch protection checks
- Shared-secret authentication for one configured client id
- Server-side named client secrets through `GH_BROKER_SECRETS_FILE`
- Rule-based `scope.json` with GitHub classification delegated to the shared
  brokerkit policy engine
- Git smart HTTP fetch and push route shape
- Exhaustive typed Agent V1 operations generated from pinned GitHub REST and GraphQL definitions
- Opaque broker-owned `app-jwt`, exact installation, user, and protected-file
  development credential providers
- Exact installation-token narrowing and cache isolation by installation,
  repository ids, permissions, API host, and expiry behavior
- Localhost bind by default for Tailnet-oriented deployment
- Conservative receive-pack size cap and upstream GitHub timeouts
- Structured audit logs without secrets, request bodies, diffs, or pack contents
- Brokerkit-backed grants with a durable operator inbox and optional Telegram notifications
- No credential API
- No policy read/write API
- Tests for auth, route shape, policy decisions, and receive-pack classification

## Generated operation surface

The checked-in stage 2–3 inventory classifies all 1,196 operations in the
pinned stable GitHub REST API and all 300 roots in the pinned full GraphQL
introspection, including 16 deprecated mutation roots. It generates 1,436
canonical typed catalog operations, closed target/argument/result schemas,
REST bindings, persisted GraphQL documents, policy metadata, GitHub App
permission profiles, CLI metadata, MCP tool schemas, and capability docs.

Browse the generated reference in
[CAPABILITIES.md](docs/generated/CAPABILITIES.md) or query it locally:

```sh
gh-broker operations list --family pull_request
gh-broker operations describe repo.visibility.update
```

The MCP server exposes the exhaustive catalog through the paged
`github://operations` resource. `tools/list` is separately filtered by the
authenticated client's enabled operations, policy-visible operations, runtime
capabilities, and the operator exposure profile. With no configured
intersection it advertises zero execution tools; it never publishes the full
catalog as 1,000+ tools by default.

Credential selection is immutable broker metadata. Callers choose an operation
and target, never a credential kind, token scope, installation, or permission
set. The generated operation catalog supplies the minimum GitHub App permission
map used for installation-token minting.

## Local Development

```sh
cp .env.example .env
cp scope.example.json scope.json
install -m 600 /dev/null github-token
# write a development-only fine-grained token to github-token
# edit GH_BROKER_SHARED_SECRET to a generated value with at least 32 bytes
# edit scope.json by hand
source .env
make check
make run
```

## Install

Install the latest release globally:

```sh
curl -fsSL https://raw.githubusercontent.com/osolmaz/brokerkit/main/brokers/github/install.sh | sh
```

Pin a version from [BrokerKit releases](https://github.com/osolmaz/brokerkit/releases):

```sh
curl -fsSL https://raw.githubusercontent.com/osolmaz/brokerkit/main/brokers/github/install.sh | VERSION=<version> sh
```

Write a client config file from a broker secrets file:

```sh
gh-broker setup client \
  --client bob \
  --url http://127.0.0.1:8081 \
  --secret-file /etc/gh-broker/secrets \
  --home-dir /home/bob
```

The generated `client.env` contains only `GH_BROKER_URL` and
`GH_BROKER_SHARED_SECRET`; it does not contain GitHub credentials.

Production Linux service setup with GitHub App credentials:

```sh
sudo gh-broker setup systemd \
  --github-app-id-file ./app-id \
  --github-app-private-key-file ./private-key.pem \
  --github-webhook-secret-file ./webhook-secret \
  --scope-file ./scope.json
```

To enable encrypted GitHub App user credentials, add the App's OAuth client
files to setup:

```sh
sudo gh-broker setup systemd \
  --github-app-id-file ./app-id \
  --github-app-private-key-file ./private-key.pem \
  --github-app-client-id-file ./client-id \
  --github-app-client-secret-file ./client-secret \
  --github-user-id 1234 \
  --github-webhook-secret-file ./webhook-secret \
  --scope-file ./scope.json
```

Development setup with a token file:

```sh
sudo gh-broker setup systemd \
  --dev-token-fallback \
  --github-token-file ./github-token \
  --scope-file ./scope.json
```

This fallback is protected-file-only and non-production. `doctor github`
returns an unsafe result if it is selected with
`GH_BROKER_ENVIRONMENT=production`.

Enroll an expiring GitHub App user credential from a local operator shell while
the broker is stopped. The state directory must already exist with the broker
service user's ownership; setup preserves that owner across key and slot
writes. The input is a mode `0600` JSON file and is deleted by the operator
after a successful enrollment:

```json
{
  "user_id": 1234,
  "login": "octocat",
  "access_token": "expiring-access-token",
  "refresh_token": "expiring-refresh-token",
  "access_expires_at": "2026-07-14T12:00:00Z",
  "refresh_expires_at": "2026-10-14T12:00:00Z"
}
```

```sh
chmod 600 user-credential.json app-client-id app-client-secret
gh-broker setup github-user enroll \
  --state-dir /var/lib/gh-broker \
  --credential-file ./user-credential.json \
  --github-app-client-id-file ./app-client-id \
  --github-app-client-secret-file ./app-client-secret
rm user-credential.json
```

Use the same command with `rotate` and a replacement credential file to rotate
an enrollment. Revoke immediately with `github-user revoke --user-id 1234`
and the same state/client flags. These commands return only the action and
immutable user id; there is no credential readback command or API route.

Add Telegram notifications by passing the bot token as a protected file:

```sh
sudo gh-broker setup systemd \
  --dev-token-fallback \
  --github-token-file ./github-token \
  --scope-file ./scope.json \
  --telegram-bot-token-file ./telegram-bot-token \
  --telegram-chat-id 123456789
```

Use `--no-start` to write files without enabling or starting the service.
The setup command writes `/etc/gh-broker/secrets`,
`/etc/gh-broker/operator-secrets`, and the optional Telegram token as protected
files. It does not place broker client secrets, operator secrets, GitHub
credentials, or Telegram credentials directly in the env file. The operator
API uses a separate credential and listener at `http://127.0.0.1:8082` by
default. Use `--operator-secret-file`, `--operator-bind-addr`, and
`--operator-port` to supply or change them.

Verify the installed deployment:

```sh
sudo gh-broker doctor github \
  --repo osolmaz/gh-broker \
  --agent-user bob \
  --service-user gh-broker
```

Use `--json` for machine-readable output. Exit code `0` means safe, `1` means
unsafe, `2` means inconclusive, and `64` means the invocation or configuration
is invalid. Doctor reads `/etc/gh-broker/env` by default; use `--env-file` for
a nonstandard installation or `--env-file ''` to use only the current process
environment.

When an env file is selected, it is authoritative; exported shell variables do
not override the installed service configuration. Inline credential values are
reported as inconclusive because doctor cannot prove which users have observed
them. Protected credential files are required for a safe isolation verdict.

Health check:

```sh
curl http://localhost:8080/healthz
```

Fetch through the broker:

```sh
git -c http.extraHeader="Authorization: Bearer $GH_BROKER_SHARED_SECRET" \
  ls-remote http://localhost:8080/osolmaz/gh-broker.git
```

List repositories visible to the selected GitHub user credential:

```sh
gh-broker operation submit repo.list_for_authenticated_user \
  --target-json '{"kind":"user","name":"osolmaz"}' \
  --arguments-json '{}' \
  --wait
```

Read repository contents:

```sh
gh-broker operation submit repo.contents.read \
  --target-json '{"kind":"repo","owner":"osolmaz","name":"brokerkit"}' \
  --arguments-json '{"path":"README.md","ref":"main"}' \
  --wait
```

Open a pull request:

```sh
curl -X POST -H "Authorization: Bearer $GH_BROKER_SHARED_SECRET" \
  -H "Content-Type: application/json" \
  -d '{"idempotency_key":"open-agent-pr","operation":"pull_request.create","target":{"kind":"repo","owner":"osolmaz","name":"gh-broker"},"arguments":{"title":"agent work","head":"bob/work","base":"main","body":"Ready for review."},"reason":"Open the reviewed feature branch"}' \
  http://localhost:8080/api/agent/v1/operations
```

## Policy

`scope.json` is the authorization source of truth. A request is classified into:

```text
client + operation + target + attrs -> allow | request | deny | no_match
```

Deny rules win over allow rules. A rule matches only when the same rule matches the client, operation, target, and operation-relevant attributes. If a rule has attrs, every operation in that rule must support every attr; split rules when operations need different attrs.

The default production-oriented workflow is:

- allow fetch, repository listing, and content reads for scoped repositories
- allow agents to push feature branches such as `refs/heads/bob/*`
- allow agents to open pull requests into `refs/heads/main`
- deny ref deletion and unsupported ref updates before forwarding
- deny default-branch pushes unless a repository has an explicit direct-main allow rule
- classify existing branch updates as `git.push.force` unless the broker can prove fast-forward
- rely on GitHub rulesets or branch protections as the upstream enforcement layer after GitHub receives the pack

Example direct-main exception:

```json
{
  "id": "direct-main-example",
  "effect": "allow",
  "clients": ["bob"],
  "operations": ["git.push.force"],
  "targets": [{"kind": "repo", "owner": "osolmaz", "name": "direct-main"}],
  "attrs": {"refs": ["refs/heads/main"]}
}
```

## Broker Routes

```text
GET  /healthz

POST /api/grants                         Git smart-HTTP protocol grant request
GET  /api/grants                         Git smart-HTTP protocol grants
GET  /api/grants/{id}                    Git smart-HTTP protocol grant

GET  /.well-known/brokerkit-agent
POST /api/agent/v1/operations
GET  /api/agent/v1/operations/{id}
GET  /api/agent/v1/operations/{id}/events
POST /api/agent/v1/operations/{id}/cancel
POST /api/agent/v1/sealed-payloads
POST /api/agent/v1/streams
GET  /api/agent/v1/streams/{id}

GET  /{owner}/{repo}.git/info/refs?service=git-upload-pack
POST /{owner}/{repo}.git/git-upload-pack

GET  /{owner}/{repo}.git/info/refs?service=git-receive-pack
POST /{owner}/{repo}.git/git-receive-pack
```

All discrete GitHub JSON operations use Agent V1. The `/api/grants` surface is
reserved for approval requests created while handling Git smart-HTTP protocol
traffic. Direct repository-list and contents proxy routes are not supported.
Compatibility aliases are not part of the production surface.

## Operator Inbox

The protected operator listener exposes Brokerkit's shared backend:

```text
GET  /api/grants
GET  /api/grants/{id}
GET  /api/grants/events
POST /api/grants/{id}/approve
POST /api/grants/{id}/deny
POST /api/grants/{id}/cancel
POST /api/grants/{id}/revoke
```

Authenticate with the separate operator credential from
`/etc/gh-broker/operator-secrets`. Agent credentials cannot use this listener.
Telegram is an optional notification view over the same durable request, so a
decision through either path closes the same state exactly once. A trusted web
host keeps this credential server-side and exposes only its own
authenticated browser session and bounded Brokerkit response fields.

## Security Model

gh-broker should run behind Tailnet-only reachability, but Tailnet access is not authorization. Every broker endpoint still requires the configured shared secret.

Production should use GitHub App credentials:

```text
GH_BROKER_GITHUB_APP_ID_FILE=/etc/gh-broker/github-app-id
GH_BROKER_GITHUB_APP_PRIVATE_KEY_FILE=/etc/gh-broker/github-app-private-key.pem
GH_BROKER_GITHUB_WEBHOOK_SECRET_FILE=/etc/gh-broker/github-webhook-secret
```

For repo-scoped requests, gh-broker resolves the GitHub App installation for
the target repository with `go-github` and mints a short-lived token with the
exact repository id and catalog-derived minimum permission map after broker
policy allows the request. Cache keys include the installation id, sorted exact
repository ids, exact permissions, API host, and refresh behavior. Broader
credentials are never reused for narrower requests. App JWT transport is
provided by `ghinstallation`; typed GitHub API pagination, errors, rate limits,
installation resolution, token requests, and webhook parsing use `go-github`.
Repository-list credentials are uncached and revoked immediately after use.

`GH_BROKER_GITHUB_TOKEN_FILE` remains available only as a protected-file local
development fallback. Inline PAT configuration is rejected.

GitHub App webhooks are accepted at:

```text
POST /webhooks/github
```

The webhook route requires `X-Hub-Signature-256`, `X-GitHub-Event`, and
`X-GitHub-Delivery`. It verifies the payload with
`GH_BROKER_GITHUB_WEBHOOK_SECRET_FILE`, accepts bodies up to 1 MiB, and logs only
audit-safe metadata such as event, delivery id, action, installation id, and
repository name. Installation suspension/deletion, repository selection
changes, and `github_app_authorization` revocation invalidate affected cached
credentials immediately. Invalid or unknown signed payloads fail closed.

User access and refresh credentials are stored only in BrokerKit's encrypted
credential store. Access credentials refresh before expiry, rotating refresh
credentials are persisted as one encrypted record, and enrollment, rotation,
revocation, errors, plans, results, audit events, and operator surfaces never
return credential material.

Deployment safety defaults:

- `GH_BROKER_BIND_ADDR` defaults to `127.0.0.1`.
- `GH_BROKER_STATE_DIR` defaults to `./state`.
- `GH_BROKER_GITHUB_HTTP_TIMEOUT` defaults to 30 seconds.
- `GH_BROKER_GITHUB_STREAM_TIMEOUT` defaults to 600 seconds for bounded uploads and downloads.
- `GH_BROKER_MAX_RECEIVE_PACK_BYTES` defaults to 25 MiB.
- `GH_BROKER_TELEGRAM_BOT_TOKEN_FILE` and `GH_BROKER_TELEGRAM_CHAT_ID` enable
  Telegram notifications for requestable grants. Telegram tokens are loaded
  only from protected files.
- Audit logs record client, operation, owner, repo, method, path, outcome,
  status, reason, matched rule ids, GitHub installation id when one was minted
  for the request, and verified webhook event metadata.
- Audit logs do not include tokens, cookies, request bodies, PR bodies, pack
  contents, diffs, raw upstream bodies, JWTs, installation tokens, or private
  keys, refresh tokens, PATs, or GitHub App client secrets.

## Grants

Request rules do not execute directly. Discrete GitHub operations use Agent V1,
which creates the durable approval request as part of the submitted operation.
Git smart-HTTP protocol handling creates a pending grant through
`POST /api/grants`; every such request must include a unique
`client_request_id`, and retries must reuse that value. gh-broker sends the
approval request to Telegram when Telegram is configured, but the durable
operator inbox remains authoritative and works without Telegram. Approval
creates a short-lived brokerkit grant that is evaluated by the same policy path
as static rules. Deny rules still win over approved grants.

The editable Telegram message reference and its last delivered lifecycle state
are stored with the grant. Once the reference is stored, status delivery
resumes after a broker restart. A verified callback commits the decision and
message reference in one transaction, including when the original send response
was lost. Durable write failures leave the callback unanswered at the same
Telegram update for retry. Ambiguous sends remain blocked for the two-minute
claim lease; a later retry uses a fresh one-time decision token.
Grant uses are reserved before GitHub forwarding; an ambiguous upstream result
is retained for operator review instead of reopening the grant budget. Retained
grants report `status: retained` and `uses_remaining: 0`.

## License

[MIT](LICENSE)
