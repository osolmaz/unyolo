# gh-broker

gh-broker is a small GitHub credential broker for coding agents. It gives an agent a broker secret, keeps the real GitHub credential server-side, and allows only the Git and GitHub API operations matched by `scope.json`.

The central invariant is strict: gh-broker must not provide an API, log path, error path, or helper that returns original GitHub credential material.

The shared broker-family install and setup cutover is tracked in
[docs/BROKERKIT_UNIFICATION.md](docs/BROKERKIT_UNIFICATION.md).

## Current Shape

- Echo HTTP server
- `gh-broker --version`
- `gh-broker setup client`
- `gh-broker setup systemd` for Linux service file/config generation
- Shared-secret authentication for one configured client id
- Server-side named client secrets through `GH_BROKER_SECRETS_FILE`
- Rule-based `scope.json` with GitHub classification delegated to the shared
  brokerkit policy engine
- Git smart HTTP fetch and push route shape
- Narrow GitHub API routes for repository listing, content reads, and pull request creation
- Server-side GitHub token forwarding as a development credential path
- Localhost bind by default for Tailnet-oriented deployment
- Conservative receive-pack size cap and upstream GitHub timeouts
- Structured audit logs without secrets, request bodies, diffs, or pack contents
- No credential API
- No policy read/write API
- Tests for auth, route shape, policy decisions, and receive-pack classification

## Local Development

```sh
cp .env.example .env
cp scope.example.json scope.json
# edit GH_BROKER_SHARED_SECRET to a generated value with at least 32 bytes
# set GH_BROKER_GITHUB_TOKEN to a GitHub token with the repo access gh-broker should broker
# edit scope.json by hand
source .env
make check
make run
```

## Install

Install the latest release globally:

```sh
curl -fsSL https://raw.githubusercontent.com/osolmaz/gh-broker/main/install.sh | sh
```

Pinned install:

```sh
curl -fsSL https://raw.githubusercontent.com/osolmaz/gh-broker/main/install.sh | VERSION=v0.1.0 sh
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

Linux service setup with the current token-file runtime:

```sh
sudo gh-broker setup systemd \
  --dev-token-fallback \
  --github-token-file ./github-token \
  --scope-file ./scope.json
```

Use `--no-start` to write files without enabling or starting the service.
The setup command writes `/etc/gh-broker/secrets` and configures the service
with `GH_BROKER_SECRETS_FILE`; it does not place the broker client secret or
GitHub token value directly in the env file.

Health check:

```sh
curl http://localhost:8080/healthz
```

Fetch through the broker:

```sh
git -c http.extraHeader="Authorization: Bearer $GH_BROKER_SHARED_SECRET" \
  ls-remote http://localhost:8080/osolmaz/gh-broker.git
```

List policy-visible repositories:

```sh
curl -H "Authorization: Bearer $GH_BROKER_SHARED_SECRET" \
  http://localhost:8080/api/repos
```

Read repository contents:

```sh
curl -H "Authorization: Bearer $GH_BROKER_SHARED_SECRET" \
  http://localhost:8080/api/repos/osolmaz/gh-broker/contents/README.md?ref=main
```

Open a pull request:

```sh
curl -X POST -H "Authorization: Bearer $GH_BROKER_SHARED_SECRET" \
  -H "Content-Type: application/json" \
  -d '{"title":"agent work","head":"bob/work","base":"main","body":"Ready for review."}' \
  http://localhost:8080/api/repos/osolmaz/gh-broker/pulls
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

GET  /api/repos
POST /api/grants
GET  /api/grants
GET  /api/grants/{id}
GET  /api/repos/{owner}/{repo}/contents/{path}
POST /api/repos/{owner}/{repo}/pulls

GET  /{owner}/{repo}.git/info/refs?service=git-upload-pack
POST /{owner}/{repo}.git/git-upload-pack

GET  /{owner}/{repo}.git/info/refs?service=git-receive-pack
POST /{owner}/{repo}.git/git-receive-pack
```

The long-term route shape is `/api/*` for JSON APIs and Git smart-HTTP routes for Git. Compatibility aliases are not part of the production plan.

## Security Model

gh-broker should run behind Tailnet-only reachability, but Tailnet access is not authorization. Every broker endpoint still requires the configured shared secret.

Production should use GitHub App credentials:

```text
GH_BROKER_GITHUB_APP_ID_FILE=/etc/gh-broker/github-app-id
GH_BROKER_GITHUB_APP_PRIVATE_KEY_FILE=/etc/gh-broker/github-app-private-key.pem
GH_BROKER_GITHUB_WEBHOOK_SECRET_FILE=/etc/gh-broker/github-webhook-secret
```

For repo-scoped requests, gh-broker resolves the GitHub App installation for
the target repository and mints a short-lived installation token after broker
policy allows the request. For repository listing, gh-broker lists App
installations and then filters visible installation repositories through
`scope.json`.

`GH_BROKER_GITHUB_TOKEN_FILE` remains available as a local development
fallback.

GitHub App webhooks are accepted at:

```text
POST /webhooks/github
```

The webhook route requires `X-Hub-Signature-256`, `X-GitHub-Event`, and
`X-GitHub-Delivery`. It verifies the payload with
`GH_BROKER_GITHUB_WEBHOOK_SECRET_FILE`, accepts bodies up to 1 MiB, and logs only
audit-safe metadata such as event, delivery id, action, installation id, and
repository name.

Deployment safety defaults:

- `GH_BROKER_BIND_ADDR` defaults to `127.0.0.1`.
- `GH_BROKER_STATE_DIR` defaults to `./state`.
- `GH_BROKER_GITHUB_HTTP_TIMEOUT` defaults to 30 seconds.
- `GH_BROKER_MAX_RECEIVE_PACK_BYTES` defaults to 25 MiB.
- `GH_BROKER_TELEGRAM_BOT_TOKEN` and `GH_BROKER_TELEGRAM_CHAT_ID` enable
  Telegram approval for requestable grants.
- Audit logs record client, operation, owner, repo, method, path, outcome,
  status, reason, matched rule ids, GitHub installation id when one was minted
  for the request, and verified webhook event metadata.
- Audit logs do not include tokens, cookies, request bodies, PR bodies, pack
  contents, diffs, raw upstream bodies, JWTs, installation tokens, or private
  keys.

## Grants

Request rules do not execute directly. An authenticated client creates a
pending grant with `POST /api/grants`; gh-broker sends the approval request to
Telegram when Telegram is configured. Approval creates a short-lived brokerkit
grant that is evaluated by the same policy path as static rules. Deny rules
still win over approved grants.

The editable Telegram message reference and its last delivered lifecycle state
are stored with the grant. Once the reference is stored, status delivery
resumes after a broker restart.
Approval sends are at most once per pending grant. If the process stops after
Telegram accepts a send but before its reference is stored, the unresolved
grant is not sent again; it fails closed and expires.
Grant uses are reserved before GitHub forwarding; an ambiguous upstream result
is retained for operator review instead of reopening the grant budget.

## License

[MIT](LICENSE)
