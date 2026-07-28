# gh-broker

gh-broker is a GitHub access broker for coding agents. It keeps GitHub App
credentials on the broker host and exposes only the Git and API operations
allowed by `scope.json`.

GitHub credential material must never appear in an API response, log, error, or
helper output. Callers name an operation and target. The broker selects the
installation and permissions needed for that operation.

## Install

Fetch the bootstrap from a reviewed unYOLO commit. It resolves the latest
GH Broker release to its exact commit, verifies release checksums, and
installs to `$HOME/.local/bin`:

```sh
UNYOLO_REV=<verified-40-character-commit-sha>
curl -fsSL "https://raw.githubusercontent.com/osolmaz/unyolo/$UNYOLO_REV/brokers/github/install.sh" | sh
```

Pin a release from [unYOLO releases](https://github.com/osolmaz/unyolo/releases)
with `VERSION=<version>`, or choose the target directory with
`INSTALL_DIR=/absolute/path`.

## Production setup on Linux

Production uses GitHub App credentials. Create the App, collect its id,
private key, and webhook secret as protected files, then run:

```sh
sudo gh-broker setup systemd \
  --github-app-id-file ./app-id \
  --github-app-private-key-file ./private-key.pem \
  --github-webhook-secret-file ./webhook-secret \
  --scope-file ./scope.json \
  --client agent-a \
  --operator operator-a \
  --agent-user agent-a \
  --operator-user operator-a \
  --git-endpoint tcp://127.0.0.1:38471
```

Setup writes protected files under `/etc/gh-broker` (`secrets`,
`operator-secrets`, the GitHub credential files, `scope.json`, `env`),
installs the systemd unit and sockets, and starts the service. It never
places broker client secrets, operator secrets, GitHub credentials, or
Telegram credentials directly in the env file. The agent and operator APIs
use distinct Unix sockets by default; use `--endpoint`, `--operator-endpoint`,
and `--operator-secret-file` to select deployment-owned endpoints or preserve
an existing operator credential. Use `--no-start` to write files without
starting the service, or `--dry-run` to preview without writing.

Omitting `--scope-file` installs the managed `request-all-agent-operations`
policy preset instead; add repeatable `--deny-operation <exact-name>` flags
to disable operations, and `--replace-policy` to overwrite an installed
policy after reviewing the printed digest and operation-count preview.
macOS uses `gh-broker setup launchd` with the same credential flags.

To also enable encrypted GitHub App user credentials, add the App's OAuth
client files and the GitHub account id:

```sh
sudo gh-broker setup systemd \
  --github-app-id-file ./app-id \
  --github-app-private-key-file ./private-key.pem \
  --github-app-client-id-file ./client-id \
  --github-app-client-secret-file ./client-secret \
  --github-user-id 1234 \
  --github-webhook-secret-file ./webhook-secret \
  --scope-file ./scope.json \
  --client agent-a \
  --operator operator-a \
  --agent-user agent-a \
  --operator-user operator-a
```

Add Telegram notifications with `--telegram-bot-token-file ./telegram-bot-token`
and `--telegram-chat-id 123456789`. The token is copied to a service-owned
protected file; pending requests remain available in the operator inbox
without Telegram. Run the separate `unyolo-telegram` ingress to receive
button decisions; provider services never compete for the shared bot's update
offset. See [Telegram approval ingress](../../docs/TELEGRAM_INGRESS.md).

Write a client config file for an agent account:

```sh
sudo gh-broker setup client \
  --client agent-a \
  --endpoint unix:///run/unyolo/github/agent/broker.sock \
  --git-endpoint tcp://127.0.0.1:38471 \
  --secret-file /etc/gh-broker/secrets \
  --home-dir /home/agent-a
```

The generated `~/.config/gh-broker/client.json` contains the client identity,
broker endpoints, and broker client secret; it does not contain GitHub
credentials. Broker clients load this owner-only file directly.

Then configure standard Git once for that user:

```sh
gh-broker git install
gh-broker git doctor
```

Normal `https://github.com/OWNER/REPO.git` and GitHub SSH-form remotes now send
all Git and LFS traffic through the broker. LFS signed URLs and
headers stay in the broker and are replaced by bounded broker-local actions.
`gh-broker git status --json`
reports the owned configuration, and `gh-broker git uninstall` removes only
that exact provider installation. The listener port is selected and persisted
by the deployment; unYOLO has no fixed Git port.

### Development token fallback

For local development only, a fine-grained token in a protected file can
replace the GitHub App:

```sh
sudo gh-broker setup systemd \
  --dev-token-fallback \
  --github-token-file ./github-token \
  --scope-file ./scope.json \
  --client agent-a \
  --operator operator-a \
  --agent-user agent-a \
  --operator-user operator-a
```

This fallback is protected-file-only and non-production. `doctor github`
returns an unsafe result if it is selected with
`GH_BROKER_ENVIRONMENT=production`. Inline PAT configuration is rejected.

### Enroll a GitHub App user credential

Enroll an expiring GitHub App user credential from a local operator shell
while the broker is stopped. The state directory must already exist with the
broker service user's ownership. The input is a mode `0600` JSON file that
the operator deletes after a successful enrollment:

```json
{
  "user_id": 1234,
  "login": "octocat",
  "access_token": "expiring-access-token",
  "refresh_token": "expiring-refresh-token",
  "access_expires_at": "<access expiry, RFC3339>",
  "refresh_expires_at": "<refresh expiry, RFC3339>"
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

Use the same command with `rotate` and a replacement credential file to
rotate an enrollment. Revoke immediately with
`github-user revoke --user-id 1234` and the same state flags. These commands
return only the action and immutable user id; there is no credential
readback command or API route. Enrolled credentials are stored only in
unYOLO's encrypted credential store and refresh before expiry.

### Verify the deployment

```sh
sudo gh-broker doctor github \
  --repo osolmaz/unyolo \
  --agent-user agent-a \
  --service-user gh-broker
```

Doctor checks local isolation, the GitHub App configuration, repository
access, and default-branch protection. Use `--json` for machine-readable
output. Exit code `0` means safe, `1` unsafe, `2` inconclusive, and `64`
invalid invocation or configuration. Doctor reads `/etc/gh-broker/env` by
default; use `--env-file` for a nonstandard installation or `--env-file ''`
to use only the current process environment. When an env file is selected it
is authoritative, and inline credential values are reported as inconclusive;
protected credential files are required for a safe isolation verdict.

## Use it

Health check:

```sh
curl --unix-socket /run/unyolo/github/agent/broker.sock \
  http://localhost/healthz
```

Standard Git uses the one-time client installation described above. Remotes
remain ordinary GitHub URLs and the broker secret is supplied only by the
scoped credential helper:

```sh
gh-broker git install
git ls-remote https://github.com/osolmaz/unyolo.git
```

Discrete GitHub operations use the typed Agent V1 CLI. It loads the generated
private client V1 file automatically:

```sh
gh-broker operation submit repo.contents.read \
  --target-json '{"kind":"repo","owner":"osolmaz","name":"unyolo"}' \
  --arguments-json '{"path":"README.md","ref":"main"}' \
  --wait
```

Open a pull request:

```sh
gh-broker operation submit pull_request.create \
  --target-json '{"kind":"repo","owner":"osolmaz","name":"unyolo"}' \
  --arguments-json '{"title":"agent work","head":"agent-a/work","base":"main","body":"Ready for review."}' \
  --reason "Open the reviewed feature branch" \
  --request-id open-agent-pr \
  --wait
```

Reuse a stable `--request-id` when retrying, and resume interrupted
operations with `gh-broker operation get|wait|cancel <id>`.

### Admin merge a pull request

`pull_request.merge_admin` mirrors the direct merge path selected by
`gh pr merge --admin`. It uses the GitHub user identity already held by the
broker; there is no separate admin credential and no caller-supplied `admin`
flag sent to GitHub. In production, enroll the user credential as described
above. Development-token mode uses the account represented by its protected
token.

```sh
gh-broker operation submit pull_request.merge_admin \
  --target-json '{"kind":"pull_request","owner":"osolmaz","repo":"unyolo","number":123}' \
  --arguments-json '{"merge_method":"squash"}' \
  --reason "Merge the reviewed pull request despite its remaining GitHub requirement" \
  --request-id admin-merge-unyolo-123 \
  --wait
```

Admin merge is a distinct high-risk, explicit, one-use operation and requests
operator approval by default. unYOLO resolves the pull request itself,
binds approval to the exact pull-request head commit, rechecks it before
execution, and supplies it to GitHub as the mutation's atomic
`expectedHeadOid` guard. Administrator
privileges may bypass review, update, or merge-queue requirements, but do not
bypass merge conflicts. A changed pull request must be submitted and approved
again.

unYOLO parses GitHub's documented error `message` fields, removes control
characters, redacts credential-like values, and limits the text before returning
it to the requesting client. Raw response bodies, GraphQL paths, and extensions
are not retained. Sealed operations omit provider messages because GitHub may echo
request values. Durable operations can therefore report errors such as a
disabled merge method while machine behavior continues to use validated codes,
HTTP status, and request IDs.

### Operation catalog

The operation surface is generated from pinned GitHub REST and GraphQL
definitions into a typed catalog. Browse it in
[docs/generated/CAPABILITIES.md](docs/generated/CAPABILITIES.md) or query it
locally:

```sh
gh-broker operations list --family pull_request
gh-broker operations describe repo.visibility.update
```

### MCP server

`gh-broker mcp` runs unYOLO's shared strict stdio MCP server and Agent
Operations bridge, backed by the same catalog and broker credential.
`tools/list` advertises only the intersection of the client's
enabled operations, policy-visible operations, runtime capabilities, and the
operator exposure profile; the full catalog stays browsable through the paged
`github://operations` resource. Submissions accept an optional `request_id`
and return a durable operation immediately; recover after a disconnect with
`gh_operation_get`, `gh_operation_wait`, and `gh_operation_list`. Tokens and
other credentials remain sealed or slot-backed and never appear in tool
output.

GitHub retains only provider-specific selection, schemas, projections, API
execution, resource handling, and file-boundary decisions. JSON-RPC handling,
operation lifecycle utilities, sealed-payload upload, and bounded stream
transport are shared with the Hugging Face broker.

## Policy

`scope.json` is the authorization source of truth. A request is classified
into:

```text
client + operation + target + attrs -> allow | request | deny | no_match
```

Deny rules win over allow rules. A rule must match the authenticated client
and the complete operation target with every relevant attribute. If
a rule has attrs, every operation in that rule must support every attr; split
rules when operations need different attrs. Start from
[scope.example.json](scope.example.json).

The default production-oriented workflow is:

- allow fetch, repository listing, and content reads for scoped repositories
- allow agents to push namespaced feature branches such as
  `refs/heads/agent-a/**`; Git ref attributes use recursive path globs, so
  `**` includes nested branch names
- allow agents to open pull requests into `refs/heads/main`
- deny ref deletion and default-branch pushes unless a repository has an
  explicit allow rule
- classify existing branch updates as `git.push.force` unless the broker can
  prove fast-forward
- rely on GitHub rulesets or branch protections as the upstream enforcement
  layer after GitHub receives the pack

Example direct-main exception:

```json
{
  "id": "direct-main-example",
  "effect": "allow",
  "clients": ["agent-a"],
  "operations": ["git.push.force"],
  "targets": [{"kind": "repo", "owner": "osolmaz", "name": "direct-main"}],
  "attrs": {"refs": ["refs/heads/main"]}
}
```

Rules with `"effect": "request"` do not execute directly. Agent V1
submissions create a durable approval request as part of the operation, and
Git smart-HTTP pushes automatically create one bounded, idempotent approval
request. Git prints the approval ID and asks the caller to approve and retry;
repeating the same push while it is pending reuses the same request. Approval
creates a short-lived grant evaluated by the same policy path, and the next
identical push consumes it. Deny rules still win over approved grants.

Routine reusable repository operations default to a `1000000`-use grant and
allow up to seven days. Force pushes, ref deletions, and tag updates stay
capped at 25 uses for one hour. Execution grants stay single-use. These larger
use budgets never widen the approved client, operation, repository, ref, path,
or other attrs.

`POST /api/grants` remains the explicit protocol endpoint for clients that
need to request a Git grant before attempting a push.

## Broker routes

The agent listener exposes:

```text
GET  /healthz

POST /api/grants                         Git smart-HTTP protocol grant request
GET  /api/grants
GET  /api/grants/{id}

GET  /.well-known/unyolo-agent
POST /api/agent/v1/operations
GET  /api/agent/v1/operations/{id}
GET  /api/agent/v1/operations/{id}/events
POST /api/agent/v1/operations/{id}/cancel
POST /api/agent/v1/sealed-payloads
POST /api/agent/v1/streams
GET  /api/agent/v1/streams/{id}

GET  /{owner}/{repo}.git/info/refs
POST /{owner}/{repo}.git/git-upload-pack
POST /{owner}/{repo}.git/git-receive-pack
POST /{owner}/{repo}.git/info/lfs/objects/batch
*    /{owner}/{repo}.git/info/lfs/objects/*
*    /{owner}/{repo}.git/info/lfs/locks/*

POST /webhooks/github                    GitHub App webhooks
```

All discrete GitHub JSON operations use Agent V1; there are no direct
repository-list or contents proxy routes. The separate operator listener
exposes the shared operator inbox:

```text
GET  /api/operator/v1/requests
GET  /api/operator/v1/requests/{id}
GET  /api/operator/v1/events
POST /api/operator/v1/requests/{id}/approve
POST /api/operator/v1/requests/{id}/deny
POST /api/operator/v1/requests/{id}/revoke
```

Authenticate the operator listener with the separate credential from
`/etc/gh-broker/operator-secrets`. Agent credentials cannot use it. Telegram
is an optional notification view over the same durable request, so a decision
through either path closes the same state exactly once. GitHub supplies the
bounded operation and target along with its risk and warnings. It also supplies
generated projection facts. unYOLO renders the shared Telegram HTML, controls, callback
answers, and terminal states.

## Security model

Run gh-broker behind Tailnet-only or otherwise restricted reachability.
Network restrictions are transport controls. Every endpoint except `GET
/healthz` still requires its route-appropriate authentication. Agent
routes require the broker client secret, the operator listener requires the
separate operator credential, and the webhook route requires a verified
`X-Hub-Signature-256` payload signature.

For repo-scoped requests, gh-broker resolves the GitHub App installation for
the target repository and mints a short-lived token narrowed to the exact
repository and the catalog-derived minimum permission map, after broker
policy allows the request. Broader credentials are never reused for narrower
requests.

GitHub App webhooks at `POST /webhooks/github` require
`X-Hub-Signature-256`, `X-GitHub-Event`, and `X-GitHub-Delivery`, and are
verified against `GH_BROKER_GITHUB_WEBHOOK_SECRET_FILE`. Installation
suspension or deletion, repository selection changes, and
`github_app_authorization` revocation invalidate affected cached credentials
immediately. Invalid or unknown signed payloads fail closed.

Deployment safety settings:

- `GH_BROKER_AGENT_ENDPOINT` is required. Production setup uses a protected
  Unix socket unless the deployment explicitly selects TCP.
- `GH_BROKER_STATE_DIR` and `GH_BROKER_SCOPE_FILE` are required and must be
  absolute in production.
- `GH_BROKER_GITHUB_HTTP_TIMEOUT` defaults to 30 seconds;
  `GH_BROKER_GITHUB_STREAM_TIMEOUT` defaults to 600 seconds;
  `GH_BROKER_MAX_RECEIVE_PACK_BYTES` defaults to 25 MiB.
- `GH_BROKER_TELEGRAM_BOT_TOKEN_FILE` and `GH_BROKER_TELEGRAM_CHAT_ID` enable
  Telegram notifications. Telegram tokens are loaded only from protected
  files.
- Audit logs record the client and operation with its target, outcome, and
  matching rule IDs. They never include tokens, cookies, request bodies, PR bodies, pack
  contents, diffs, or any GitHub or Telegram credential material.

See [.env.example](.env.example) for the full annotated environment.

## Local development

From a unYOLO checkout:

```sh
cd brokers/github
cp .env.example .env
cp scope.example.json scope.json
install -m 600 /dev/null github-token
# write a development-only fine-grained token to github-token
# set GH_BROKER_SHARED_SECRET to a generated value with at least 32 bytes
# edit scope.json by hand
set -a; . ./.env; set +a
go run ./cmd/gh-broker
```

Run the tests with `go test ./...` from the repository root.

## License

[MIT](LICENSE)
