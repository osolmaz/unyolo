---
title: gh-broker
description: Give agents policy-controlled Git and GitHub API access without giving them a GitHub credential.
---

`gh-broker` is a GitHub credential broker for coding agents. It gives an agent a broker secret,
keeps the real GitHub credential server-side, and allows only the Git and GitHub API operations
that `scope.json` matches.

`gh-broker` never returns the original GitHub credential through an API, log, error, or helper.
Callers choose an operation and a target. They cannot choose a credential kind, token scope,
installation, or permission set.

## Install

```sh
curl -fsSL https://unyolo.io/install.sh | sh
```

Pin a release with `VERSION=<version>` or choose a directory with `INSTALL_DIR=/absolute/path`.

## Production setup

Production uses GitHub App credentials. Create the App, collect its ID, private key, and webhook
secret as protected files, then run:

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

Setup writes protected files under `/etc/gh-broker` (`secrets`, `operator-secrets`, the GitHub
credential files, `scope.json`, and `env`), installs the systemd unit and sockets, and starts the
service. It never places broker client secrets, operator secrets, GitHub credentials, or Telegram
credentials directly in the env file. The agent and operator APIs use distinct Unix sockets by
default.

Omitting `--scope-file` installs the managed `request-all-agent-operations` preset instead. Add
repeatable `--deny-operation <exact-name>` flags to disable operations, and `--replace-policy` to
overwrite an installed policy after reviewing the printed digest and operation-count preview. macOS
uses `gh-broker setup launchd` with the same flags.

To enable encrypted GitHub App user credentials, add the App's OAuth client files and the GitHub
account ID:

```sh
sudo gh-broker setup systemd \
  --github-app-id-file ./app-id \
  --github-app-private-key-file ./private-key.pem \
  --github-app-client-id-file ./client-id \
  --github-app-client-secret-file ./client-secret \
  --github-user-id 1234 \
  --github-webhook-secret-file ./webhook-secret \
  --scope-file ./scope.json \
  --client agent-a --operator operator-a \
  --agent-user agent-a --operator-user operator-a
```

Add Telegram with `--telegram-bot-token-file ./telegram-bot-token` and
`--telegram-chat-id 123456789`. Run the separate `unyolo-telegram` ingress to receive button
decisions, so provider services never compete for the shared bot's update offset.

### Development token fallback

For local development only, a fine-grained token in a protected file can replace the GitHub App:

```sh
sudo gh-broker setup systemd \
  --dev-token-fallback \
  --github-token-file ./github-token \
  --scope-file ./scope.json \
  --client agent-a --operator operator-a \
  --agent-user agent-a --operator-user operator-a
```

This fallback is protected-file-only and non-production. `doctor github` returns an unsafe result
if it is selected with `GH_BROKER_ENVIRONMENT=production`, and inline PAT configuration is
rejected outright.

## Client and Git setup

```sh
sudo gh-broker setup client \
  --client agent-a \
  --endpoint unix:///run/unyolo/github/agent/broker.sock \
  --git-endpoint tcp://127.0.0.1:38471 \
  --secret-file /etc/gh-broker/secrets \
  --home-dir /home/agent-a

gh-broker git install
gh-broker git doctor
```

The generated `~/.config/gh-broker/client.json` holds the client identity, broker endpoints, and
broker client secret. It contains no GitHub credentials.

After `git install`, ordinary `https://github.com/OWNER/REPO.git` and GitHub SSH-form remotes use
the broker for clone, fetch, pull, push, and Git LFS. LFS signed URLs and headers stay in the
broker and are replaced by bounded broker-local actions. `gh-broker git status --json` reports the
owned configuration, and `gh-broker git uninstall` removes only that exact provider installation.

## Credential minting

For a repo-scoped request, `gh-broker` resolves the GitHub App installation for the target
repository and mints a short-lived token narrowed to that exact repository and the catalog-derived
minimum permission map, *after* broker policy allows the request. Broader credentials are never
reused for narrower requests.

### Enrolling a user credential

Some operations need a GitHub user identity rather than an installation. Enroll an expiring GitHub
App user credential from a local operator shell while the broker is stopped. The state directory
must already exist with the broker service user's ownership, and the input is a mode `0600` JSON
file the operator deletes afterwards:

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

Use `rotate` with a replacement file to rotate, and `github-user revoke --user-id 1234` to revoke
immediately. These commands return only the action and the immutable user ID. There is no
credential readback command and no API route for one. Enrolled credentials live only in unYOLO's
encrypted credential store and refresh before expiry.

## The operation catalog

The operation surface is generated from pinned GitHub REST and GraphQL definitions into a typed
catalog:

```sh
gh-broker operations list --family pull_request
gh-broker operations describe repo.visibility.update
```

The full catalog is also browsable in `docs/generated/CAPABILITIES.md` in the repository.

Discrete operations use the typed Agent V1 CLI, which loads the client config automatically:

```sh
gh-broker operation submit repo.contents.read \
  --target-json '{"kind":"repo","owner":"osolmaz","name":"unyolo"}' \
  --arguments-json '{"path":"README.md","ref":"main"}' \
  --wait

gh-broker operation submit pull_request.create \
  --target-json '{"kind":"repo","owner":"osolmaz","name":"unyolo"}' \
  --arguments-json '{"input":{"title":"agent work","head":"agent-a/work","base":"main","body":"Ready for review."}}' \
  --reason "Open the reviewed feature branch" \
  --request-id open-agent-pr \
  --wait
```

Reuse a stable `--request-id` when retrying, and resume interrupted operations with
`gh-broker operation get|wait|cancel <id>`. When an operation is not terminal, the CLI says that
the requested action is not complete and prints the exact wait command for the same ID. Do not
report completion until the operation is `succeeded`. All discrete GitHub JSON operations go
through Agent V1; there are no direct repository-list or contents proxy routes.

## Admin merge

`pull_request.merge_admin` mirrors the direct merge path `gh pr merge --admin` selects. It uses the
GitHub user identity the broker already holds. There is no separate admin credential and no
caller-supplied `admin` flag sent to GitHub.

```sh
gh-broker operation submit pull_request.merge_admin \
  --target-json '{"kind":"pull_request","owner":"osolmaz","repo":"unyolo","number":123}' \
  --arguments-json '{"merge_method":"squash"}' \
  --reason "Merge the reviewed pull request despite its remaining GitHub requirement" \
  --request-id admin-merge-unyolo-123 \
  --wait
```

Reach for this only when GitHub itself is what stands in the way. If you want an agent that cannot
merge unless you say so, the control point is your own policy: give `pull_request.merge` a `request`
rule and the agent's merge stops at `pending` until you approve it, with the branch protection on
`main` left intact. Admin merge is for the narrower case where the merge must go through despite a
GitHub requirement that will not be satisfied, and it is a bypass, so treat it as one.

Admin merge is a distinct high-risk, explicit operation and requests operator approval by default.
Its request rule uses a reusable window unless policy selects exact, single-use execution mode.
unYOLO resolves the pull request itself, binds each invocation to the exact head commit, rechecks
it before execution, and supplies it to GitHub as the mutation's atomic `expectedHeadOid` guard.
A changed pull request must be submitted again. A matching active window may authorize its fresh
plan; execution mode requires a new operator decision.

Administrator privileges may bypass review, update, or merge-queue requirements. They do not bypass
merge conflicts.

## Policy

`scope.json` classifies every request into
`client + operation + target + attrs -> allow | request | deny | no_match`. Deny rules win over
allow rules. A rule matches only when it matches the client, operation, target, and
operation-relevant attributes together. If a rule has attrs, every operation in that rule must
support every attr, so split rules when operations need different attrs.

The default production-oriented workflow looks like this:

- Allow fetch, repository listing, and content reads for scoped repositories.
- Allow agents to push namespaced feature branches such as `refs/heads/agent-a/**`. Git ref
  attributes use recursive path globs, so `**` includes nested names.
- Allow agents to open pull requests into `refs/heads/main`.
- Deny ref deletion and default-branch pushes unless a repository has an explicit allow rule.
- Classify an existing branch update as `git.push.force` whenever fast-forward cannot be proven.
- Keep GitHub rulesets or branch protections as the upstream enforcement layer after GitHub
  receives the pack.

A direct-main exception looks like this:

```json
{
  "id": "direct-main-example",
  "effect": "allow",
  "clients": ["agent-a"],
  "operations": ["git.push.force"],
  "targets": [{ "kind": "repo", "owner": "osolmaz", "name": "direct-main" }],
  "attrs": { "refs": ["refs/heads/main"] }
}
```

Rules with `"effect": "request"` do not execute directly. Agent V1 submissions create a durable
approval as part of the operation, and Git smart-HTTP pushes automatically create one bounded,
idempotent approval request. Git prints the approval ID and asks the caller to approve and retry;
repeating the same push while it is pending reuses the same request. Approval creates a short-lived
grant evaluated by the same policy path, and the next identical push consumes it.

Every requestable operation defaults to a reusable window. A request rule can instead require an
exact approval for each operation:

```json
"grant_policy": {
  "mode": "execution",
  "default_minutes": 5,
  "max_minutes": 5,
  "request_ttl_minutes": 5,
  "default_max_uses": 1,
  "max_uses": 1
}
```

## Routes

The agent listener exposes:

```text
GET  /healthz

POST /api/grants
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

POST /webhooks/github
```

The separate operator listener exposes the shared inbox routes, authenticated with the credential
in `/etc/gh-broker/operator-secrets`. Agent credentials cannot use it.

## MCP

`gh-broker mcp` runs the shared strict stdio MCP server and Agent Operations bridge, backed by the
same catalog and broker credential. `tools/list` advertises only the intersection of the client's
enabled operations, policy-visible operations, runtime capabilities, and the operator exposure
profile. The full catalog stays browsable through the paged `github://operations` resource.

Submissions accept an optional `request_id` and return a durable operation immediately. Recover
after a disconnect with `gh_operation_get`, `gh_operation_wait`, and `gh_operation_list`. Tokens
and other credentials stay sealed or slot-backed and never appear in tool output.

## Error sanitization

unYOLO parses GitHub's documented error `message` fields, removes control characters, redacts
credential-like values, and limits the text before returning it to the requesting client. Raw
response bodies, GraphQL paths, and extensions are not retained. Sealed operations omit provider
messages entirely, because GitHub may echo request values back.

The practical effect is that a durable operation can report something useful like a disabled merge
method, while machine behaviour continues to use validated codes, HTTP status, and request IDs.

## Webhooks

`POST /webhooks/github` requires `X-Hub-Signature-256`, `X-GitHub-Event`, and `X-GitHub-Delivery`,
verified against `GH_BROKER_GITHUB_WEBHOOK_SECRET_FILE`. Installation suspension or deletion,
repository selection changes, and `github_app_authorization` revocation invalidate affected cached
credentials immediately. Invalid or unknown signed payloads fail closed.

## Verify the deployment

```sh
sudo gh-broker doctor github \
  --repo osolmaz/unyolo \
  --agent-user agent-a \
  --service-user gh-broker
```

Doctor checks local isolation, the GitHub App configuration, repository access, and default-branch
protection. Use `--json` for machine-readable output. Exit codes are `0` safe, `1` unsafe, `2`
inconclusive, and `64` invalid invocation or configuration.

Doctor reads `/etc/gh-broker/env` by default; use `--env-file` for a nonstandard installation or
`--env-file ''` to use only the current process environment. When an env file is selected it is
authoritative, and inline credential values are reported as inconclusive. Protected credential
files are required for a safe isolation verdict.

## Deployment settings

Run `gh-broker` behind Tailnet-only or otherwise restricted reachability, but treat network access
as transport rather than authorization. Every endpoint except `GET /healthz` requires its
route-appropriate authentication.

- `GH_BROKER_AGENT_ENDPOINT` is required. Production setup uses a protected Unix socket unless the
  deployment explicitly selects TCP.
- `GH_BROKER_STATE_DIR` and `GH_BROKER_SCOPE_FILE` are required and must be absolute in production.
- `GH_BROKER_GITHUB_HTTP_TIMEOUT` defaults to 30 seconds, `GH_BROKER_GITHUB_STREAM_TIMEOUT` to 600
  seconds, and `GH_BROKER_MAX_RECEIVE_PACK_BYTES` to 25 MiB.
- Telegram tokens load only from protected files.

Audit logs record client, operation, target, outcome, and matched rule IDs. They never include
tokens, cookies, request bodies, pull request bodies, pack contents, diffs, or any GitHub or
Telegram credential material.
