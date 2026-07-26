---
name: gh-broker
description: Use BrokerKit for GitHub repositories, pull requests, explicit administrator merges, issues, reviews, comments, checks, workflows, releases, and other GitHub API operations when gh-broker is installed. Use instead of gh auth, GH_TOKEN, GITHUB_TOKEN, personal access tokens, or direct GitHub API credentials.
metadata:
  { "openclaw": { "emoji": "🔐", "requires": { "bins": ["gh-broker"] } } }
---

# GitHub Broker

Use `gh-broker` for GitHub API operations. BrokerKit keeps the upstream GitHub
credential inside the broker, so `gh auth status` may correctly report that no
GitHub host is authenticated.

## Authenticate to BrokerKit

`gh-broker` loads its private client V1 document directly from
`~/.config/gh-broker/client.json`. Do not source it or copy its credential into
the environment. Environment configuration is only for isolated development.

Do not run `gh auth login`, request a personal access token, read protected
service credentials, or set `GH_TOKEN` or `GITHUB_TOKEN`.

## Git transport

Use ordinary Git URLs and commands for clone, fetch, pull, push, and Git LFS.
The installed Git configuration and scoped credential helper route them through
the broker:

```sh
git clone https://github.com/OWNER/REPO.git
git fetch origin
git push origin HEAD
```

If routing is in doubt, run `gh-broker git doctor`. Do not replace the remote
with a broker-local URL.

## Typed GitHub operations

Use Agent V1 for issues, pull requests, reviews, comments, repository metadata,
checks, workflows, and other GitHub API operations:

```sh
gh-broker operations list --family pull_request
gh-broker operations describe pull_request.create
```

Inspect an operation before guessing its target or argument fields. Submit only
typed operations exposed by the catalog:

```sh
gh-broker operation submit pull_request.create \
  --target-json '{"kind":"repo","owner":"OWNER","name":"REPO"}' \
  --arguments-json '{"title":"TITLE","head":"BRANCH","base":"main","body":"BODY"}' \
  --reason "Open the reviewed branch" \
  --request-id STABLE-REQUEST-ID \
  --wait \
  --wait-timeout 15m
```

Use `--wait` for agent-driven work so the command stays attached until the
operation finishes or the wait timeout expires. A timeout can leave the
operation pending. Keep its ID and resume the same operation.

Approval waiting is part of the same agent turn. Do not return control to the
user while the operation remains pending. If a wait interval expires,
immediately wait again with the same operation ID. Continue until the user
clicks or otherwise records a decision and the operation reaches a terminal
state. Stop only for a terminal result, an explicit user cancellation, or an
unrecoverable broker error.

Use a stable, task-specific `--request-id`. If a call is interrupted, recover
it instead of submitting the mutation again:

```sh
gh-broker operation get OPERATION-ID
gh-broker operation wait --wait-timeout 15m OPERATION-ID
gh-broker operation cancel OPERATION-ID
```

Never fall back to `gh api`, `curl api.github.com`, or an untyped proxy when a
broker operation is unavailable. Report the missing typed capability.

## Administrator merges

Use `pull_request.merge` for an ordinary merge. A failed ordinary merge does
not authorize a stronger retry. Report review requirements, branch protection,
and other safe diagnostics returned by the broker.

`pull_request.merge_admin` is an explicit-only, high-risk operation. Submit it
only when the user specifically asks to merge with administrator privileges or
to bypass a named protection after seeing the blocker:

```sh
gh-broker operations describe pull_request.merge_admin
gh-broker operation submit pull_request.merge_admin \
  --target-json '{"kind":"pull_request","owner":"OWNER","repo":"REPO","number":123}' \
  --arguments-json '{"merge_method":"squash"}' \
  --reason "Bypass the required review for this approved pull request revision" \
  --request-id STABLE-REQUEST-ID \
  --wait \
  --wait-timeout 15m
```

The broker binds approval to the authenticated GitHub user, pull request node,
current head commit, merge method, and one use. A changed head requires a new
request and a new operator decision. Do not ask for a raw GitHub token or add a
head SHA to the arguments.

If execution reports an unknown upstream result, recover the existing
operation and re-read the pull request. Do not submit another merge with a new
request ID.

## Approvals and results

A pending response means policy requires operator approval; it does not mean
GitHub authentication failed. Preserve the operation ID and keep waiting for the
decision without ending the agent turn. Do not bypass BrokerKit policy.

Treat broker results as the authoritative outcome. Before a destructive or
state-sensitive follow-up such as merge, ref deletion, or force push, re-read
the exact remote state and bind the operation to the identifiers required by
the catalog.
