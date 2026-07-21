---
name: gh-broker
description: Use BrokerKit for GitHub repositories, pull or merge requests, issues, reviews, comments, checks, workflows, releases, and other GitHub API operations when gh-broker is installed. Use instead of gh auth, GH_TOKEN, GITHUB_TOKEN, personal access tokens, or direct GitHub API credentials.
metadata:
  { "openclaw": { "emoji": "🔐", "requires": { "bins": ["gh-broker"] } } }
---

# GitHub Broker

Use `gh-broker` for GitHub API operations. BrokerKit keeps the upstream GitHub
credential inside the broker, so `gh auth status` may correctly report that no
GitHub host is authenticated.

## Authenticate to BrokerKit

The runtime normally provides `GH_BROKER_AGENT_ENDPOINT` and
`GH_BROKER_SHARED_SECRET`. If either is missing and the client file is
readable, load it before running broker commands:

```sh
. "$HOME/.config/gh-broker/client.env"
```

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
  --wait
```

Use a stable, task-specific `--request-id`. If a call is interrupted, recover
it instead of submitting the mutation again:

```sh
gh-broker operation get OPERATION-ID
gh-broker operation wait OPERATION-ID
gh-broker operation cancel OPERATION-ID
```

Never fall back to `gh api`, `curl api.github.com`, or an untyped proxy when a
broker operation is unavailable. Report the missing typed capability.

## Approvals and results

A pending response means policy requires operator approval; it does not mean
GitHub authentication failed. Preserve the operation ID and wait for or report
the decision. Do not bypass BrokerKit policy.

Treat broker results as the authoritative outcome. Before a destructive or
state-sensitive follow-up such as merge, ref deletion, or force push, re-read
the exact remote state and bind the operation to the identifiers required by
the catalog.
