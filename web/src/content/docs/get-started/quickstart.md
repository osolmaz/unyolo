---
title: Quickstart
description: Run gh-broker locally and test an allowed push and a refused force-push.
---

This ten-minute guide runs `gh-broker` in development mode against one repository. You will push an
allowed branch, then confirm that the broker refuses a force-push to `main` before it reaches GitHub.

<div class="callout callout--warn">
<span class="callout__title">Development mode only</span>
<p>Development mode runs the broker as your own user with the credential in your environment, which
means the isolation boundary does not hold. It is fine for learning the model and wrong for
anything real. Use <a href="/docs/deploy/systemd">service setup</a> for a deployment.</p>
</div>

## Before you start

You need Go matching the version in `go.mod`, a GitHub account, and a repository you do not mind
pushing branches to. Create a fine-grained personal access token with contents and pull request
write access to just that repository. Production uses a GitHub App instead, but a scoped token
keeps this walkthrough short, and the narrow scope limits the blast radius of the exercise.

## Install the binary

Build from a checkout:

```sh
git clone https://github.com/osolmaz/unyolo
cd unyolo
go install ./brokers/github/cmd/gh-broker
```

For a real installation you would use the release installer instead, which verifies checksums and
GitHub build attestations. See [installation](/docs/get-started/installation).

## Write a policy

The broker refuses anything it cannot match, so the rules file comes first. Create `scope.json` in
the directory you will run from, replacing the owner and name with your repository:

```json
{
  "rules": [
    {
      "id": "agent-a-read-and-branch",
      "effect": "allow",
      "clients": ["agent-a"],
      "operations": ["contents.read", "git.fetch", "git.push.fast_forward"],
      "targets": [{ "kind": "repo", "owner": "YOUR-USER", "name": "YOUR-REPO" }],
      "attrs": { "refs": ["refs/heads/agent-a/**"] }
    },
    {
      "id": "agent-a-open-pull-requests",
      "effect": "allow",
      "clients": ["agent-a"],
      "operations": ["pull_request.create"],
      "targets": [{ "kind": "repo", "owner": "YOUR-USER", "name": "YOUR-REPO" }]
    }
  ]
}
```

The first rule permits reads, fetches, and fast-forward pushes, but only to branches under
`refs/heads/agent-a/`. Ref attributes use recursive path globs, so `**` covers nested names like
`agent-a/fix/parser`. The second rule lets the agent open pull requests.

Notice what is absent. There is no rule for `refs/heads/main` and no rule for `git.push.force`, so
both are denied by default. Every other repository in your account is denied too, because nothing
names it.

## Start the broker

Development mode needs an explicit endpoint. A port of `0` asks the OS to pick a free one, and the
broker prints the resolved endpoint in its readiness record.

```sh
export GH_BROKER_ENVIRONMENT=development
export GH_BROKER_AGENT_ENDPOINT=tcp://127.0.0.1:0
export GH_BROKER_GIT_ENDPOINT=tcp://127.0.0.1:0
export GH_BROKER_GITHUB_TOKEN_FILE=$PWD/github-token
export GH_BROKER_SHARED_SECRET=$(openssl rand -hex 32)
export GH_BROKER_SCOPE_FILE=$PWD/scope.json
export GH_BROKER_STATE_DIR=$PWD/state

install -m 600 /dev/null github-token
# write your fine-grained token into ./github-token
go run ./cmd/gh-broker
```

`GH_BROKER_SHARED_SECRET` is what your client authenticates with. It carries no GitHub authority at
all, so leaking it costs you the operations your policy allows and nothing more. The token file is
the real credential, and it stays server-side.

Note the agent and Git endpoints the broker prints.

## Point Git at the broker

In a second terminal, write the client config and install the Git integration for your user:

```sh
gh-broker setup client \
  --client agent-a \
  --endpoint tcp://127.0.0.1:<agent-port> \
  --git-endpoint tcp://127.0.0.1:<git-port> \
  --home-dir "$HOME"

gh-broker git install
gh-broker git doctor
```

`git install` writes exact `url.*.insteadOf` rewrites and a credential helper scoped to that
listener origin. Your remotes stay ordinary `https://github.com/...` URLs and hold no credential.
`git doctor` refuses to report success if some other rewrite already routes GitHub traffic
elsewhere.

## Push a branch

Clone the repository and push a branch in the namespace the policy allows:

```sh
git clone https://github.com/YOUR-USER/YOUR-REPO
cd YOUR-REPO
git switch -c agent-a/parser-fix
echo "one" >> notes.txt && git add -A && git commit -m "Add a line"
git push -u origin agent-a/parser-fix
```

That goes through. The broker classified it as `git.push.fast_forward` on
`refs/heads/agent-a/parser-fix`, matched the first rule, and forwarded the pack with a credential
your Git client never saw.

Open a pull request through the typed operation API:

```sh
gh-broker operation submit pull_request.create \
  --target-json '{"kind":"repo","owner":"YOUR-USER","name":"YOUR-REPO"}' \
  --arguments-json '{"title":"Parser fix","head":"agent-a/parser-fix","base":"main"}' \
  --wait
```

## Watch a push get refused

Now try the things the policy does not cover. Pushing to the default branch:

```sh
git switch main
echo "two" >> notes.txt && git commit -am "Direct to main"
git push
```

And rewriting history:

```sh
git commit --amend -m "Rewrite"
git push --force
```

Both are refused at the broker, and neither reaches GitHub:

```text
 ! [remote rejected] main -> main (gh-broker: no matching rule)
```

The broker parsed the receive-pack body, classified each ref update, found no rule covering
`refs/heads/main`, and stopped. Nothing was forwarded.

## Add an approval path

Refusing outright is the right default for `main`, but sometimes you want the operation available
with a human in the loop. Add a `request` rule to `scope.json` and restart the broker:

```json
{
  "id": "request-force-push-to-main",
  "effect": "request",
  "clients": ["agent-a"],
  "operations": ["git.push.force"],
  "targets": [{ "kind": "repo", "owner": "YOUR-USER", "name": "YOUR-REPO" }],
  "attrs": { "refs": ["refs/heads/main"] },
  "grant_policy": {
    "mode": "window",
    "default_minutes": 5,
    "max_minutes": 10,
    "default_max_uses": 1,
    "max_uses": 1
  }
}
```

Retry the force push. This time the broker creates a durable approval request, prints its ID, and
holds the push rather than refusing it. Approve it from another terminal with the operator
credential the broker printed at startup:

```sh
curl -sS -X POST \
  -H "Authorization: Bearer $OPERATOR_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"expected_revision": 1, "idempotency_key": "quickstart"}' \
  http://127.0.0.1:<operator-port>/api/operator/v1/requests/<request-id>/approve
```

The waiting push resumes and completes. Try it a second time and it is refused again: the grant
covered one use of one operation on one ref of one repository, and it is now spent.

## Recap

Your Git client never held a GitHub token. The broker classified each push before forwarding
anything, allowed the branch push its policy covered, refused the two it did not, and accepted the
force push only after a human approved a grant bounded to that exact ref for five minutes and one
use. Every one of those decisions is in the audit stream with the rule IDs that matched, and none
of the records contain the token, the pack, or the commit contents.

## Next steps

Read [write a policy](/docs/guides/write-a-policy) to understand attrs and matcher semantics, which
is where most of the useful narrowing lives. When you are ready to run this properly,
[installation](/docs/get-started/installation) covers verified releases and
[systemd and launchd](/docs/deploy/systemd) covers service setup with a GitHub App, a dedicated
account, and separate agent and operator sockets.
