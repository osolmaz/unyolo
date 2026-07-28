---
title: Broker Git traffic
description: Brokered Git, covering URL rewrites, the route-gated listener, LFS confinement, and approval mid-push.
---

Git is the surface where brokering has to be invisible. An agent that has to learn a special remote
URL or a wrapper command will get it wrong, so BrokerKit makes ordinary `git clone`, `git fetch`,
and `git push` route through the broker while remotes keep their normal provider URLs.

## Installing the integration

Run as the user whose Git configuration you are changing:

```sh
hf-broker git install
hf-broker git doctor
gh-broker git install
gh-broker git doctor
```

`git install` writes exact user-level `url.*.insteadOf` mappings plus a credential helper scoped to
the broker's listener origin. `setup client` deliberately does not do this; editing Git
configuration is a separate, explicit act.

Remotes stay as `https://huggingface.co/...` or `https://github.com/OWNER/REPO.git`, and they hold
no credential. The broker secret is supplied only by the scoped credential helper, and the
provider's real credential never leaves the broker.

## Treating Git config as untrusted

Installation validates what is already there. It rejects conflicting URL rewrites, owns the exact
values it writes, never stores an upstream credential, and fails closed when the broker listener or
helper is missing.

That last property matters more than it sounds. Broker-only mode never falls back to the provider,
so an unavailable broker produces a failed push rather than a push that quietly went direct with
whatever credential Git could find.

Two commands help you see and undo the state:

```sh
gh-broker git status --json
gh-broker git uninstall
```

`uninstall` removes only that exact provider installation and leaves any other broker's
configuration alone.

## The Git listener

The Git data plane is a separate, explicitly deployment-selected TCP endpoint. BrokerKit defines no
default port, and the deployment persists the one it chose. Standard Git clients need TCP, which is
why this listener cannot be a Unix socket like the agent and operator listeners.

Its route gate is independent of the agent router and exposes only an authenticated identity
handshake plus provider-approved smart-HTTP and LFS routes:

```text
GET  /{owner}/{repo}.git/info/refs
POST /{owner}/{repo}.git/git-upload-pack
POST /{owner}/{repo}.git/git-receive-pack
POST /{owner}/{repo}.git/info/lfs/objects/batch
*    /{owner}/{repo}.git/info/lfs/objects/*
*    /{owner}/{repo}.git/info/lfs/locks/*
```

Agent operations, grants, webhooks, browser sessions, credential lifecycle routes, and operator
routes all return not found here. A Git endpoint cannot be turned into a broad agent API, even by a
client that knows the other paths.

Credentials are scoped to the exact loopback listener origin, so the helper does not offer the
broker secret to anything else.

## Classifying a push

A receive-pack request is one authorization transaction. Every ref update in the body is classified
before a single byte goes upstream.

`hf-broker` accepts a push only when all of its ref updates are append-only: fast-forwards, new
branches, or new tags. Ancestry is verified against a local commits-only mirror created with
`--filter=tree:0`, so the check stays cheap even for very large repositories. `gh-broker`
classifies an existing branch update as `git.push.force` unless it can prove the update is a
fast-forward, which is the conservative direction.

A deny rejects the whole batch. Requestable refs produce one approval bound to the exact body
digest and the ordered command set. Atomic and multi-ref pushes are never split into separately
authorized updates, so there is no state where half a push landed.

Refused pushes never leave the broker, and the reason reaches the terminal:

```text
 ! [remote rejected] main -> main (hf-broker: history rewrite refused)
```

## Waiting for approval mid-push

When a push needs approval, the original HTTP request stays open. One durable approval covers the
complete ordered transaction, and approval resumes that same `git push` rather than asking the user
to run it again.

While waiting, the broker releases the provider lock, then reacquires it and reclassifies the exact
transaction before forwarding the unchanged body. Without that release, a single pending approval
would block every other push to the repository.

Denial, expiry, cancellation, or changed upstream state returns an ordinary Git failure and
forwards nothing. On `gh-broker`, Git prints the approval ID and asks the caller to approve and
retry; repeating the same push while it is pending reuses the same request rather than filling the
inbox with duplicates.

## LFS confinement

Upstream LFS action URLs and headers stay inside the broker. Supported LFS actions are rewritten to
broker-local capabilities. Each one is random and expiring, and it is bound to the client,
repository, path, method, and policy. A signed provider URL never crosses the trust boundary, so
it cannot be captured from a response and replayed directly against the provider.

Hugging Face Xet negotiation is refused before any signed action is returned. Enabling it would
require exporting the Hub token to the client side, so it fails closed until the custom transfer
can satisfy the same confinement and conformance requirements.

## Diagnosing problems

`git doctor` is the first command to run when Git behaves unexpectedly. It detects conflicting
provider rewrites that would route around the broker, a missing helper, and an unreachable
listener.

Native Git discovery, upload-pack, receive-pack, and LFS requests emit the provider's normal policy
and proxy audit records, so the audit stream shows what was classified and why. The Git listener's
identity response contains only the provider ID. Credential-helper input and output are never
logged, and neither are Basic credentials.

## Writing ref policy

Ref attributes use recursive path globs, so `**` crosses `/`. A rule allowing
`refs/heads/agent-a/**` covers `refs/heads/agent-a/parser-fix` and nested names below it.

The pattern that works well in practice is to give each agent a branch namespace it owns, allow
fast-forward pushes there, and require approval or deny outright for the default branch:

```json
{
  "id": "agent-a-push-own-branches",
  "effect": "allow",
  "clients": ["agent-a"],
  "operations": ["git.push.fast_forward"],
  "targets": [{ "kind": "repo", "owner": "osolmaz", "name": "brokerkit" }],
  "attrs": { "refs": ["refs/heads/agent-a/**"] }
}
```

Keep GitHub rulesets or branch protections in place as the upstream enforcement layer. The broker
decides what it forwards; the provider still decides what it accepts.
