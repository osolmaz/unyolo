---
title: Overview
description: Learn how unYOLO keeps provider credentials away from coding agents.
---

unYOLO is an access-control framework for coding agents. It keeps provider
credentials in separate broker processes and gives each agent only the
operations allowed by policy.

An agent can push its own branches and open pull requests without receiving a
GitHub token. The broker can refuse a force-push to `main`, reject access to an
unlisted repository, or wait for an operator before continuing.

Ready-to-run brokers cover GitHub and Hugging Face. `sudo-broker` applies the
same model to privileged Unix commands. You can also use the framework to put a
policy boundary in front of another provider.

## Credential problem

A GitHub personal access token describes what its owner may do across an
account. It does not describe the smaller job you wanted an agent to perform.
A token that can open a pull request may also be able to rewrite `main`, change
repository settings, or read unrelated private repositories.

The agent must also be able to read any token placed in its environment,
configuration, or `~/.netrc`. Once exposed there, the token can be printed,
copied, or used outside the intended workflow.

## Broker model

A broker runs under a separate account where the agent cannot inspect its
memory or credential files. The agent receives a broker-client secret that has
no meaning to the upstream provider. The broker classifies each request and
checks it against policy before using the provider credential.

```text
client request
        ↓
authenticate broker client
        ↓
classify request into client + operation + target + attrs
        ↓
policy decision: deny / active grant / allow / request / no_match
        ↓
optional operator approval grant
        ↓
provider-specific executor
        ↓
audit log
```

An unclassified request is refused, and an empty rules array denies everything.

Most of the request path is shared. Authentication, policy evaluation, grants,
approval records, and audit fields do not depend on the provider. The provider
adapter owns classification and execution.

## Included brokers

Each broker has its own process, listener, credential domain, state directory,
release artifact, and audit stream.

| Broker | Holds | Typical operations |
| --- | --- | --- |
| [`gh-broker`](/docs/brokers/github) | GitHub App credentials | Git traffic, contents reads, pull requests, and the GitHub APIs |
| [`hf-broker`](/docs/brokers/hugging-face) | A Hugging Face token | Git, LFS, repository operations, bucket objects, and Router inference |
| [`sudo-broker`](/docs/brokers/sudo) | The ability to act as another Unix user | One exact command from a root-owned catalog |

The `unyolo` host command activates signed runtime bundles and checks the
resulting processes. `unyolo-telegram` owns inbound Telegram updates when
several brokers share one bot. The [OpenClaw plugin](/docs/brokers/openclaw)
adds an approvals tab and broker skills.

## Protocols

Agents submit typed operations through Agent Operations V1. Operators use the
protected Operator V1 inbox to approve, deny, and revoke requests. OpenAPI
documents define both protocols, and checked-in Go and TypeScript artifacts
provide strict clients and validators.

Each endpoint reports its exact contract digest so peers can reject incompatible
artifacts before processing a request.

## Starting points

The [quickstart](/docs/get-started/quickstart) runs `gh-broker` against one
repository. The [security model](/docs/security/security-model) explains the
host boundary, and the [framework overview](/docs/build/framework) covers
custom brokers.
