---
title: Overview
description: What unYOLO is, the problem it solves, and how its pieces fit together.
---

unYOLO is a Go framework for building credential brokers. A broker is a small service that holds
a real credential, GitHub App keys, a Hugging Face token, or the ability to act as another Unix
user, and hands an untrusted client a separate credential that works only for the operations you
allowed.

The point is to let a coding agent do useful work in your own accounts without giving it the
credential that would let it destroy something. An agent can push to its own branches and open pull
requests, while the same credential cannot force-push over `main`, delete a repository, or read the
repositories you did not list.

Three brokers ship ready to run, and they are consumers of the framework rather than the whole of
it. If you need the same boundary in front of an internal API key or a cloud role, you write the
provider-specific parts and inherit everything else.

## The problem

A GitHub personal access token is scoped to your account, not to the job you wanted done. Give one
to an agent so it can open a pull request, and you have also given it the ability to force-push
over `main`, delete branches, change repository visibility, and read every private repository you
can read. Hugging Face write tokens and `sudoers` entries have the same shape. The credential
matches your identity, and the thing you meant to delegate was one operation on one target.

Handing that credential to the agent also puts it somewhere the agent can reach. It ends up in an
environment variable, a config file, or a `~/.netrc`, all of which the agent can read and echo.
Rotating it afterwards means rotating something your other tools depend on.

## The broker answer

The broker runs as a separate process under its own account, where the agent cannot inspect its
memory or read its credential files. The agent gets a broker-client secret that is worth nothing to
GitHub. Every request it makes is classified and checked against a policy file before the broker
spends the real credential on its behalf.

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

Requests the policy cannot classify are refused. There is no permissive default, and an empty rules
array is a valid deny-all policy.

The property that makes this reusable is where provider knowledge sits. Authentication, policy
evaluation, grant lifecycle, the approval workflow, and audit formatting are shared code with no
idea what a GitHub pull request is. Classification and execution are the only stages that know, and
they live in the provider's own directory.

## Included brokers

Each broker is a separate process with its own listener, credential domain, state directory,
release artifact, and audit stream, so one cannot reach another's credentials.

| Broker | Holds | Typical operations |
| --- | --- | --- |
| [`gh-broker`](/docs/brokers/github) | GitHub App credentials | Git traffic, contents reads, pull requests, the wider REST and GraphQL catalog |
| [`hf-broker`](/docs/brokers/hugging-face) | A Hugging Face token | Git and LFS traffic, repository reads and writes, bucket objects, Router inference |
| [`sudo-broker`](/docs/brokers/sudo) | The ability to act as another Unix user | One exact command from a root-owned catalog |

Alongside them sit the `unyolo` host command, which activates signed immutable runtime bundles
and verifies the resulting processes, the `unyolo-telegram` ingress that owns inbound updates
when several brokers share one bot, and an [OpenClaw plugin](/docs/brokers/openclaw) that adds an
approvals tab and client skills to that agent host.

## Protocols

Agent Operations V1 is the authenticated surface agents submit typed operations to. Operator V1 is
the protected inbox you use to approve, deny, and revoke. Both are defined by OpenAPI documents,
with generated Go and TypeScript artifacts checked in, and both expose an exact contract digest so
a client can detect drift without guessing from a version label.

## Further reading

Start with the [quickstart](/docs/get-started/quickstart) if you want `gh-broker` running against
one repository in the next few minutes. Read [why unYOLO](/docs/get-started/why-unyolo) if
you first want to know what it refuses to do, which is often the faster way to decide whether it
fits.

If you are evaluating this for a host that already has agents on it, the
[security model](/docs/security/security-model) and the
[threat model](/docs/security/threat-model) are the two pages worth reading before anything else.
If you came here to broker something other than the three shipped providers, start at the
[framework overview](/docs/build/framework).
