---
title: Verify host isolation
description: Verifying the isolation boundary, the shared building blocks, exit codes, and provider-specific probes.
---

Running a broker on the same host as the agent it serves is the common case and the easiest one to
get wrong. Every broker ships a `doctor` command that checks whether the host actually matches the
threat model, and it fails closed when it cannot establish that.

```sh
<broker> doctor
<broker> doctor isolation
```

The doctor does not make an unsafe setup safe. It tells you whether the boundary you think exists
is real.

## Exit codes

| Code | Meaning |
| --- | --- |
| `0` | OK |
| `1` | Unsafe |
| `2` | Inconclusive |
| `64` | Invalid arguments or configuration |

`2` deserves attention rather than dismissal. Inconclusive means a fact could not be established,
and a boundary you cannot verify is not a boundary you should rely on. On macOS the doctor is
deliberately conservative and reports facts it cannot establish as `unknown`, which makes the
overall result inconclusive rather than OK.

## Shared checks

The portable building blocks cover local account and supplementary-group lookup, root and
root-equivalent group detection, broker service and agent UID separation, secret-file type, mode,
path stability, and agent read and write access, and stable text and JSON reports.

The checks never read or print secret contents. A symbolic link or an access control list makes the
portable path check inconclusive, and an agent-writable or agent-owned path component makes it
unsafe. A credential path an agent could replace never receives an OK verdict, even when its
current contents are fine.

## Unsafe host conditions

The isolation doctor fails closed when the agent account is host root, is root-equivalent through
a group such as `sudo`, `wheel`, `admin`, `docker`, `lxd`, or `incus`, can read or modify the token
file, can read the broker's process environment, can write to or connect to the checked Unix
socket, or shares the broker's UID.

The `docker` group inclusion catches something people miss. Membership in `docker` is equivalent to
root on most hosts, because it allows mounting the host filesystem into a container. An agent in
that group can read the broker's token file no matter what its mode says.

## Running it

```sh
hf-broker doctor \
  --agent-user agent \
  --broker-pid "$(pgrep -x hf-broker)" \
  --token-file /etc/hf-broker/hf-token \
  --socket /run/brokerkit/huggingface/agent/broker.sock
```

With no agent identity flags supplied, the doctor checks the live doctor process instead. That is
useful for catching stale sessions still carrying old root-equivalent groups after an account was
demoted, because group membership changes do not apply to sessions that were already open.

Add `--json` for deployment checks. The `--token-file` value is never echoed in findings.

Supply every relevant installed path so the credential report is complete:

```sh
hf-broker doctor isolation \
  --token-file /etc/hf-broker/hf-token \
  --client-secrets-file /etc/hf-broker/secrets \
  --operator-secrets-file /etc/hf-broker/operator-secrets \
  --telegram-token-file /etc/hf-broker/telegram-bot-token
```

## Provider-specific probes

Each broker adds checks for its own domain.

`hf-broker` checks the Hugging Face token file, the local mirrors, and Git and LFS reachability,
plus a `doctor policy` subcommand that compares generated policy artifacts against the current
catalog:

```sh
hf-broker doctor policy \
  --profile /etc/hf-broker/policy-profile.json \
  --scope /etc/hf-broker/scope.json \
  --manifest /etc/hf-broker/policy-manifest.json
```

`gh-broker` checks the GitHub App configuration, installation token minting, the webhook secret,
ruleset visibility, repository access, and default-branch protection:

```sh
sudo gh-broker doctor github \
  --repo osolmaz/brokerkit \
  --agent-user agent-a \
  --service-user gh-broker
```

It reads `/etc/gh-broker/env` by default. Use `--env-file` for a nonstandard installation or
`--env-file ''` to use only the current process environment. When an env file is selected it is
authoritative, inline credential values are reported as inconclusive, and protected credential
files are required for a safe isolation verdict.

`sudo-broker` checks the command catalog, the target users, sudo, systemd, and launchd helper
permissions, the privileged socket, and execution backend safety:

```sh
sudo sudo-broker doctor host --agent agent-a
```

## Git configuration

Git-speaking brokers add a Git doctor that detects conflicting provider rewrites which would route
around the broker, a missing credential helper, and an unreachable listener:

```sh
hf-broker git doctor
gh-broker git doctor
gh-broker git status --json
```

## Host-level health

`brokerkit system doctor` adds the view across the whole managed host. It compares the activation
record, immutable artifact digests, native service state, process executable paths, and the active
bundle.

The host is unhealthy when an artifact digest changes, a required service is inactive, a process
executable differs from the immutable active release, a Linux executable is marked `(deleted)`, or
a rollback did not complete.

```sh
brokerkit system status --json
brokerkit system doctor --json
```

JSON output contains no provider credentials and no callback authority.

## Credential reporting

Every doctor report includes a `credentials` list covering the credential class, source kind,
installed age, expiry state, exact expiry where available, rotation state, and revocation mode. See
[credential lifecycle](/docs/guides/rotate-credentials) for what each value means and how rotation
works.
