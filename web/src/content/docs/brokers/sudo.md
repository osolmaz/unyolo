---
title: sudo-broker
description: The Unix privilege broker, its exact cataloged commands, the root helper, and the V1 boundary.
---

`sudo-broker` is a privileged-command broker for Unix hosts. It lets an authenticated local agent
request and run one exact, operator-approved command as another Unix user. Commands come from a
root-owned catalog. It does not accept shell strings, arbitrary executables, interactive shells,
TTYs, stdin, or caller-controlled environment variables.

The protected resource is different from the two credential brokers, but the control-plane shape is
identical:

```text
client
  ↓
unyolo auth
  ↓
sudo-broker classifier
  ↓
unyolo policy and grants
  ↓
approval channel
  ↓
sudo-broker executor
  ↓
target Unix user
```

## Two processes

The runtime is split so that the network-facing part is unprivileged:

`sudo-broker` is an unprivileged HTTP frontend using unYOLO policy, grants, Operator V1, and
optional Telegram approval. `sudo-broker-exec` is a root helper reachable only through a private
Unix socket, and only by the dedicated frontend account.

The frontend never gains privilege. It asks the helper to run a cataloged command, and the helper
performs the identity transition.

## Install

```sh
curl -fsSL https://unyolo.io/install.sh | sh -s sudo
```

The frontend goes into the selected binary directory. The helper goes into the adjacent `libexec`
directory and is deliberately kept off ordinary user command paths.

## The command catalog

The catalog is the security-relevant file. It fixes each command's exact executable, arguments,
target users, timeout, and output limit. Start from `catalog.example.json` and read
`docs/catalog.md` in the repository for the authoring rules.

Because the catalog names the executable and the argument shape, an agent asking for
`restart-myapp` cannot smuggle extra arguments, redirect output, or chain another command. Typed
argument slots are the only variable part, and each slot is validated and normalized before it
reaches the helper.

## Configure on Linux

Write the catalog and policy, then run setup:

```sh
sudo sudo-broker setup systemd \
  --catalog-file ./catalog.json \
  --policy-file ./policy.json \
  --client agent-a \
  --operator operator-a \
  --agent-user agent-a \
  --operator-user operator-a
```

Setup generates independent client and operator secrets, installs a root helper unit and an
unprivileged frontend unit, and starts them in dependency order. Use `--no-start` to write the
configuration without enabling it, or `--dry-run` to validate and print the unit shape without
changing the host.

Write a client config for the agent account:

```sh
sudo sudo-broker setup client \
  --client agent-a \
  --endpoint unix:///run/unyolo/sudo/agent/broker.sock \
  --secret-file /etc/sudo-broker/secrets \
  --home-dir /home/agent-a
```

Then verify host isolation and helper readiness:

```sh
sudo sudo-broker doctor host --agent agent-a
```

## Policy vocabulary

V1 has a deliberately tiny vocabulary.

| Operation | Meaning |
| --- | --- |
| `exec.command` | Run one declared command as a target user. |

| Target kind | Meaning |
| --- | --- |
| `user` | A local Unix user. |

| Attr | Meaning |
| --- | --- |
| `command_id` | Declared command ID from the catalog. |
| `argument.<slot>` | One catalog-declared normalized typed slot value. |

A rule allowing one agent to restart one service as one user looks like this:

```json
{
  "id": "agent-a-can-run-restart",
  "effect": "allow",
  "clients": ["agent-a"],
  "operations": ["exec.command"],
  "targets": [{ "kind": "user", "name": "deploy" }],
  "attrs": { "command_ids": ["restart-myapp"] }
}
```

## Running a command

The client reads `SUDO_BROKER_AGENT_ENDPOINT` and `SUDO_BROKER_SHARED_SECRET` from the environment,
or loads the generated client config:

```sh
sudo-broker run nginx-reload \
  --as root \
  --reason "Apply reviewed nginx configuration" \
  --operation-id nginx-reload-config-refresh
```

`run` submits one Agent V1 operation, waits for approval, executes the exact cataloged command
through the privileged helper, prints the command's output, and exits with its exit code. For typed
catalog slots, repeat `--arg-json NAME=JSON`.

Request rules default to reusable window grants. Each matching command still gets its own immutable
plan, operation ID, helper reservation, result, and audit record. Set `"mode": "execution"` in
`grant_policy` when one exact command must require a single-use approval.

Reuse a stable `--operation-id` when retrying. Never retry an ambiguous execution under a new ID,
because the broker cannot tell a retry from a second request and a privileged command that may
already have run is exactly the case where a duplicate matters.

## The V1 boundary

V1 supports only `exec.command` with one exact cataloged command shape. It does not support shell
sessions, TTY attachment, arbitrary command lines, caller environment variables, stdin, or command
discovery. Those are all excluded rather than pending.

The reasoning is the same one behind the catalog. Safely validating an arbitrary shell string is a
problem the project declines to take on, so the surface that would require it does not exist.

## Service hardening

`sudo-broker` is the one broker that deliberately performs an identity transition, which means it
must explicitly select the privilege escalation policy so unYOLO renders
`NoNewPrivileges=false`. Every other broker keeps the default, which denies escalation.

Home access stays denied in V1, and the helper requires root-trusted executable and working
directory chains. Writable state, read-only config, the service executable, and the environment
file occupy non-overlapping paths, and trusted service paths are always rejected below `/home`,
`/root`, and `/run/user`.

## Approval presentation

When Telegram notifications are configured, `sudo-broker` supplies only the cataloged command
description, target user, bounded arguments, timeout, and risk. unYOLO renders the same escaped
approval layout and fixed Approve and Deny controls used by the other brokers.

Raw executables, environment values, and unrestricted command lines are never notification fields.
An operator approving a `sudo-broker` request sees the catalog's description of what will run, not
a command line they might misread at a glance.

## Doctor

`sudo-broker` adds provider-specific checks on top of the shared ones: the command catalog, target
users, sudo, systemd, and launchd helper permissions, the privileged socket, and execution backend
safety.

```sh
sudo sudo-broker doctor host --agent agent-a
```

The shared exit codes apply: `0` for OK, `1` for unsafe, `2` for inconclusive.
