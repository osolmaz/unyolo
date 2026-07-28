---
title: Connect an agent
description: Write the client config, install the Git integration, and expose broker operations over MCP.
---

An agent reaches a broker through three surfaces, and which ones you set up depends on what the
agent does. The client config file is always needed. Git integration matters if the agent runs
`git`. The MCP server matters if the agent is an LLM tool caller. This page covers all three.

## Write the client config

`setup client` writes a private config file into the agent account's home directory:

```sh
sudo hf-broker setup client \
  --client agent-a \
  --endpoint unix:///run/unyolo/huggingface/agent/broker.sock \
  --git-endpoint tcp://127.0.0.1:38471 \
  --secret-file /etc/hf-broker/secrets \
  --home-dir /home/agent-a
```

That produces `/home/agent-a/.config/hf-broker/client.json`, owner-readable only, using the closed
`unyolo.io/client/v1` schema:

```json
{
  "api_version": "unyolo.io/client/v1",
  "client_id": "agent-a",
  "agent_endpoint": "unix:///run/unyolo/huggingface/agent/broker.sock",
  "git_endpoint": "tcp://127.0.0.1:38471",
  "shared_secret": "broker-client-secret"
}
```

The command does not print the secret, and it never writes an upstream provider credential. Broker
CLIs, MCP adapters, and Git helpers load this file directly, which is why a production agent does
not need shell startup files or exported environment variables to reach its broker.

Each broker gets its own config under `~/.config/<broker>/client.json`, so an agent with all three
brokers available has three files and three unrelated secrets.

<div class="callout callout--warn">
<span class="callout__title">There is no dual-secret window</span>
<p>Client secrets are replaced exactly, with no overlap period. When a broker's cutover succeeds,
clients holding the old secret start failing immediately and must be given the new config as a
separate step. Plan the two changes together.</p>
</div>

## Install Git integration

`setup client` deliberately does not touch Git configuration. That is a separate command, run as
the agent user:

```sh
hf-broker git install
hf-broker git doctor
```

`git install` writes exact user-level `url.*.insteadOf` mappings plus a credential helper scoped to
the broker's listener origin. After it runs, ordinary `https://huggingface.co/...` remotes and
Hugging Face SSH-form remotes route through the broker for clone, fetch, pull, and push, and
supported LFS routes go the same way. The remotes themselves contain no credential.

Installation treats existing Git configuration as untrusted input. It rejects conflicting URL
rewrites, owns the exact values it writes, and fails closed when the broker listener or helper is
missing. `git status --json` reports the configuration it owns, and `git uninstall` removes only
that exact provider installation and leaves everything else alone.

Clones, pulls, fast-forward pushes, new branches, and new tags behave normally. A refused push
prints its reason at the terminal:

```text
 ! [remote rejected] main -> main (hf-broker: history rewrite refused)
```

Basic Git LFS works. Hugging Face Xet custom-transfer negotiation fails closed before any signed
action is returned, because enabling it would mean exporting the Hub token past the boundary.

## Run discrete operations

Operations that are not Git traffic go through the typed Agent V1 CLI, which loads the client
config automatically:

```sh
gh-broker operation submit pull_request.create \
  --target-json '{"kind":"repo","owner":"osolmaz","name":"unyolo"}' \
  --arguments-json '{"title":"agent work","head":"agent-a/work","base":"main","body":"Ready for review."}' \
  --reason "Open the reviewed feature branch" \
  --request-id open-agent-pr \
  --wait
```

If policy requires approval, the command prints a durable operation ID and waits. Reuse the same
`--request-id` when retrying, and recover an interrupted call with `operation get`, `operation
wait`, or `operation cancel`. Retrying a request ID that already exists returns the existing
operation rather than starting a second one.

`hf-broker` uses a slightly different command shape for the same lifecycle:

```sh
hf-broker client repo create \
  --target-json '{"kind":"repo","type":"dataset","owner":"osolmaz","name":"test-data"}' \
  --arguments-json '{"visibility":"private"}'

hf-broker client operation wait <operation-id>
```

## Expose operations over MCP

For an LLM agent, run the broker's stdio MCP server:

```sh
hf-broker mcp
gh-broker mcp
```

The advertised tool set is the intersection of the agent-facing catalog, the client's enabled
operations, the operations policy makes visible, the operations with registered runtime adapters,
and the operator exposure profile. Catalog entries without an executor stay browsable as
documentation without becoming runnable tools.

Every ordinary tool call submits one durable Agent V1 operation and returns immediately with a
transcript-safe projection, so a tool call never blocks waiting for approval. Recover after a
disconnect with `<prefix>operation_get`, `<prefix>operation_wait`, or `<prefix>operation_list`.
Waits are bounded to 25 seconds and return the latest known state on timeout. Credentials stay
sealed or slot-backed and never appear in tool output.

MCP submissions accept an optional `request_id`. Omit it and the broker generates one before
durable admission. Supply the same ID with the same immutable request and you get the existing
operation back; supply it with a conflicting request and you get a bounded `request_id_conflict`.

The explicit `<prefix>grant_*` tools exist only for callers deliberately managing a temporary
capability that a native protocol such as Git will use later. They are not a preflight step for
ordinary operation tools, and using them that way creates approval requests nobody needed. See
[MCP servers](/docs/guides/mcp-server) for the full lifecycle.

## Give the agent instructions

An agent that does not know a broker exists will keep looking for `HF_TOKEN`. The
[OpenClaw plugin](/docs/brokers/openclaw) ships client skills for all three brokers that teach
an agent to use the installed broker clients instead of hunting for upstream credentials or trying
to escalate privilege directly. A skill becomes eligible only when its matching broker executable is
present, and the skill itself grants no access.

For other agent hosts, the same idea applies by hand: put the broker CLI in the agent's tool list
and say plainly in its instructions that provider credentials are unavailable and broker commands
are the way to act.

## Verify the boundary

Before trusting any of this, check that the host actually matches the model:

```sh
hf-broker doctor \
  --agent-user agent-a \
  --broker-pid "$(pgrep -x hf-broker)" \
  --token-file /etc/hf-broker/hf-token \
  --socket /run/unyolo/huggingface/agent/broker.sock
```

The doctor fails closed when the agent account is root, is root-equivalent through a group such as
`sudo`, `wheel`, `admin`, `docker`, `lxd`, or `incus`, can read or modify the token file, can read
the broker's process environment, can write to the checked socket, or shares the broker's UID. See
[doctor checks](/docs/guides/verify-isolation).
