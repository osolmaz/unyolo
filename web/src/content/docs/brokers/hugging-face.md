---
title: hf-broker
description: The Hugging Face credential broker, covering Git and LFS proxying, Hub operations, bucket writes, and Router inference.
---

`hf-broker` is a self-hosted credential broker between a coding agent and Hugging Face. It exposes
only registered, policy-gated Git, LFS, repository, and Router inference operations. Broad Hugging
Face credentials stay inside the broker, and agents receive revocable broker credentials. Dangerous
operations can require a short-lived operator approval without weakening the append-only and
execution-time checks the broker performs anyway.

## Git proxy behaviour

The broker is a Git smart-HTTP proxy that reads before it forwards. Every `git push` body is parsed
first, and a push is accepted only if all of its ref updates are append-only: fast-forwards, new
branches, or new tags. Ancestry is verified against a local commits-only mirror created with
`--filter=tree:0`, so even a terabyte-scale repository costs megabytes to check.

Accepted pushes go upstream with a server-side write token the agent can never read. Refused pushes
never leave the broker, and `git push` prints the reason at the terminal:

```text
 ! [remote rejected] main -> main (hf-broker: history rewrite refused)
```

## Install

```sh
curl -fsSL https://unyolo.io/install | sh -s huggingface
```

Pin a release with `VERSION=<version>` or choose a target directory with
`INSTALL_DIR=/absolute/path`. For development, `go install ./brokers/huggingface/cmd/hf-broker`
from a checkout.

Bucket object writes need the maintained Xet implementation in a broker-only Python environment:

```sh
python3 -m venv /opt/hf-broker/xet
/opt/hf-broker/xet/bin/pip install 'hf-xet==1.5.2'
export HF_BROKER_XET_PYTHON=/opt/hf-broker/xet/bin/python
```

The helper receives the Hub token over a private stdin pipe, uploads content, and returns a file
hash. It never receives client requests and never chooses Hub URLs. Bucket reads and all non-Xet
operations do not touch it.

## Token scope as a ceiling

`hf-broker` treats the permissions and resource scopes on its dedicated fine-grained token as a
hard upstream authority ceiling. Policy and operator approval can narrow that authority; nothing
can expand it. Creating a token scoped to the two repositories the agent needs is therefore worth
the five minutes.

Repair an installed service's credential interactively:

```sh
hf-broker credential repair
```

The command opens the Hugging Face fine-grained token form, prints the exact URL, and reads the
token through a hidden terminal prompt. The final panel reports only the verified subject and the
capability count. The token form starts empty, so the operator chooses what the broker may use.

For inspection or automation, use bounded standard input and explicit JSON output. Non-interactive
repair never invokes `sudo` itself, so the caller enters an approved privilege boundary explicitly:

```sh
printf '%s\n' "$CANDIDATE_TOKEN" | hf-broker credential inspect --token-stdin --json
printf '%s\n' "$CANDIDATE_TOKEN" | sudo hf-broker credential repair --no-open --token-stdin --json
hf-broker credential status
```

`--json` keeps stdout machine-readable, opens no browser, and prints no interactive instructions.

## Run in development

```sh
export HF_BROKER_DEVELOPMENT=true
export HF_BROKER_AGENT_ENDPOINT=tcp://127.0.0.1:0
export HF_BROKER_GIT_ENDPOINT=tcp://127.0.0.1:0
export HF_BROKER_HF_TOKEN=hf_...
export HF_BROKER_SHARED_SECRET=$(openssl rand -hex 32)
export HF_BROKER_SCOPE_FILE=scope.json
export HF_BROKER_STATE_DIR=state
cp scope.example.json scope.json
hf-broker
```

A loopback port of `0` asks the OS for an available port, and the broker prints the resolved
endpoint in its readiness record. For any real deployment, prefer a token file:

```sh
sudo install -o hf-broker -g hf-broker -m 0600 /path/to/hf-token /etc/hf-broker/hf-token
export HF_BROKER_HF_TOKEN_FILE=/etc/hf-broker/hf-token
```

unYOLO defines no default TCP port. Local production setup uses separate permission-restricted
agent and operator Unix sockets, while standard Git HTTP and remote clients need an explicit TCP
listener or an HTTPS reverse proxy.

## Policy

`scope.json` is the authorization source of truth, and a request without a matching rule is denied.
This minimal rule lets one client read and fetch one dataset repository, then append-push it:

```json
{
  "rules": [
    {
      "id": "allow-scraped-news",
      "effect": "allow",
      "clients": ["default"],
      "operations": ["repo.contents.read", "git.fetch", "git.push.append"],
      "targets": [
        { "kind": "repo", "type": "dataset", "owner": "osolmaz", "name": "scraped-news" }
      ]
    }
  ]
}
```

Grantable Git capabilities are `git.push.force` for history rewrites, `git.ref.delete` for non-tag
branch and ref deletion, and `git.tag.update` for moving or deleting tags. Each must be enabled
separately with its own `"effect": "request"` rule.

Every requestable operation in the default preset uses a reusable window. Routine repository and
bucket operations receive a `1000000`-use, seven-day ceiling. Force pushes, ref deletions, and tag
updates stay capped at 25 uses for one hour. Policy may select exact execution mode, which always
uses one immutable plan once. Neither mode broadens the approved operation, target, or attrs.

## Configure Git

Give the service a deployment-selected loopback TCP listener with `--git-endpoint`, include the
same endpoint when running `setup client`, then configure Git once for the user:

```sh
hf-broker git install
hf-broker git doctor
```

Ordinary `https://huggingface.co/...` and Hugging Face SSH-form remotes now use the broker for
clone, fetch, pull, and push, and supported LFS routes use it too. Remotes contain no broker or
provider credential.

Basic Git LFS is supported. Xet custom-transfer negotiation fails closed before signed actions are
returned, because unYOLO will not export the Hugging Face token to enable it.

## Inference

OpenAI-compatible clients use the same HTTPS ingress and the broker secret as their API key:

```text
base URL = https://hf-broker.example.com/v1
API key  = value from HF_BROKER_SHARED_SECRET
```

The agent listener exposes only `GET /v1/models` and `POST /v1/chat/completions`. Requests are
authenticated with the broker client secret, evaluated against `scope.json`, and forwarded to the
Hugging Face Router with the real token only when an explicit allow rule matches. Prompts,
completions, tool arguments, and credentials are excluded from audit output, and other `/v1/*`
routes fail closed.

## Agent operations

Protected Hub mutations use the typed Agent Operations API. The bundled client and MCP adapter use
only a broker client secret and load the client V1 file generated by `setup client` automatically:

```sh
hf-broker client repo create \
  --target-json '{"kind":"repo","type":"dataset","owner":"osolmaz","name":"test-data"}' \
  --arguments-json '{"visibility":"private"}'

hf-broker client bucket object list \
  --target-json '{"kind":"bucket","namespace":"osolmaz","name":"artifacts"}' \
  --arguments-json '{"prefix":"runs/","recursive":true,"limit":100}'

hf-broker client bucket object write \
  --target-json '{"kind":"bucket","namespace":"osolmaz","name":"artifacts"}' \
  --arguments-json '{"path":"runs/result.json","overwrite":false}' \
  --source ./result.json \
  --request-id publish-result
```

If policy requires approval, the command prints the durable operation ID and waits. Resume after a
disconnect with `hf-broker client operation wait <operation-id>`.

`repo.list` queries the authenticated Hub and filters every result through the calling client's
policy before projection. A target name of `*` discovers bounded repositories for one exact owner
and repository type, and specific deny rules override wildcard discovery. Repository content still
requires its own authorization.

The checked-in OpenAPI snapshot is monitored against the official Hub schema without automatic
updates. See
[Hugging Face capability maintenance](https://github.com/osolmaz/unyolo/blob/main/docs/HUGGING_FACE_CAPABILITY_MAINTENANCE.md)
for the review and regeneration procedure.

## MCP

`hf-broker mcp` runs a stdio MCP server advertising agent-facing catalog operations that have
registered runtime adapters, plus operation and grant lifecycle tools. Every ordinary tool submits
through the shared Agent Operations lifecycle, including safe reads and window-authorized
operations.

An allowed private-repository read executes immediately with the broker token; it does not ask for
a grant and it does not expose the token. Submissions accept an optional `request_id` and return
immediately. Recover interrupted calls with `hf_operation_get`, `hf_operation_wait`, or
`hf_operation_list`. The `hf_grant_*` tools are only for deliberate temporary-grant management.

## Linux service setup

Run the broker as a dedicated service user rather than as the agent or your interactive account:

```text
operator-a = administrator account
agent-a    = agent account, no root-equivalent groups
hf-broker  = service account that can read the real Hugging Face token
```

```sh
sudo hf-broker setup systemd \
  --hf-token-file ./hf-token \
  --xet-python /opt/hf-broker/xet/bin/python \
  --telegram-bot-token-file ./telegram-bot-token \
  --telegram-chat-id 123456789 \
  --client agent-a \
  --operator operator-a \
  --agent-user agent-a \
  --operator-user operator-a
```

Setup creates protected configuration under `/etc/hf-broker`, state under `/var/lib/hf-broker`,
systemd service and socket units, and the `hf-broker` service user when needed, then enables and
starts the service. The agent and operator listeners are separate Unix sockets:

```text
/run/unyolo/huggingface/agent/broker.sock
/run/unyolo/huggingface/operator/broker.sock
```

It prints the broker endpoint and a secret-safe client setup command, and it never prints the
generated broker client secret. The real Hugging Face and Telegram tokens stay readable only by the
service, and the generated operator credential is separate from every agent credential.

Setup persists `--xet-python` in the systemd or launchd environment, because an interactive export
is not inherited by a managed service. Omit both Telegram flags to run without Telegram; pending
requests remain available in the operator inbox. Use `--dry-run` to preview without writing files,
and `hf-broker setup launchd` on macOS with the same credential flags.

A fresh setup installs the `request-all-agent-operations` preset: safe reads, discovery, and
inference are allowed directly; writes, administration, and destructive operations require
approval; internal and credential-output operations are denied. Add repeatable
`--deny-operation <exact-name>` flags to disable more. Setup refuses to overwrite an existing
policy unless `--replace-policy` is supplied, and before replacement it previews the current and
candidate policy digests and the change in operation counts. To install a deliberately narrow
policy for one repository instead, supply both `--repo owner/name` and
`--repo-type model|dataset|space`.

Write a client config for an agent account:

```sh
sudo hf-broker setup client \
  --client agent-a \
  --endpoint unix:///run/unyolo/huggingface/agent/broker.sock \
  --secret-file /etc/hf-broker/secrets \
  --home-dir /home/agent-a
```

## Check local isolation

If the broker and agent share a host, run the isolation doctor before trusting the setup:

```sh
hf-broker doctor \
  --agent-user agent \
  --broker-pid "$(pgrep -x hf-broker)" \
  --token-file /etc/hf-broker/hf-token \
  --socket /run/unyolo/huggingface/agent/broker.sock
```

`hf-broker doctor isolation` is the explicit form and behaves identically. With no agent identity
flags it checks the live doctor process, which catches stale sessions still carrying old
root-equivalent groups after an account was demoted.

The doctor fails closed when the agent is host root, is root-equivalent through groups such as
`sudo`, `wheel`, `admin`, `docker`, `lxd`, or `incus`, can read or modify the token file, can read
the broker process environment, can write to or connect to the checked socket, or shares the broker
UID. Add `--json` for deployment checks. Exit codes are `0` for OK, `1` for unsafe, `2` for
inconclusive, and `64` for invalid arguments.

The doctor does not make an unsafe setup safe. It verifies whether the host matches the threat
model, and it never echoes the `--token-file` value in findings. On macOS it keeps the same CLI and
report shape but is intentionally conservative: facts it cannot establish are reported as
`unknown`, which makes the overall result `inconclusive` rather than `ok`.

## Operator inbox

The separate operator listener exposes unYOLO's shared inbox at
`/api/operator/v1/requests` and the related decision routes. Authenticate with a bearer token from
`/etc/hf-broker/operator-secrets`, and do not give that file to an agent. Lifecycle events use
durable SSE cursors, so a trusted host can reconnect after a restart without depending on Telegram.

Rerunning provider setup without both Telegram flags disables Telegram notifications and retires
the managed token file after the restarted service passes its readiness check.
