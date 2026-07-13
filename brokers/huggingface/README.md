# hf-broker

hf-broker is a self-hosted credential broker between a coding agent and
Hugging Face. It exposes only registered, policy-gated Git, LFS, repository,
and Router operations. Broad Hugging Face credentials remain inside
the broker; agents receive only revocable broker credentials. Dangerous
operations can require a short-lived approval without weakening append-only or
execution-time provider checks.

The provider-specific design and threat model are in
[docs/SPECIFICATION.md](docs/SPECIFICATION.md).
The shared install, setup, policy, approval, and release contract is in
[BrokerKit's unified broker contract](../../docs/UNIFIED_BROKER_CONTRACT.md).

## How it works

The broker is a git smart-HTTP proxy. Every `git push` body is parsed
before anything is forwarded; a push is accepted only if all its ref
updates are append-only (fast-forwards, new branches, new tags). Ancestry
is verified against a local commits-only mirror (`--filter=tree:0`), so
even terabyte repos cost megabytes. Accepted pushes are forwarded
upstream with a server-side write token the agent can never read;
refused pushes never leave the broker and `git push` prints the reason.

## Install

The recommended install path downloads a prebuilt release binary and
installs it globally:

```sh
curl -fsSL https://raw.githubusercontent.com/osolmaz/brokerkit/main/brokers/huggingface/install.sh | sh
```

Pin a version from [BrokerKit releases](https://github.com/osolmaz/brokerkit/releases)
with `VERSION`:

```sh
curl -fsSL https://raw.githubusercontent.com/osolmaz/brokerkit/main/brokers/huggingface/install.sh | VERSION=<version> sh
```

Install to a specific directory with `INSTALL_DIR`:

```sh
curl -fsSL https://raw.githubusercontent.com/osolmaz/brokerkit/main/brokers/huggingface/install.sh | INSTALL_DIR="$HOME/.local/bin" sh
```

For development, install from a BrokerKit checkout with the Go version declared
by the root module:

```sh
go install ./brokers/huggingface/cmd/hf-broker
```

## Run

```sh
export HF_BROKER_HF_TOKEN=hf_...            # upstream write token, outbound only
export HF_BROKER_SHARED_SECRET=$(openssl rand -hex 32)
cp scope.example.json scope.json         # edit: which repos are reachable
hf-broker
```

OpenAI-compatible clients use the broker secret as their API key:

```text
base URL = http://127.0.0.1:8080/v1
API key  = value from HF_BROKER_SHARED_SECRET
```

The agent listener exposes only `GET /v1/models` and
`POST /v1/chat/completions` for inference. Requests are authenticated with the
broker client secret and then evaluated against `scope.json`. They are
forwarded to the Hugging Face Router with the real token only when an explicit
allow rule matches. Prompts, completions, tool arguments, and credentials are
excluded from audit output. Other `/v1/*` routes fail closed.

## Agent operations

Protected Hub mutations use the typed Agent Operations API. The bundled client
and MCP adapter use only a broker client secret; neither can read the upstream
Hugging Face token.

```sh
export HF_BROKER_URL=http://127.0.0.1:8080
export HF_BROKER_SHARED_SECRET_FILE=/run/user/1000/hf-broker-agent-secret
hf-broker client repo create osolmaz/test-data --type dataset
```

If policy requires approval, the command prints the durable operation ID and
waits. Resume it after a disconnect with:

```sh
hf-broker client operation wait <operation-id>
```

Run `hf-broker mcp` as a stdio MCP server to expose the repository operation
tools and the `hf_grant_request|get|wait|cancel|revoke` tools. The tool
descriptions explicitly tell agents not to request a Hugging Face token.

## Temporary grants

Request an exact temporary capability when the policy marks an operation as
requestable:

```sh
hf-broker client grant request git.push.force osolmaz/model \
  --type model \
  --ref refs/heads/main \
  --minutes 30 \
  --max-uses unlimited \
  --reason "Repair protected history" \
  --idempotency-key repair-main
```

Omit `--minutes` or `--max-uses` to use the matched policy's finite default.
`--max-uses` accepts a positive integer or `unlimited`; unlimited grants
still expire at the approved time. The command waits for a decision by default.
Grant state can be resumed or changed without holding the protected operation
open:

```sh
hf-broker client grant get <grant-id>
hf-broker client grant wait <grant-id>
hf-broker client grant cancel <grant-id>
hf-broker client grant revoke <grant-id>
```

Repository requests use repeatable `--ref` flags. The broker validates the
operation, target, attributes, duration, and use budget against the exact
matched policy rule before creating an approval.

Inference defaults to denied. This rule allows one client to list Router models
and call models under one owner:

```json
{
  "rules": [
    {
      "id": "allow-acme-inference",
      "effect": "allow",
      "clients": ["default"],
      "operations": ["inference.models.list"],
      "targets": [{"kind": "inference", "owner": "router", "name": "models"}]
    },
    {
      "id": "allow-acme-chat",
      "effect": "allow",
      "clients": ["default"],
      "operations": ["inference.chat.complete"],
      "targets": [{"kind": "inference", "owner": "acme", "name": "*"}]
    }
  ]
}
```

For a hardened same-host deployment, prefer a broker-only token file
over placing the token value in the broker environment:

```sh
sudo install -o hf-broker -g hf-broker -m 0600 /path/to/hf-token /etc/hf-broker/hf-token
export HF_BROKER_HF_TOKEN_FILE=/etc/hf-broker/hf-token
```

`scope.json` is a rule file. This minimal rule lets one client read,
fetch, and append-push one dataset repo:

```json
{
  "rules": [
    {
      "id": "allow-scraped-news",
      "effect": "allow",
      "clients": ["default"],
      "operations": ["repo.contents.read", "git.fetch", "git.push.append"],
      "targets": [
        {"kind": "repo", "type": "dataset", "owner": "osolmaz", "name": "scraped-news"}
      ]
    }
  ]
}
```

Binding defaults to `127.0.0.1:8080`. Expose it to the agent over a
Tailnet or equivalent — and run the broker somewhere the agent cannot
log into, otherwise the isolation is decoration. See the specification
for all environment variables.

## Linux Service Setup

For a same-host setup, run the broker as a dedicated service user rather
than as the agent or your interactive account:

```text
onur      = admin
bob       = agent account, no sudo or docker
hf-broker = service account that can read the real Hugging Face token
```

After installing the binary, create a token file and configure systemd:

```sh
sudo hf-broker setup systemd \
  --hf-token-file ./hf-token \
  --repo osolmaz/scraped-news \
  --repo-type dataset \
  --telegram-bot-token-file ./telegram-bot-token \
  --telegram-chat-id 123456789 \
  --client bob
```

The setup command creates:

```text
/etc/hf-broker/hf-token
/etc/hf-broker/telegram-bot-token
/etc/hf-broker/secrets
/etc/hf-broker/operator-secrets
/etc/hf-broker/scope.json
/etc/hf-broker/env
/var/lib/hf-broker
/etc/systemd/system/hf-broker.service
```

It also creates the `hf-broker` service user when needed, enables and
starts the service, and prints the broker URL plus a secret-safe client setup
command. It never prints the generated broker client secret. The real Hugging
Face and Telegram tokens stay readable only by the service. The generated
operator credential is separate from every agent credential and is used only
on the operator listener at `http://127.0.0.1:8081`. The agent receives
only the broker client secret through `setup client`. Omit both Telegram flags
to run without Telegram; pending requests remain available in the operator
inbox and the Telegram flags must otherwise be set together.

To supply an existing broker client secret, use `--shared-secret-file` or
`--shared-secret-stdin`. Raw secret command-line flags are not accepted.
Use `--operator-secret-file` to preserve or rotate the operator credential,
and `--operator-bind-addr` / `--operator-port` to change the protected
listener. Agent and operator listeners must use different ports.

Write a client config file for an agent account with:

```sh
sudo hf-broker setup client \
  --client bob \
  --url http://127.0.0.1:8080 \
  --secret-file /etc/hf-broker/secrets \
  --home-dir /home/bob
```

This writes `/home/bob/.config/hf-broker/client.env` with only the broker
URL and broker shared secret. It does not print either secret and never writes
the Hugging Face token.

Use `--dry-run` to preview the service setup without writing files:

```sh
sudo hf-broker setup systemd \
  --hf-token-file ./hf-token \
  --repo osolmaz/scraped-news \
  --repo-type dataset \
  --dry-run
```

## Check Local Isolation

If the broker and agent share a host, run the isolation doctor before
trusting the setup:

```sh
hf-broker doctor \
  --agent-user agent \
  --broker-pid "$(pgrep -x hf-broker)" \
  --token-file /etc/hf-broker/hf-token \
  --socket /run/hf-broker/hf-broker.sock
```

`hf-broker doctor isolation` is the explicit form and behaves the same.
If no agent identity flags are supplied, `hf-broker doctor` checks the
live doctor process. This catches stale sessions that still carry old
root-equivalent groups after the account has been demoted.

The doctor fails closed when the agent is host root, root-equivalent
through groups such as `sudo`, `wheel`, `admin`, `docker`, `lxd`, or
`incus`, can read or modify the token file, can read the broker process
environment, can write/connect to the checked Unix socket, or shares the
broker UID.
It can also emit JSON for deployment checks:

```sh
hf-broker doctor --agent-user agent --token-file /etc/hf-broker/hf-token --json
```

Exit codes are `0` for OK, `1` for unsafe, `2` for inconclusive, and
`64` for invalid arguments. The doctor does not make an unsafe local
setup safe; it verifies whether the host matches the broker threat model.
It does not echo the `--token-file` value in findings. For file-token
deployments, pass `--token-file`; `--broker-pid` checks broker
environment reachability but does not verify file permissions by itself.

On macOS, the doctor keeps the same CLI and JSON report shape but is
intentionally conservative. It treats `admin` and `wheel` membership as
root-equivalent, checks token files and Unix sockets by ownership, mode
bits, ACLs, parent-directory writability, symlink targets, and active
read/connect probes when it can run as the agent identity. Process
environment facts and ACL entries that cannot be parsed conservatively
are reported as `unknown`, which makes the overall result `inconclusive`
rather than `ok`.

## Point the agent at it

On the agent machine, the broker is just a git remote; the broker secret
is the password:

```sh
git remote set-url origin https://broker.tailnet:8080/datasets/osolmaz/scraped-news
git config credential.helper '!f() { echo username=default; echo password=$HF_BROKER_SHARED_SECRET; }; f'
```

Clones, pulls, fast-forward pushes, new branches, and new tags work as
normal. A history rewrite is refused with a message at the terminal:

```text
 ! [remote rejected] main -> main (hf-broker: history rewrite refused)
```

## Operator Inbox

The operator listener exposes Brokerkit's shared backend:

```text
GET  /api/grants
GET  /api/grants/{id}
GET  /api/grants/events
POST /api/grants/{id}/approve
POST /api/grants/{id}/deny
POST /api/grants/{id}/cancel
POST /api/grants/{id}/revoke
```

Authenticate with a bearer token from `/etc/hf-broker/operator-secrets`.
Do not give that file or token to an agent. The listener returns bounded
Hugging Face-specific display fields while decisions apply only to the
canonical stored request. Lifecycle events use durable SSE cursors, so a
trusted host can reconnect after a restart without depending on Telegram. The
browser must authenticate to the trusted host; the host keeps
the broker operator credential server-side.

## Telegram Grants

Destructive git pushes are still refused by default. To make a narrow
exception, add a request rule for the repo in `scope.json` and
configure the broker host with a Telegram bot token and the single
operator chat id:

Telegram transport and callback handling come from
`github.com/osolmaz/brokerkit`; hf-broker keeps the Hugging Face-specific
approval message text and request classification.

Policy decisions also run through `github.com/osolmaz/brokerkit/policy`.
hf-broker keeps the Hugging Face rules-file parser, provider vocabulary, and
request classifiers; brokerkit owns matching, precedence, ambiguity checks,
grant bounds, and active-grant overlays. Brokerkit also owns durable grant
state, notification claims and references, expiry, reservation recovery, and
use accounting. hf-broker only maps HF targets and attrs and renders HF-specific
operator text.

Telegram is optional. It is a notification view over the same durable grant
store used by the operator inbox; a decision through either path closes the
same request exactly once.

Telegram callbacks are acknowledged immediately after the durable decision.
Status edits run through the restart-safe brokerkit grant sweep. A verified
callback commits the decision and editable message reference in one transaction
when Telegram delivered the prompt but the original send response was lost. A
durable write failure is left unanswered and retried from the same Telegram
update.

```json
{
  "rules": [
    {
      "id": "request-scraped-news-force",
      "effect": "request",
      "clients": ["default"],
      "operations": ["git.push.force"],
      "targets": [
        {"kind": "repo", "type": "dataset", "owner": "osolmaz", "name": "scraped-news"}
      ],
      "grant_policy": {
        "default_minutes": 5,
        "default_max_uses": 1,
        "max_uses": 3
      }
    }
  ]
}
```

```sh
export HF_BROKER_TELEGRAM_BOT_TOKEN=...
export HF_BROKER_TELEGRAM_CHAT_ID=123456789
```

For a service deployment, use `--telegram-bot-token-file` during `setup
systemd`. The installer copies the token to a service-owned `0600` file and
puts only its path in the service environment. Rerunning setup without both
Telegram flags disables Telegram and removes the managed token only after the
restarted service passes its readiness check. `--no-start` does not retire the
file.

An authenticated client can then request a time-boxed grant. Every request must
carry a unique `client_request_id`; retry the same request with the same value.

```sh
curl -sS -H "Authorization: Bearer $HF_BROKER_SHARED_SECRET" \
  -H "Content-Type: application/json" \
  -d '{
    "operation": "git.push.force",
    "target": {
      "kind": "repo",
      "type": "dataset",
      "owner": "osolmaz",
      "name": "scraped-news",
      "refs": ["refs/heads/main"]
    },
    "reason": "recover main after a bad commit",
    "minutes": 5,
    "max_uses": 1,
    "client_request_id": "recover-main-20260706"
  }' \
  https://broker.tailnet:8080/api/grants
```

Other grantable git capabilities are `git.ref.delete` for non-tag
branch/ref deletion and `git.tag.update` for moving or deleting tags.
Each one must be enabled separately in `scope.json`.

The broker sends the request to Telegram with Approve and Deny buttons
and long-polls the Bot API for the answer. There is no inbound Telegram
callback URL. A grant only covers the requested repo/ref, expires at the
approved time, is consumed after its use budget is exhausted, and
decisions from any chat except the configured operator chat are ignored.

If Telegram delivery returns an ambiguous error, the broker keeps the
notification claim and fails the client request. It does not send a duplicate
until the original two-minute claim lease expires; that retry uses a fresh
one-time decision token. This state survives broker restarts.

## License

[MIT](LICENSE)
