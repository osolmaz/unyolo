# hf-broker

hf-broker is a self-hosted credential broker between a coding agent and
Hugging Face. It exposes only registered, policy-gated Git, LFS, repository,
and Router inference operations; broad Hugging Face credentials remain inside
the broker while agents receive only revocable broker credentials. Dangerous
operations can require a short-lived operator approval without weakening
append-only or execution-time provider checks.

The provider-specific design and threat model are in
[docs/SPECIFICATION.md](docs/SPECIFICATION.md), including the full list of
environment variables.

## How the Git proxy works

The broker is a git smart-HTTP proxy. Every `git push` body is parsed before
anything is forwarded; a push is accepted only if all its ref updates are
append-only (fast-forwards, new branches, new tags). Ancestry is verified
against a local commits-only mirror (`--filter=tree:0`), so even terabyte
repos cost megabytes. Accepted pushes are forwarded upstream with a
server-side write token the agent can never read; refused pushes never leave
the broker and `git push` prints the reason.

## Install

Fetch the bootstrap from a reviewed BrokerKit commit. It resolves the latest
HF Broker release to its exact commit, verifies release checksums, and
installs to `$HOME/.local/bin`:

```sh
BROKERKIT_REV=<verified-40-character-commit-sha>
curl -fsSL "https://raw.githubusercontent.com/osolmaz/brokerkit/$BROKERKIT_REV/brokers/huggingface/install.sh" | sh
```

Pin a release from [BrokerKit releases](https://github.com/osolmaz/brokerkit/releases)
with `VERSION=<version>`, or choose the target directory with
`INSTALL_DIR=/absolute/path`.

For development, install from a BrokerKit checkout with the Go version
declared by the root module:

```sh
go install ./brokers/huggingface/cmd/hf-broker
```

## Run in development

Foreground development requires an explicit endpoint and development mode. A
loopback port of `0` asks the OS to choose an available port; the broker
prints the resolved endpoint in its readiness record.

```sh
export HF_BROKER_DEVELOPMENT=true
export HF_BROKER_AGENT_ENDPOINT=tcp://127.0.0.1:0
export HF_BROKER_HF_TOKEN=hf_...          # upstream write token, outbound only
export HF_BROKER_SHARED_SECRET=$(openssl rand -hex 32)
export HF_BROKER_SCOPE_FILE=scope.json
export HF_BROKER_STATE_DIR=state
cp scope.example.json scope.json          # edit: which repos are reachable
hf-broker
```

For any deployment, prefer a broker-only token file over placing the token
value in the broker environment:

```sh
sudo install -o hf-broker -g hf-broker -m 0600 /path/to/hf-token /etc/hf-broker/hf-token
export HF_BROKER_HF_TOKEN_FILE=/etc/hf-broker/hf-token
```

BrokerKit defines no default TCP port. Local production setup uses separate
permission-restricted agent and operator Unix sockets; standard Git HTTP and
remote clients require an explicit TCP listener or HTTPS reverse proxy. Run
the broker somewhere the agent cannot inspect its process or credential
files; otherwise the isolation boundary does not hold.

## Policy

`scope.json` is a manually edited rule file and the authorization source of
truth. A request without a matching rule is denied. This minimal rule lets
one client read, fetch, and append-push one dataset repo:

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

See [scope.example.json](scope.example.json) for read, request, and
inference rules, and [docs/POLICY_RULES_SPEC.md](docs/POLICY_RULES_SPEC.md)
for the full rule vocabulary.

## Point a Git client at it

Expose the agent listener through an explicitly configured HTTPS ingress.
The broker secret is the password:

```sh
git remote set-url origin https://hf-broker.example.com/datasets/osolmaz/scraped-news
git config credential.helper '!f() { echo username=default; echo password=$HF_BROKER_SHARED_SECRET; }; f'
```

Clones, pulls, fast-forward pushes, new branches, and new tags work as
normal. A history rewrite is refused with a message at the terminal:

```text
 ! [remote rejected] main -> main (hf-broker: history rewrite refused)
```

## Inference

OpenAI-compatible clients use the same HTTPS ingress and the broker secret as
their API key:

```text
base URL = https://hf-broker.example.com/v1
API key  = value from HF_BROKER_SHARED_SECRET
```

The agent listener exposes only `GET /v1/models` and
`POST /v1/chat/completions`. Requests are authenticated with the broker
client secret, evaluated against `scope.json`, and forwarded to the Hugging
Face Router with the real token only when an explicit allow rule matches.
Prompts, completions, tool arguments, and credentials are excluded from audit
output. Other `/v1/*` routes fail closed.

## Agent operations

Protected Hub mutations use the typed Agent Operations API. The bundled
client and MCP adapter use only a broker client secret; neither can read the
upstream Hugging Face token. The example sources the `client.env` generated
by `setup client` (see [Linux service setup](#linux-service-setup)):

```sh
. "$HOME/.config/hf-broker/client.env"
hf-broker client repo create \
  --target-json '{"kind":"repo","type":"dataset","owner":"osolmaz","name":"test-data"}' \
  --arguments-json '{"visibility":"private"}'
hf-broker client repo delete \
  --target-json '{"kind":"repo","type":"dataset","owner":"osolmaz","name":"test-data"}' \
  --arguments-json '{}'
```

If policy requires approval, the command prints the durable operation ID and
waits. Resume it after a disconnect with:

```sh
hf-broker client operation wait <operation-id>
```

Run `hf-broker mcp` as a stdio MCP server to expose one explicit tool for
every agent-facing operation in the capability catalog, plus operation and
grant lifecycle tools. The same catalog generates the CLI command tree and
policy vocabulary. Tool descriptions explicitly tell agents not to request a
Hugging Face token. MCP submissions accept an optional `request_id` and
return immediately; recover interrupted calls with `hf_operation_get`,
`hf_operation_wait`, or `hf_operation_list`, and use the `hf_grant_*` tools
for temporary-grant lifecycles.

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
  --request-id repair-main
```

Omit `--minutes` or `--max-uses` to use the matched policy's finite default.
`--max-uses` accepts a positive integer or `unlimited`; unlimited grants
still expire at the approved time. The command waits for a decision by
default. Grant state can be resumed or changed without holding the protected
operation open:

```sh
hf-broker client grant get <grant-id>
hf-broker client grant wait <grant-id>
hf-broker client grant cancel <grant-id>
hf-broker client grant revoke <grant-id>
```

Repository requests use repeatable `--ref` flags. The broker validates the
operation, target, attributes, duration, and use budget against the exact
matched policy rule before creating an approval.

Grantable git capabilities are `git.push.force` for history rewrites,
`git.ref.delete` for non-tag branch/ref deletion, and `git.tag.update` for
moving or deleting tags. Each one must be enabled separately with a
`"effect": "request"` rule in `scope.json`:

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

A grant only covers the requested repo/ref, expires at the approved time, and
is consumed after its use budget is exhausted.

## Linux service setup

For a same-host setup, run the broker as a dedicated service user rather
than as the agent or your interactive account:

```text
operator-a = administrator account
agent-a    = agent account, no root-equivalent groups
hf-broker  = service account that can read the real Hugging Face token
```

After installing the binary, create a token file and configure systemd:

```sh
sudo hf-broker setup systemd \
  --hf-token-file ./hf-token \
  --telegram-bot-token-file ./telegram-bot-token \
  --telegram-chat-id 123456789 \
  --client agent-a \
  --operator operator-a \
  --agent-user agent-a \
  --operator-user operator-a
```

Setup creates protected configuration under `/etc/hf-broker`, state under
`/var/lib/hf-broker`, systemd service and socket units, and the `hf-broker`
service user when needed, then enables and starts the service. The agent and
operator listeners are separate Unix sockets:

```text
/run/brokerkit/huggingface/agent/broker.sock
/run/brokerkit/huggingface/operator/broker.sock
```

It prints the broker endpoint plus a secret-safe client setup command and
never prints the generated broker client secret. The real Hugging Face and
Telegram tokens stay readable only by the service, and the generated operator
credential is separate from every agent credential. Omit both Telegram flags
to run without Telegram; pending requests remain available in the operator
inbox. Use `--dry-run` to preview without writing files.

A fresh setup installs the provider-owned `request-all-agent-operations`
policy preset: safe reads, discovery, and inference are allowed directly;
writes, administration, and destructive operations require approval; internal
and credential-output operations are denied. Add repeatable
`--deny-operation <exact-name>` flags to disable more operations. Setup
refuses to overwrite an existing policy unless `--replace-policy` is
supplied, so a binary upgrade cannot silently widen an installation; before
replacement it previews the current and candidate policy digests and
operation-count changes. Existing deny overrides remain in effect unless the
operator also supplies `--reset-denied-operations`. See
[Policy presets](docs/POLICY_PRESETS.md) for rendering and drift checks.

To create an intentionally narrow policy for one repository instead, supply
both `--repo owner/name` and `--repo-type model|dataset|space`.

To supply an existing broker client secret, use `--shared-secret-file` or
`--shared-secret-stdin`; raw secret command-line flags are not accepted. Use
`--operator-secret-file` to preserve or rotate the operator credential, and
`--endpoint` / `--operator-endpoint` to select deployment-owned listeners.
Agent and operator endpoints must be distinct. macOS uses
`hf-broker setup launchd` with the same credential flags.

Write a client config file for an agent account with:

```sh
sudo hf-broker setup client \
  --client agent-a \
  --endpoint unix:///run/brokerkit/huggingface/agent/broker.sock \
  --secret-file /etc/hf-broker/secrets \
  --home-dir /home/agent-a
```

This writes `/home/agent-a/.config/hf-broker/client.env` with only
`HF_BROKER_AGENT_ENDPOINT` and `HF_BROKER_SHARED_SECRET`. It does not print
either secret and never writes the Hugging Face token. The agent loads it
with:

```sh
. "$HOME/.config/hf-broker/client.env"
```

Check whether generated policy artifacts still match the current catalog:

```sh
hf-broker doctor policy \
  --profile /etc/hf-broker/policy-profile.json \
  --scope /etc/hf-broker/scope.json \
  --manifest /etc/hf-broker/policy-manifest.json
```

## Check local isolation

If the broker and agent share a host, run the isolation doctor before
trusting the setup:

```sh
hf-broker doctor \
  --agent-user agent \
  --broker-pid "$(pgrep -x hf-broker)" \
  --token-file /etc/hf-broker/hf-token \
  --socket /run/brokerkit/huggingface/agent/broker.sock
```

`hf-broker doctor isolation` is the explicit form and behaves the same. If no
agent identity flags are supplied, the doctor checks the live doctor process,
which catches stale sessions that still carry old root-equivalent groups
after the account has been demoted.

The doctor fails closed when the agent is host root, root-equivalent through
groups such as `sudo`, `wheel`, `admin`, `docker`, `lxd`, or `incus`, can
read or modify the token file, can read the broker process environment, can
write/connect to the checked Unix socket, or shares the broker UID. Add
`--json` for deployment checks. Exit codes are `0` for OK, `1` for unsafe,
`2` for inconclusive, and `64` for invalid arguments.

The doctor does not make an unsafe local setup safe; it verifies whether the
host matches the broker threat model. It never echoes the `--token-file`
value in findings. On macOS the doctor keeps the same CLI and JSON report
shape but is intentionally conservative: facts it cannot establish are
reported as `unknown`, which makes the overall result `inconclusive` rather
than `ok`.

## Operator inbox

The separate operator listener exposes BrokerKit's shared inbox:

```text
GET  /api/operator/v1/requests
GET  /api/operator/v1/requests/{id}
GET  /api/operator/v1/events
POST /api/operator/v1/requests/{id}/approve
POST /api/operator/v1/requests/{id}/deny
POST /api/operator/v1/requests/{id}/revoke
```

Authenticate with a bearer token from `/etc/hf-broker/operator-secrets`. Do
not give that file or token to an agent. Lifecycle events use durable SSE
cursors, so a trusted host can reconnect after a restart without depending on
Telegram. Cancellation is requester-owned and stays on the authenticated
agent surface; operators deny pending requests or revoke active grants.

Telegram is optional. It is a notification view over the same durable grant
store used by the operator inbox; a decision through either path closes the
same request exactly once. For a service deployment, pass
`--telegram-bot-token-file` and `--telegram-chat-id` during `setup systemd`.
The broker sends approval requests to the configured operator chat with
Approve and Deny buttons and applies durable status edits. The separate
`brokerkit-telegram` service is the only Bot API poller and sends decisions to
this broker's authenticated Operator V1 socket. Configure it as described in
[Telegram approval ingress](../../docs/TELEGRAM_INGRESS.md). Rerunning provider
setup without both Telegram flags disables Telegram notifications and retires
the managed token file after the restarted service passes its readiness check.

Authenticated clients can also request grants over HTTP. Every request must
carry a unique `client_request_id`, reused on retries:

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
    "client_request_id": "recover-main-after-bad-commit"
  }' \
  https://hf-broker.example.com/api/grants
```

## License

[MIT](LICENSE)
