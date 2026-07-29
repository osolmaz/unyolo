# hf-broker

hf-broker is a self-hosted Hugging Face access broker for coding agents. It
keeps the Hugging Face token inside the broker and exposes registered
operations through revocable broker credentials. Policy covers Git, LFS,
repository operations, and Router inference. Sensitive work can wait for a
short-lived operator approval.

The provider design, threat model, and environment variables are documented in
[docs/SPECIFICATION.md](docs/SPECIFICATION.md).

## Git proxy

The broker is a Git smart-HTTP proxy. It parses every `git push` body before
forwarding anything and accepts only append-only ref updates. Ancestry is
verified against a local commits-only mirror (`--filter=tree:0`), which keeps
large repositories cheap to check. An accepted push uses a server-side write
token that the agent cannot read. A refused push never leaves the broker, and
`git push` prints the reason.

## Install

Fetch the bootstrap from a reviewed unYOLO commit. It resolves the latest
HF Broker release to its exact commit, verifies release checksums, and
installs to `$HOME/.local/bin`:

```sh
UNYOLO_REV=<verified-40-character-commit-sha>
curl -fsSL "https://raw.githubusercontent.com/osolmaz/unyolo/$UNYOLO_REV/brokers/huggingface/install.sh" | sh
```

Pin a release from [unYOLO releases](https://github.com/osolmaz/unyolo/releases)
with `VERSION=<version>`, or choose the target directory with
`INSTALL_DIR=/absolute/path`.

For development, install from a unYOLO checkout with the Go version
declared by the root module:

```sh
go install ./brokers/huggingface/cmd/hf-broker
```

Bucket object writes use the maintained Xet implementation. Install the pinned
helper in a broker-only Python environment and point HF Broker at its
interpreter:

```sh
python3 -m venv /opt/hf-broker/xet
/opt/hf-broker/xet/bin/pip install 'hf-xet==1.5.2'
export HF_BROKER_XET_PYTHON=/opt/hf-broker/xet/bin/python
```

The helper receives the Hub token only over a private stdin pipe. It uploads
content to Xet and returns the file hash; it does not receive client requests or
choose Hub URLs. Bucket reads and all non-Xet operations do not import the
helper.

HF Broker treats the permissions and resource scopes on its dedicated
fine-grained token as a hard upstream authority ceiling. Repair an installed
service interactively with:

```sh
hf-broker credential repair
```

The command opens Hugging Face's fine-grained token form, prints the exact URL,
and reads the token through a hidden terminal prompt. Its final panel reports
only the verified subject and capability count. The token form starts empty:
the operator chooses the permissions and resources the broker may use.
unYOLO policy and operator approval can narrow that authority but can never
expand it.

For inspection or automation, use bounded standard input and explicit JSON
output. Noninteractive repair never invokes `sudo` itself, so the caller must
enter an approved privilege boundary explicitly:

```sh
printf '%s\n' "$CANDIDATE_TOKEN" | hf-broker credential inspect --token-stdin --json
printf '%s\n' "$CANDIDATE_TOKEN" | sudo hf-broker credential repair --no-open --token-stdin --json
hf-broker credential status
```

`--json` keeps standard output machine-readable and does not open a browser or
print interactive instructions. Credential lifecycle events remain in the
protected append-only `credential-lifecycle.jsonl` file in the installed
broker config directory (`/etc/hf-broker` on Linux). They are not mixed into
normal terminal output; add `--verbose` to mirror those secret-safe JSON audit
records to standard error while troubleshooting.

## Run in development

Foreground development requires an explicit endpoint and development mode. A
loopback port of `0` asks the OS to choose an available port; the broker
prints the resolved endpoint in its readiness record.

```sh
export HF_BROKER_DEVELOPMENT=true
export HF_BROKER_AGENT_ENDPOINT=tcp://127.0.0.1:0
export HF_BROKER_GIT_ENDPOINT=tcp://127.0.0.1:0
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

unYOLO defines no default TCP port. Local production setup uses separate
permission-restricted agent and operator Unix sockets; standard Git HTTP and
remote clients require an explicit TCP listener or HTTPS reverse proxy. Run
the broker somewhere the agent cannot inspect its process or credential
files; otherwise the isolation boundary does not hold.

## Policy

`scope.json` is a manually edited rule file and the authorization source of
truth. A request without a matching rule is denied. This minimal rule lets
one client read and fetch one dataset repo, then append-push it:

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

## Configure Git

Give the service a deployment-selected loopback TCP listener with
`--git-endpoint`, include the same endpoint when running `setup client`, then
configure standard Git once for the user:

```sh
hf-broker git install
hf-broker git doctor
```

Normal `https://huggingface.co/...` and Hugging Face SSH-form remotes now use
the broker for clone and fetch operations plus pull and push. Supported Git LFS routes use it too. Remotes
contain no broker or provider credential. The listener port belongs to the
deployment; unYOLO defines no fixed Git port.

Basic Git LFS is supported. Xet custom-transfer negotiation currently fails
closed before signed actions are returned; unYOLO never exports the Hugging
Face token to enable Xet.

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
upstream Hugging Face token. They load the private client V1 file generated by
`setup client` automatically:

```sh
hf-broker client repo create \
  --target-json '{"kind":"repo","type":"dataset","owner":"osolmaz","name":"test-data"}' \
  --arguments-json '{"visibility":"private"}'
hf-broker client repo delete \
  --target-json '{"kind":"repo","type":"dataset","owner":"osolmaz","name":"test-data"}' \
  --arguments-json '{}'

hf-broker client bucket object list \
  --target-json '{"kind":"bucket","namespace":"osolmaz","name":"artifacts"}' \
  --arguments-json '{"prefix":"runs/","recursive":true,"limit":100}'

hf-broker client bucket object write \
  --target-json '{"kind":"bucket","namespace":"osolmaz","name":"artifacts"}' \
  --arguments-json '{"path":"runs/result.json","overwrite":false}' \
  --source ./result.json \
  --request-id publish-result
```

If policy requires approval, the command prints the durable operation ID and
waits. Resume it after a disconnect with:

```sh
hf-broker client operation wait <operation-id>
```

Run `hf-broker mcp` as a stdio MCP server. It advertises only agent-facing
catalog operations with registered runtime adapters, plus operation and grant
lifecycle tools. Every ordinary tool submits through the shared Agent
Operations lifecycle, including safe reads and window-authorized operations.
An allowed private-repository read executes immediately with the broker token;
it does not ask for a grant or expose that token. MCP submissions accept an
optional `request_id` and return immediately; recover interrupted calls with
`hf_operation_get`, `hf_operation_wait`, or `hf_operation_list`. The explicit
`hf_grant_*` tools are only for deliberate temporary-grant management.

`repo.list` queries the authenticated Hub and filters every result through the
calling client's policy before projection. Use a target name of `*` to
discover bounded repositories for one exact owner and repository type.
Specific deny rules override wildcard discovery. Repository content requires
its own authorization.

The checked-in OpenAPI snapshot is monitored against the official Hub schema
without automatic updates. See
[capability maintenance](../../docs/HUGGING_FACE_CAPABILITY_MAINTENANCE.md) for
the review and regeneration procedure.

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

Repository requests use repeatable `--ref` and `--path` flags. Bucket requests
use repeatable `--key` flags. A path or key may be exact or a single bounded
trailing `/**` prefix. The broker validates the operation, scope, duration, and
use budget against the exact matched policy rule before creating an approval.

Grantable git capabilities are `git.push.force` for history rewrites,
`git.ref.delete` for non-tag branch/ref deletion, and `git.tag.update` for
moving or deleting tags. Each one must be enabled separately with a
`"effect": "request"` rule in `scope.json`.

Every requestable operation in the default preset uses a reusable window.
Routine repository and bucket operations receive a `1000000`-use, seven-day
ceiling. Force pushes, ref deletions, and tag updates stay capped at 25 uses
for one hour. Policy may select exact execution mode, which always uses one
immutable plan once. Neither mode widens the approved operation, target, or
attrs.

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
  --xet-python /opt/hf-broker/xet/bin/python \
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
/run/unyolo/huggingface/agent/broker.sock
/run/unyolo/huggingface/operator/broker.sock
```

It prints the broker endpoint plus a secret-safe client setup command and
never prints the generated broker client secret. The real Hugging Face and
Telegram tokens stay readable only by the service, and the generated operator
credential is separate from every agent credential. The setup command persists
`--xet-python` in the systemd or launchd environment; an interactive export is
not inherited by the managed service. Omit both Telegram flags
to run without Telegram; pending requests remain available in the operator
inbox. Use `--dry-run` to preview without writing files.

A fresh setup installs the provider-owned `request-all-agent-operations`
policy preset: safe reads and discovery plus inference are allowed directly;
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
  --endpoint unix:///run/unyolo/huggingface/agent/broker.sock \
  --secret-file /etc/hf-broker/secrets \
  --home-dir /home/agent-a
```

This writes `/home/agent-a/.config/hf-broker/client.json` using the closed
client V1 schema. It does not print the broker secret and never writes the
Hugging Face token. Broker clients load the owner-only file directly.

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
  --socket /run/unyolo/huggingface/agent/broker.sock
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

The separate operator listener exposes unYOLO's shared inbox:

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
The broker sends approval requests to the configured operator chat with the
shared rich layout, fixed Approve and Deny buttons, and durable terminal status
edits. Hugging Face code supplies only bounded operation, target, risk,
warning, and plan facts; unYOLO owns Telegram formatting and escaping. The
separate `unyolo-telegram` service is the only Bot API poller and sends
decisions to this broker's authenticated Operator V1 socket. Configure it as described in
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
