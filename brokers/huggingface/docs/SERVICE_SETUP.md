# Linux service setup

`hf-broker` is a server. For a real same-host deployment, run it as a
dedicated service user and let local clients use its protected agent socket.

Recommended account model:

```text
operator-a = administrator account
agent-a    = agent account, no root-equivalent groups
hf-broker  = service account that can read the real Hugging Face token
```

The agent should not read or store the real Hugging Face token. It should
only know a broker client secret.

## Install the Binary

Install from a reviewed unYOLO commit:

```sh
UNYOLO_REV=<verified-40-character-commit-sha>
curl -fsSL "https://raw.githubusercontent.com/osolmaz/unyolo/$UNYOLO_REV/brokers/huggingface/install.sh" | sh
```

## Configure systemd

Create a local file containing the upstream Hugging Face token:

```sh
printf '%s\n' 'hf_...' > ./hf-token
chmod 600 ./hf-token
```

Then configure the broker service:

```sh
sudo hf-broker setup systemd \
  --hf-token-file ./hf-token \
  --client agent-a \
  --operator operator-a \
  --agent-user agent-a \
  --operator-user operator-a
```

The setup command creates:

```text
/etc/hf-broker/hf-token
/etc/hf-broker/secrets
/etc/hf-broker/operator-secrets
/etc/hf-broker/policy-profile.json
/etc/hf-broker/scope.json
/etc/hf-broker/policy-manifest.json
/etc/hf-broker/env
/var/lib/hf-broker
/etc/systemd/system/hf-broker.service
/etc/systemd/system/hf-broker-agent.socket
/etc/systemd/system/hf-broker-operator.socket
```

unYOLO performs the privileged host installation. hf-broker supplies the
Hugging Face-specific file contents and service definition; it does not keep a
second account, ownership, file-install, or systemctl implementation.

Fresh setup renders the provider-owned `request-all-agent-operations` preset.
Safe reads, discovery, and inference are allowed; mutations and administration
are requestable through the approval flow; internal and credential-output
operations are denied. Add `--deny-operation <exact-name>` to hard-deny more
operations. To install a narrow single-repository policy instead, explicitly
set both `--repo owner/name` and `--repo-type model|dataset|space`.

Setup refuses to replace an existing `scope.json` unless the operator supplies
`--replace-policy`. A binary update therefore cannot silently expand policy.
The refused command and `--dry-run` both show the current and candidate policy
digests and operation-count changes for review before replacement.
Preset deny overrides are preserved during replacement. Clearing them requires
the additional explicit `--reset-denied-operations` flag.
See [Policy presets](POLICY_PRESETS.md) for standalone rendering and drift
diagnostics.

The real Hugging Face token is copied to:

```text
/etc/hf-broker/hf-token
```

That file is owned by `hf-broker:hf-broker` and mode `0600`.

After installation, rotate or repair this credential with the hidden-input
interactive flow:

```sh
hf-broker credential repair
```

For automation, pipe the token to an explicitly privileged command and request
pure JSON output:

```sh
printf '%s\n' "$CANDIDATE_TOKEN" | sudo hf-broker credential repair --no-open --token-stdin --json
```

Noninteractive repair does not invoke `sudo` implicitly. Successful lifecycle
events are appended to `/etc/hf-broker/credential-lifecycle.jsonl` with mode
`0600`; raw audit JSON is shown in the terminal only when `--verbose` is
requested.

The operator inbox credential is generated independently at
`/etc/hf-broker/operator-secrets`, also mode `0600`. Systemd owns separate
agent and operator sockets under `/run/unyolo/huggingface/`, with access
controlled by distinct groups. Agents receive neither the operator credential
nor access to the operator socket through their client configuration.

hf-broker has no Telegram settings. For Telegram approval cards, install
`unyolo-telegram` as described in
[Telegram approval owner](../../../docs/TELEGRAM_INGRESS.md); it holds the only
copy of the bot token and decides through the operator socket.

Older releases stored a bot token at `/etc/hf-broker/telegram-bot-token`.
Rerunning setup writes an environment without Telegram, restarts the service,
waits for `/healthz`, and then removes that file.

The broker client secret is stored in:

```text
/etc/hf-broker/secrets
```

That file is also owned by `hf-broker:hf-broker` and mode `0600`. Setup never
prints the generated client secret. Use `hf-broker setup client` as an
administrator to write the matching broker endpoint and client secret directly
into the agent account's private configuration.

## Agent Setup

Write the protected client configuration directly into the agent account:

```sh
sudo hf-broker setup client \
  --client agent-a \
  --endpoint unix:///run/unyolo/huggingface/agent/broker.sock \
  --secret-file /etc/hf-broker/secrets \
  --home-dir /home/agent-a
```

The unYOLO CLI, MCP adapter, and Git helper load the owner-only
`~/.config/hf-broker/client.json` file directly. Do not source it or copy its
credential into shell startup files.

Ordinary Git HTTP clients cannot connect directly to a Unix socket. When Git
proxying is required, configure an explicit TCP listener or HTTPS reverse proxy
and use that deployment-owned URL as the Git remote.

## Verify

Check the service:

```sh
systemctl status hf-broker
curl --unix-socket /run/unyolo/huggingface/agent/broker.sock \
  -fsS http://localhost/healthz
```

Check local isolation:

```sh
hf-broker doctor \
  --agent-user agent-a \
  --broker-pid "$(pgrep -x hf-broker)" \
  --token-file /etc/hf-broker/hf-token
```

The doctor should report `ok` before trusting a same-host deployment.

Check generated policy integrity and catalog drift:

```sh
hf-broker doctor policy \
  --profile /etc/hf-broker/policy-profile.json \
  --scope /etc/hf-broker/scope.json \
  --manifest /etc/hf-broker/policy-manifest.json
```
