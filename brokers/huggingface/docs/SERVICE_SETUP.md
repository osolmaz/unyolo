# Linux Service Setup

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

Install from a reviewed BrokerKit commit:

```sh
BROKERKIT_REV=<verified-40-character-commit-sha>
curl -fsSL "https://raw.githubusercontent.com/osolmaz/brokerkit/$BROKERKIT_REV/brokers/huggingface/install.sh" | sh
```

## Configure systemd

Create a local file containing the upstream Hugging Face token:

```sh
printf '%s\n' 'hf_...' > ./hf-token
chmod 600 ./hf-token
```

For Telegram approvals, also create a local bot-token file:

```sh
printf '%s\n' '123456:bot-token' > ./telegram-bot-token
chmod 600 ./telegram-bot-token
```

Then configure the broker service:

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

The setup command creates:

```text
/etc/hf-broker/hf-token
/etc/hf-broker/telegram-bot-token
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

Brokerkit performs the privileged host installation. hf-broker supplies the
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

The operator inbox credential is generated independently at
`/etc/hf-broker/operator-secrets`, also mode `0600`. Systemd owns separate
agent and operator sockets under `/run/brokerkit/huggingface/`, with access
controlled by distinct groups. Agents receive neither the operator credential
nor access to the operator socket through their client configuration.

When Telegram is configured, its token is copied to
`/etc/hf-broker/telegram-bot-token` with the same ownership and mode. The
service environment contains the token-file path and operator chat ID, never
the token value.

Rerun setup without both Telegram flags to disable Telegram. Setup writes the
Telegram-free environment, restarts the service, waits for `/healthz`, and only
then removes `/etc/hf-broker/telegram-bot-token`. A failed restart or readiness
check leaves the token file in place for recovery. `--no-start` also preserves
the token file because the new configuration has not been activated.

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
  --endpoint unix:///run/brokerkit/huggingface/agent/broker.sock \
  --secret-file /etc/hf-broker/secrets \
  --home-dir /home/agent-a
```

Source that file before running the BrokerKit CLI or MCP adapter:

```sh
. "$HOME/.config/hf-broker/client.env"
```

Ordinary Git HTTP clients cannot connect directly to a Unix socket. When Git
proxying is required, configure an explicit TCP listener or HTTPS reverse proxy
and use that deployment-owned URL as the Git remote.

## Verify

Check the service:

```sh
systemctl status hf-broker
curl --unix-socket /run/brokerkit/huggingface/agent/broker.sock \
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
