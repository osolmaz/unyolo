# Linux Service Setup

`hf-broker` is a server. For a real same-host deployment, run it as a
dedicated service user and let the agent talk to it over HTTP.

Recommended account model:

```text
onur      = admin account
bob       = agent account, no sudo and no docker
hf-broker = service account that can read the real Hugging Face token
```

The agent should not read or store the real Hugging Face token. It should
only know a broker client secret.

## Install the Binary

Install the latest release globally:

```sh
curl -fsSL https://raw.githubusercontent.com/osolmaz/brokerkit/main/brokers/huggingface/install.sh | sh
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
  --client bob
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
`/etc/hf-broker/operator-secrets`, also mode `0600`. The service exposes the
operator API on `127.0.0.1:8081` by default. Agents receive neither this
credential nor access to that listener through their client configuration.

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
administrator to write the matching broker URL and client secret directly into
the agent account's private configuration.

## Agent Setup

Point the agent repo at the broker URL printed by setup:

```sh
git remote set-url origin http://127.0.0.1:8080/datasets/osolmaz/scraped-news
```

Configure the agent's git credential helper with the broker client secret:

```sh
git config credential.helper '!f() { echo username=agent; echo password=$HF_BROKER_SHARED_SECRET; }; f'
```

Bob does not run the broker as Onur. Bob talks to a local server. The server
runs as the `hf-broker` service user.

## Verify

Check the service:

```sh
systemctl status hf-broker
curl -fsS http://127.0.0.1:8080/healthz
```

Check local isolation:

```sh
hf-broker doctor \
  --agent-user bob \
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
