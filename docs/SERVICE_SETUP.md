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

## Grant State Cutover

The brokerkit grant cutover intentionally replaces the old hf-broker grant
file format. Before the first start of this version, stop hf-broker and archive
or remove `<state-dir>/grants/grants.json`. Existing grants are short-lived and
must be requested again; raw approval tokens from the old store are not
migrated.

## Install the Binary

Install the latest release globally:

```sh
curl -fsSL https://raw.githubusercontent.com/osolmaz/hf-broker/main/install.sh | sh
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
  --repo osolmaz/scraped-news \
  --repo-type dataset
```

The setup command creates:

```text
/etc/hf-broker/hf-token
/etc/hf-broker/secrets
/etc/hf-broker/scope.json
/etc/hf-broker/env
/var/lib/hf-broker
/etc/systemd/system/hf-broker.service
```

The real Hugging Face token is copied to:

```text
/etc/hf-broker/hf-token
```

That file is owned by `hf-broker:hf-broker` and mode `0600`.

The broker client secret is stored in:

```text
/etc/hf-broker/secrets
```

That file is also owned by `hf-broker:hf-broker` and mode `0600`. The setup
command prints the generated client secret once so it can be given to the
agent.

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
