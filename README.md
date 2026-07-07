# hf-broker

hf-broker is a small self-hosted credential broker that sits between a
coding agent and Hugging Face. It lets the agent push to Hub repos
directly — no human click per change — while refusing anything
irreversible: force-pushes, branch and tag deletion, and tag moves are
rejected per request, and the agent never sees a real Hub token, only a
revocable broker secret.

It is the level-2 companion to
[hf-auth-helper](https://github.com/osolmaz/hf-auth-helper) (level 1,
propose-only): use hf-auth-helper for everything, and a broker remote for
the specific repos that need direct writes. The full design, threat
model, and roadmap (bucket proxy, time-boxed grants) are in
[docs/SPECIFICATION.md](docs/SPECIFICATION.md).

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
curl -fsSL https://raw.githubusercontent.com/osolmaz/hf-broker/main/install.sh | sh
```

Pin a release with `VERSION`:

```sh
curl -fsSL https://raw.githubusercontent.com/osolmaz/hf-broker/main/install.sh | VERSION=v0.1.0 sh
```

Install to a specific directory with `INSTALL_DIR`:

```sh
curl -fsSL https://raw.githubusercontent.com/osolmaz/hf-broker/main/install.sh | INSTALL_DIR="$HOME/.local/bin" sh
```

Manual install is also just a tarball download:

```sh
curl -LO https://github.com/osolmaz/hf-broker/releases/download/v0.1.0/hf-broker_linux_arm64.tar.gz
curl -LO https://github.com/osolmaz/hf-broker/releases/download/v0.1.0/checksums.txt
sha256sum -c checksums.txt --ignore-missing
tar -xzf hf-broker_linux_arm64.tar.gz
sudo install -m 0755 hf-broker /usr/local/bin/hf-broker
```

For development, install from source with Go 1.23+:

```sh
go install github.com/osolmaz/hf-broker/cmd/hf-broker@latest
```

## Run

```sh
export HF_BROKER_HF_TOKEN=hf_...            # upstream write token, outbound only
export HF_BROKER_SHARED_SECRET=$(openssl rand -hex 32)
cp scope.example.json scope.json         # edit: which repos are reachable
hf-broker
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

It also creates the `hf-broker` service user when needed, enables and
starts the service, then prints the broker URL and generated broker
client secret. The real Hugging Face token stays readable only by the
service. The agent receives only the broker client secret.

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

## Telegram Grants

Destructive git pushes are still refused by default. To make a narrow
exception, add a request rule for the repo in `scope.json` and
configure the broker host with a Telegram bot token and the single
operator chat id:

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

An authenticated client can then request a time-boxed grant:

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

## License

[MIT](LICENSE)
