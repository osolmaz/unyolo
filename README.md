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

Requires Go 1.23+ and `git` on the broker host.

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

`scope.json` lists the only repos the broker will touch:

```json
{
  "repos": [
    {"id": "osolmaz/scraped-news", "type": "dataset", "mode": "append-only"}
  ]
}
```

Binding defaults to `127.0.0.1:8080`. Expose it to the agent over a
Tailnet or equivalent — and run the broker somewhere the agent cannot
log into, otherwise the isolation is decoration. See the specification
for all environment variables.

## Point the agent at it

On the agent machine, the broker is just a git remote; the broker secret
is the password:

```sh
git remote set-url origin https://broker.tailnet:8080/datasets/osolmaz/scraped-news
git config credential.helper '!f() { echo username=agent; echo password=$HF_BROKER_SHARED_SECRET; }; f'
```

Clones, pulls, fast-forward pushes, new branches, and new tags work as
normal. A history rewrite is refused with a message at the terminal:

```text
 ! [remote rejected] main -> main (hf-broker: history rewrite refused)
```

## Telegram Grants

Destructive git pushes are still refused by default. To make a narrow
exception, configure the broker host with a Telegram bot token and the
single operator chat id:

```sh
export HF_BROKER_TELEGRAM_BOT_TOKEN=...
export HF_BROKER_TELEGRAM_CHAT_ID=123456789
```

An authenticated client can then request a time-boxed grant:

```sh
curl -sS -H "Authorization: Bearer $HF_BROKER_SHARED_SECRET" \
  -H "Content-Type: application/json" \
  -d '{
    "operation": "git_receive_pack",
    "target": "dataset/osolmaz/scraped-news",
    "ref": "refs/heads/main",
    "reason": "recover main after a bad commit",
    "minutes": 5
  }' \
  https://broker.tailnet:8080/grants
```

The broker sends the request to Telegram with Approve and Deny buttons
and long-polls the Bot API for the answer. There is no inbound Telegram
callback URL. A grant only covers the requested repo/ref, expires at the
approved time, and decisions from any chat except the configured operator
chat are ignored.

## License

[MIT](LICENSE)
