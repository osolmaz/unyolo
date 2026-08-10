---
title: Configuration
description: Environment variables, file layout, client configuration, and host deployment configuration.
---

A broker reads settings from environment variables, protected files, and its policy file. Service
setup writes the environment variables to a systemd or launchd environment file.

## Naming convention

Common settings follow each broker's prefix, which is `HF_BROKER`, `GH_BROKER`, or `SUDO_BROKER`:

```text
<PREFIX>_AGENT_ENDPOINT
<PREFIX>_OPERATOR_ENDPOINT
<PREFIX>_DEVELOPMENT
<PREFIX>_NETWORK_EXPOSURE
<PREFIX>_SCOPE_FILE or <PREFIX>_POLICY_FILE
<PREFIX>_SECRETS_FILE
<PREFIX>_STATE_DIR
```

Secret-bearing settings should always be file paths in a deployment. Raw values in environment
variables exist for development, and the doctor reports inline credential values as inconclusive.

## hf-broker

| Variable | Notes |
| --- | --- |
| `HF_BROKER_AGENT_ENDPOINT` | Required. No default port exists. |
| `HF_BROKER_OPERATOR_ENDPOINT` | Must differ from the agent endpoint. |
| `HF_BROKER_GIT_ENDPOINT` | TCP endpoint for the Git data plane. |
| `HF_BROKER_DEVELOPMENT` | Enables foreground development mode. |
| `HF_BROKER_HF_TOKEN_FILE` | Preferred. Service-owned, mode `0600`. |
| `HF_BROKER_HF_TOKEN` | Development only. |
| `HF_BROKER_SHARED_SECRET` | Development only; production uses the secrets file. |
| `HF_BROKER_SCOPE_FILE` | Policy file. Absolute in production. |
| `HF_BROKER_SECRETS_FILE` | Named client secrets. |
| `HF_BROKER_STATE_DIR` | Absolute in production. |
| `HF_BROKER_XET_PYTHON` | Interpreter for the pinned Xet helper. |
| `HF_BROKER_TELEGRAM_BOT_TOKEN_FILE` | Protected file only. |
| `HF_BROKER_TELEGRAM_CHAT_ID` | Operator chat. |
| `HF_BROKER_ADMISSION_CONFIG` | Absolute, normalized path to the admission file. |

## gh-broker

| Variable | Notes |
| --- | --- |
| `GH_BROKER_AGENT_ENDPOINT` | Required. Production uses a protected Unix socket unless TCP is explicitly selected. |
| `GH_BROKER_OPERATOR_ENDPOINT` | Must differ from the agent endpoint. |
| `GH_BROKER_STATE_DIR` | Required and absolute in production. |
| `GH_BROKER_SCOPE_FILE` | Required and absolute in production. |
| `GH_BROKER_GITHUB_APP_PRIVATE_KEY_FILE` | GitHub App private key. |
| `GH_BROKER_GITHUB_TOKEN_FILE` | Development fallback token. |
| `GH_BROKER_GITHUB_WEBHOOK_SECRET_FILE` | Verifies `X-Hub-Signature-256`. |
| `GH_BROKER_GITHUB_HTTP_TIMEOUT` | Defaults to 30 seconds. |
| `GH_BROKER_GITHUB_STREAM_TIMEOUT` | Defaults to 600 seconds. |
| `GH_BROKER_MAX_RECEIVE_PACK_BYTES` | Defaults to 25 MiB. |
| `GH_BROKER_ENVIRONMENT` | Setting `production` makes the dev token fallback an unsafe doctor result. |
| `GH_BROKER_TELEGRAM_BOT_TOKEN_FILE` | Protected file only. |
| `GH_BROKER_TELEGRAM_CHAT_ID` | Operator chat. |
| `GH_BROKER_ADMISSION_CONFIG` | Absolute, normalized path to the admission file. |

`brokers/github/.env.example` in the repository carries the full annotated environment.

## sudo-broker

| Variable | Notes |
| --- | --- |
| `SUDO_BROKER_AGENT_ENDPOINT` | Required. |
| `SUDO_BROKER_OPERATOR_ENDPOINT` | Must differ from the agent endpoint. |
| `SUDO_BROKER_CATALOG_FILE` | Root-owned command catalog. |
| `SUDO_BROKER_POLICY_FILE` | Policy file. |
| `SUDO_BROKER_STATE_DIR` | Absolute in production. |
| `SUDO_BROKER_SHARED_SECRET` | Development only. |

The admission config is supplied as `sudo-broker serve --admission-config` rather than through the
environment.

## File layout

```text
/etc/<broker>/env
/etc/<broker>/secrets
/etc/<broker>/operator-secrets
/etc/<broker>/<policy-file>
/var/lib/<broker>/
/etc/systemd/system/<broker>.service
```

`/etc/<broker>` is root-owned and group-readable only where needed. Upstream credentials are
separate files owned by the service user or root, mode `0600`. `/var/lib/<broker>` is owned by the
service user.

The named client secret file format is shared:

```text
client-name = generated-secret
```

Secrets carry at least 32 bytes of entropy-equivalent material and are never printed by diagnostics
after setup.

## Default sockets

```text
/run/unyolo/huggingface/agent/broker.sock
/run/unyolo/huggingface/operator/broker.sock
/run/unyolo/github/agent/broker.sock
/run/unyolo/github/operator/broker.sock
/run/unyolo/sudo/agent/broker.sock
/run/unyolo/sudo/operator/broker.sock
```

unYOLO defines no default TCP port for any listener. The Git data plane requires an explicit
deployment-selected TCP endpoint because standard Git clients cannot use a Unix socket.

## Client config

`setup client` writes `~/.config/<broker>/client.json`, owner-readable only, using the closed
`unyolo.io/client/v1` schema:

```json
{
  "api_version": "unyolo.io/client/v1",
  "client_id": "agent-a",
  "agent_endpoint": "unix:///run/unyolo/provider/agent/broker.sock",
  "git_endpoint": "tcp://127.0.0.1:38471",
  "shared_secret": "broker-client-secret"
}
```

Broker CLIs, MCP adapters, and Git helpers load this file directly. Production clients do not
depend on shell startup files or inherited secrets.

## Admission config

An optional closed JSON object that must define every default and global value:

```json
{
  "requests_per_window": 60,
  "window_seconds": 60,
  "client_active": 25,
  "client_pending": 10,
  "global_active": 512,
  "global_executing": 64,
  "clients": {
    "automation-a": {
      "requests_per_window": 20,
      "window_seconds": 60,
      "active": 8,
      "pending": 4
    }
  }
}
```

Bounded to 64 KiB with an absolute, normalized path. Partial values, unknown clients, duplicate or
unknown fields, non-positive limits, pending limits above active limits, and client active limits
above the global active limit all fail startup.

## Telegram ingress config

```json
{
  "telegram_bot_token_file": "/etc/unyolo-telegram/telegram-bot-token",
  "telegram_chat_id": 123456789,
  "inbox_path": "/var/lib/unyolo-telegram/callbacks.db",
  "inbox_key_file": "/etc/unyolo-telegram/inbox-key",
  "routes": {
    "h": {
      "operator_endpoint": "unix:///run/unyolo/huggingface/operator/broker.sock",
      "operator_token_file": "/etc/unyolo-telegram/operator-token-h"
    }
  }
}
```

Route keys are `h`, `g`, and `s`. Duplicate or unknown fields, unsupported routes, relative secret
paths, and malformed endpoints are rejected.

## Env file parsing

`internal/config/envfile` reads the literal `KEY=VALUE` files setup generates. It bounds input to
1 MiB, rejects duplicate or malformed assignments, and does not interpret shell syntax. Explicit
process environment values take precedence in its overlay lookup.

Doctor commands use this parser so they can inspect installed configuration without inheriting the
systemd process environment. When an env file is selected it is authoritative.
