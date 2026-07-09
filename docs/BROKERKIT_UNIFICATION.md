# Brokerkit Unification

gh-broker should use the same install, setup, client config, policy, approval,
audit, doctor, and release contract as hf-broker and sudo-broker.

The canonical shared contract is:

```text
github.com/osolmaz/brokerkit/docs/UNIFIED_BROKER_CONTRACT.md
```

## Current Status

Implemented today:

- global Go binary can be built and installed manually
- `gh-broker --version`
- `install.sh`
- release tarballs and checksums through `scripts/release.sh`
- `gh-broker setup client`
- `gh-broker setup systemd --dev-token-fallback`
- Echo HTTP server
- named client id through `GH_BROKER_CLIENT_ID`
- shared secret through `GH_BROKER_SHARED_SECRET`
- named client secret file through `GH_BROKER_SECRETS_FILE`
- server-side GitHub token through `GH_BROKER_GITHUB_TOKEN_FILE`
- GitHub App credentials through `GH_BROKER_GITHUB_APP_ID_FILE` and
  `GH_BROKER_GITHUB_APP_PRIVATE_KEY_FILE`
- GitHub App installation-token minting for repo-scoped upstream requests
- GitHub App installation repository listing for `/api/repos`
- policy file through `GH_BROKER_SCOPE_FILE`
- state directory through `GH_BROKER_STATE_DIR`
- optional Telegram approval through `GH_BROKER_TELEGRAM_BOT_TOKEN` and
  `GH_BROKER_TELEGRAM_CHAT_ID`
- brokerkit-backed generated grants and `/api/grants`
- Git smart-HTTP fetch and receive-pack route shape
- narrow GitHub REST routes for repo listing, content reads, and PR creation

Not implemented yet:

- brokerkit audit helpers
- verified GitHub webhook endpoint for installation cache invalidation
- runtime GitHub branch ruleset doctor checks

## What Moves To brokerkit

The following pieces should be shared through brokerkit or a brokerkit-owned
template:

- release installer behavior
- common setup command parsing and validation
- systemd setup helpers
- service user and file ownership helpers
- named-client secret generation and storage
- client config rendering under `~/.config/gh-broker/client.env`
- broker client auth
- policy parser, registry mechanics, decisions, generated grants, and grant
  policy bounds
- approval lifecycle and Telegram callback handling
- audit event schema and no-secret helpers
- common doctor checks
- storage helpers for grant and state files
- generic Git smart-HTTP parsing only where the same API is also used by
  hf-broker

## What Stays In gh-broker

gh-broker keeps GitHub-specific behavior:

- GitHub App private key and app id validation
- GitHub App JWT signing
- installation token minting
- installation and repo visibility lookup
- GitHub REST and Git smart-HTTP forwarding
- PR create, update, and merge semantics
- webhook verification and installation cache invalidation
- ruleset and branch-protection interpretation
- GitHub request classification
- GitHub-specific approval summaries
- GitHub-specific audit extension fields, such as request ids or installation
  ids

brokerkit must not learn GitHub App, PR, webhook, branch protection, ruleset,
or installation-token semantics.

## Target Setup UX

Binary install:

```sh
curl -fsSL https://raw.githubusercontent.com/osolmaz/gh-broker/main/install.sh | sh
```

Linux service setup:

```sh
sudo gh-broker setup systemd \
  --github-app-id-file ./app-id \
  --github-app-private-key-file ./private-key.pem \
  --github-webhook-secret-file ./webhook-secret \
  --scope-file ./scope.json
```

Development fallback setup may continue to support a PAT file:

```sh
sudo gh-broker setup systemd \
  --github-token-file ./github-token \
  --scope-file ./scope.json \
  --dev-token-fallback
```

Client setup should converge on:

```sh
gh-broker setup client \
  --client bob \
  --url http://127.0.0.1:8081 \
  --secret-file /etc/gh-broker/secrets \
  --home-dir /home/bob
```

The client setup command should write only broker URL and broker client secret.
It must not write or print a GitHub token, GitHub App private key, webhook
secret, installation token, or token metadata.

Production Linux service setup should use GitHub App credential files. The
explicit `--dev-token-fallback` mode remains available for local development
and smoke tests with a narrowly scoped token file.

## Default Linux Layout

Target files:

```text
/etc/gh-broker/env
/etc/gh-broker/secrets
/etc/gh-broker/scope.json
/etc/gh-broker/github-app-id
/etc/gh-broker/github-app-private-key.pem
/etc/gh-broker/github-webhook-secret
/etc/gh-broker/github-token        # dev fallback only
/var/lib/gh-broker
/etc/systemd/system/gh-broker.service
```

Production should prefer GitHub App credentials. The PAT file is only a local
development fallback.

## Cutover Rules

- Do not keep two auth, policy, grant, approval, audit, config, or installer
  runtimes.
- When brokerkit owns a shared behavior, delete the gh-broker-local duplicate
  in the same change.
- Generate broker client secrets by default. If an operator supplies a client
  secret, read it from a file or stdin, never from a raw command-line argument.
- Keep GitHub request classification and execution local.
- Keep `install.sh` binary-only. It must not create services or credentials.
- Keep broker client secrets in `/etc/gh-broker/secrets` and configure the
  server through `GH_BROKER_SECRETS_FILE`; do not place raw broker secrets or
  GitHub tokens in `/etc/gh-broker/env`.
- CI must use fake GitHub upstreams, fake installation-token minting, and fake
  notifiers. It must not mutate real GitHub repositories or send real Telegram
  messages.

## Test Gates

The brokerkit install/setup cutover is complete only when tests prove:

- `install.sh` follows the shared release and checksum behavior
- `setup systemd --dry-run` renders expected GitHub App and dev-token files
  without writing them
- `setup systemd --no-start` writes files in temp directories without enabling
  a real service
- generated client config contains only broker URL and broker client secret
- policy decisions use brokerkit and GitHub classification fails closed
- requestable operations can be approved through a fake brokerkit notifier
- Telegram approval is covered with a fake Bot API server and no live bot token
- audit output contains no GitHub token, GitHub App private key, installation
  token, webhook secret, broker secret, approval token, Telegram bot token,
  request body, PR body, pack contents, or raw upstream response
