# Brokerkit Unification

hf-broker currently has the most complete install and Linux service setup path
in the broker family. That shape is the baseline, but the reusable parts should
move behind the shared brokerkit contract instead of remaining hf-broker-only.

The canonical shared contract is:

```text
github.com/osolmaz/brokerkit/docs/UNIFIED_BROKER_CONTRACT.md
```

## Current Status

Implemented in hf-broker today:

- release binary install documented through `install.sh`
- `hf-broker --version`
- `hf-broker setup systemd`
- `hf-broker setup client`
- dedicated `hf-broker` service user and group
- `/etc/hf-broker` config directory
- `/etc/hf-broker/secrets` named-client secret file
- `/etc/hf-broker/scope.json`
- `/etc/hf-broker/env`
- `/var/lib/hf-broker`
- `/etc/systemd/system/hf-broker.service`
- `hf-broker doctor isolation`
- Telegram-backed grant requests through brokerkit's reusable Telegram adapter

That UX should stay, but the implementation should stop being bespoke where the
behavior is shared by gh-broker and sudo-broker.

## What Moves To brokerkit

The following behavior should move to brokerkit or a brokerkit-owned helper
template:

- release installer behavior: platform detection, version selection, checksum
  verification, install-directory priority, and final version check
- common `setup systemd` parsing and validation
- service account creation helpers
- env, secrets, scope, state, and unit-file layout helpers
- `--dry-run` and `--no-start` behavior
- named-client secret generation and file rendering
- client setup file rendering under `~/.config/<broker>/client.env`
- strict config loading helpers
- broker client auth
- policy parsing and registry mechanics
- grants, approval state, idempotency, and use budgets
- shared Telegram transport and callback handling: implemented through
  brokerkit's reusable Telegram adapter; hf-broker now keeps only HF approval
  message composition and grant-decision application
- audit event schema and no-secret helpers
- common doctor checks for user separation, root-equivalent groups, secret file
  permissions, process environment reachability, socket access, and service
  state

## What Stays In hf-broker

hf-broker keeps only Hugging Face-specific behavior:

- Hugging Face token file flags and validation
- model, dataset, and space target mapping
- Hugging Face Git smart-HTTP routes
- LFS, Xet, and bucket behavior
- commits-only mirrors and ancestry checks
- append-only enforcement
- Hugging Face request classification
- Hugging Face-specific approval summaries
- Hugging Face-specific doctor probes

## Target Setup UX

Binary installation remains:

```sh
curl -fsSL https://raw.githubusercontent.com/osolmaz/hf-broker/main/install.sh | sh
```

Linux service setup remains:

```sh
sudo hf-broker setup systemd \
  --hf-token-file ./hf-token \
  --repo osolmaz/scraped-news \
  --repo-type dataset \
  --client bob
```

Client setup should converge on the shared shape:

```sh
hf-broker setup client \
  --client bob \
  --url http://127.0.0.1:8080 \
  --secret-file /etc/hf-broker/secrets \
  --home-dir /home/bob
```

The client setup command should write only broker client material for bob. It
must not write or print the Hugging Face token.

## Cutover Rules

- Do not keep two auth, policy, grant, approval, Telegram, audit, config, or
  installer runtimes.
- When a brokerkit helper replaces hf-broker-local setup code, delete the local
  duplicate in the same change.
- Preserve the public `hf-broker setup systemd` UX unless the brokerkit
  contract intentionally changes it for all brokers.
- Replace raw client-secret command-line flags with generated secrets by
  default, plus file or stdin input only when an operator supplies a secret.
- Keep `install.sh` binary-only. It must not create users or services.
- CI must test Telegram with a fake Bot API server or fake notifier. It must
  not send real Telegram messages.

## Test Gates

The brokerkit install/setup cutover is complete only when tests prove:

- `install.sh` follows the shared release and checksum behavior
- `setup systemd --dry-run` renders the expected paths without writing files
- `setup systemd --no-start` writes files in temp directories without enabling
  a real service
- generated client setup contains only broker URL and broker client secret
- local doctor checks still fail for root-equivalent agent users
- grant requests still use brokerkit approval state and Telegram transport
- audit output contains no Hugging Face token, broker secret, approval token,
  Telegram bot token, request body, pack contents, or raw upstream response

## Operations Cutover Status

Implemented:

- `install.sh` is a thin wrapper over the pinned Brokerkit installer.
- `setup client` delegates parsing, validation, bounded secret-file loading,
  config rendering, ownership, and secret-safe output to Brokerkit.
- `setup systemd` uses Brokerkit defaults, flags, path/account validation, and
  generated/file/stdin secret handling.
- systemd unit rendering uses Brokerkit's hardened service baseline with home
  access denied for hf-broker.
- privileged systemd installation now delegates service account creation,
  trusted directory preparation, atomic managed-file writes, ownership,
  hardened unit installation, and activation to Brokerkit. hf-broker provides
  only the bounded Hugging Face token, scope, environment, secret payload, and
  typed unit definition.
- root-equivalent group classification uses Brokerkit; Hugging Face token,
  process, socket, ACL, and active-probe checks remain provider-specific.
- the old raw `--shared-secret` argument and all replaced local helpers were
  removed as a direct cutover.
- the local account, UID/GID, mkdir, write/chmod/chown, command-runner, and
  `systemctl` helpers were deleted in the same cutover.
