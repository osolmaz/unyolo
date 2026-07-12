# Brokerkit Unification

sudo-broker should use the same install, setup, client config, policy, approval,
audit, doctor, and release contract as hf-broker and gh-broker. The Unix
execution boundary stays local to sudo-broker.

The canonical shared contract is:

```text
github.com/osolmaz/brokerkit/docs/UNIFIED_BROKER_CONTRACT.md
```

## Current Status

The shared Brokerkit control-plane runtime now owns grant storage, client and
operator authentication, the operator API, audit wiring, and Telegram decision
mapping. Sudo Broker supplies only Unix policy, execution, session behavior,
and operator presentation. Operator credentials use the common
`name = secret` format in `/etc/sudo-broker/operator-secrets`; setup retires
the old raw `operator-secret` file only after the restarted broker is healthy.

Implemented today:

- global CLI binary
- `sudo-broker --version`
- `sudo-broker serve`
- `sudo-broker run`
- `sudo-broker request exec`
- `sudo-broker request shell`
- `sudo-broker shell`
- `sudo-broker sessions`
- `sudo-broker terminate`
- `sudo-broker grants`
- `sudo-broker setup client`
- `sudo-broker check`
- `sudo-broker exec`
- `install.sh`
- `sudo-broker setup systemd` on Linux
- release tarballs and checksums through `scripts/release.sh`
- policy loading through brokerkit
- command catalog loading and validation
- direct runner for same-user smoke tests
- sudo compatibility runner code path
- local authenticated HTTP API for exec and grants
- local authenticated HTTP API for shell session start, list, and terminate
- Telegram approval through brokerkit's shared Telegram transport
- shared control-plane assembly for grant storage, client/operator auth,
  operator API, audit wiring, and Telegram decisions
- shared named-secret parsing, coverage measurement, and deterministic release archives
- durable notification claims, message references, and restart-safe status
  delivery through brokerkit grants
- atomic Telegram callback decisions with durable retry and callback-carried
  message-reference recovery
- required idempotency keys on API grant requests
- fail-closed retained reservations for uncertain post-start execution results
- fake notifier and fake runner tests
- root-owned Linux systemd service setup files with private secret files and a
  non-secret environment file
- direct root-owned Linux user-switch execution through the `setuid` runner
- broker-managed shell session lifecycle for approved `session.shell` grants
- interactive PTY attach with resize and disconnect cleanup
- Linux/macOS root-owned credential-switch execution
- Linux/macOS `doctor isolation` using Brokerkit common checks plus Unix
  privilege-boundary checks

The current global CLI plus `serve` command is useful as the broker control
plane. On Linux, `setup systemd` installs the production service layout and
defaults to the root-owned `setuid` executor. Hosts can still opt into the sudo
compatibility runner with `--runner sudo`.

On macOS, the same daemon runs as root with `--runner setuid`, either directly
or from a root-owned launchd job. Service creation remains outside the
binary-only installer.

## What Moves To brokerkit

The following behavior should be shared through brokerkit or a brokerkit-owned
template:

- release installer behavior
- common setup command parsing and validation
- systemd setup helpers
- service user and file ownership helpers
- named-client secret generation and storage
- client config rendering under `~/.config/sudo-broker/client.env`
- broker client auth
- policy parser, registry mechanics, decisions, generated grants, and grant
  policy bounds
- approval lifecycle and Telegram callback handling
- audit event schema and no-secret helpers
- common doctor checks
- storage helpers for grant and state files

## What Stays In sudo-broker

sudo-broker keeps Unix-specific behavior:

- local user and group lookup
- host identity checks
- command catalog parsing and normalization
- command digest generation over non-secret command metadata
- shell selector validation
- TTY and session lifecycle
- sudo compatibility executor
- direct root-owned Linux user-switch execution
- systemd-run, launchd, or privileged helper execution
- local isolation checks specific to Unix privilege boundaries
- sudo-specific approval summaries
- sudo-specific audit extension fields, such as executor, target user, command
  id, session id, exit code, and timeout status

brokerkit must not learn how to run commands, open shells, switch users, manage
TTYs, or interpret sudoers.

## Target Setup UX

Binary install:

```sh
curl -fsSL https://raw.githubusercontent.com/osolmaz/sudo-broker/main/install.sh | sh
```

Linux service setup:

```sh
sudo sudo-broker setup systemd \
  --policy-file ./policy.json \
  --catalog-file ./catalog.json \
  --host "$(hostname)"
```

Client setup:

```sh
sudo-broker setup client \
  --client bob \
  --url http://127.0.0.1:8082 \
  --secret-file /etc/sudo-broker/secrets \
  --home-dir /home/bob
```

The client setup command should write only broker URL and broker client secret
for bob. It must not write target-user credentials, approval tokens, command
output, session transcripts, or privileged helper material.

## Default Linux Layout

Target files:

```text
/etc/sudo-broker/env
/etc/sudo-broker/secrets
/etc/sudo-broker/operator-secrets
/etc/sudo-broker/policy.json
/etc/sudo-broker/catalog.json
/var/lib/sudo-broker
/var/lib/sudo-broker/grants.json
/etc/systemd/system/sudo-broker.service
```

Ownership rules:

- policy, catalog, env, client secret, operator secret, Telegram token, and state
  files are root-owned by default and not writable by the agent or target user
- broker client secrets and operator secrets are service-private files, not
  environment values
- privileged sockets are not writable by the agent except through the intended
  broker protocol
- command output and shell transcripts are not logged by default

## Service Shape

Production sudo-broker should be a daemon or daemon plus helper. The daemon
owns policy, grants, approvals, audit, and request classification. The
privileged backend owns only the user switch and process/session lifecycle.

Acceptable Linux backends:

1. root-owned sudo-broker daemon with direct user-switch execution
2. service daemon plus small root-owned helper
3. `systemd-run --uid` backend when systemd session semantics are desired
4. tightly scoped `sudo -u` compatibility backend for development and
   constrained deployments

The backend must be explicit in audit records.

## Cutover Rules

- Do not add a sudo clone or shell command parser.
- Do not authorize arbitrary argv strings.
- Do not keep a second policy or grant runtime outside brokerkit.
- When brokerkit owns a shared behavior, delete the sudo-broker-local duplicate
  in the same change.
- Generate broker client secrets by default. If an operator supplies a client
  secret, read it from a file or stdin, never from a raw command-line argument.
- Keep command catalog parsing, execution, shell/session handling, and local
  isolation checks in sudo-broker.
- Keep `install.sh` binary-only. It must not create services or privileged
  helpers.
- CI must use fake notifiers and fake executors by default. It must not require
  root, mutate real user accounts, or send real Telegram messages.

## Test Gates

The brokerkit install/setup cutover is complete only when tests prove:

- `install.sh` follows the shared release and checksum behavior
- `setup systemd --dry-run` renders expected policy, catalog, env, state, grant,
  secret, and unit paths without writing them
- `setup systemd --no-start` writes files in temp directories without enabling
  a real service
- generated client config contains only broker URL and broker client secret
- local doctor fails for root-equivalent agent users and unsafe file ownership
- fixed command requests are reclassified from the catalog before policy
- generated grants are evaluated by brokerkit before any executor is called
- shell grants expire and terminate or refuse the session
- notification delivery resumes from the grant file after restart and does not
  duplicate approval sends
- ambiguous sends remain blocked through their lease and rotate the decision
  token before a later retry
- callback decisions and message references commit atomically; durable failures
  do not advance or answer the Telegram update
- retained grants expose zero usable capacity
- failed Telegram status edits remain due for retry
- pre-start failures release reservations, while uncertain post-start results
  retain the use and close further grant access
- audit output contains no broker secret, approval token, command input,
  command output, session transcript, Telegram bot token, or target-user secret
