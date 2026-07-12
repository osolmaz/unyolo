# sudo-broker

> [!IMPORTANT]
> This standalone repository is deprecated and archived. Development moved to
> [BrokerKit's sudo broker](https://github.com/osolmaz/brokerkit/tree/main/brokers/sudo).
> This repository receives no further updates.

sudo-broker is a broker for Unix privilege transitions.
It lets an agent request tightly scoped access to run commands or start a
short-lived shell as another local user, while policy, approvals, and audit stay
outside the agent account.

sudo-broker is not a sudo replacement. It is an approval and policy layer that
uses mature local primitives such as `sudo`, `systemd-run`, launchd helpers, or
a small root-owned host agent for the actual user switch.

The shared broker-family install and setup cutover is tracked in
[docs/BROKERKIT_UNIFICATION.md](docs/BROKERKIT_UNIFICATION.md).

## Intended Shape

```text
agent user
  ↓
sudo-broker CLI or API
  ↓
brokerkit auth, policy, grants, approvals, notify, audit
  ↓
phone/operator approval when required
  ↓
host executor
  ↓
command or shell as target Unix user
```

Fixed commands can be scoped by command id, arguments, timeout, working
directory, environment, and target user.

Shell sessions are different. A shell grant means the caller may act as the
target user for the approved time window. It cannot safely be command-scoped
inside the shell. Explicit shell selectors must be `login` or an exact
approved absolute shell path, not just any path with a shell-like basename.

## Example Policy

```json
{
  "rules": [
    {
      "id": "bob-can-request-deploy-shell",
      "effect": "request",
      "clients": ["bob"],
      "operations": ["session.shell"],
      "targets": [{"kind": "user", "name": "deploy"}],
      "grant_policy": {
        "mode": "window",
        "default_minutes": 5,
        "max_minutes": 10,
        "default_max_uses": 1,
        "max_uses": 1
      }
    }
  ]
}
```

## Status

The brokerkit cutover and Unix execution path are implemented.

Implemented:

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
- `sudo-broker setup systemd` on Linux
- global binary installer and release asset script
- sudo-broker's brokerkit policy registry
- strict command catalog parsing and classification
- brokerkit-backed request, approval, active-grant, reserve, and consume flow
- HTTP API for fixed-command execution and grant request/list/status
- HTTP API for approved shell session start/list/terminate
- Telegram approval using brokerkit's reusable Telegram transport
- a dedicated Brokerkit operator inbox listener with bounded list, detail,
  event, approve, deny, cancel, and revoke APIs
- durable approval requests when Telegram is disabled or temporarily
  unavailable; Telegram and the operator inbox decide the same grant state
- durable approval-message references and restart-safe lifecycle status delivery
- ambiguous approval sends fail closed through a durable claim lease; a later
  retry rotates the one-time decision token before sending again
- verified Telegram callbacks atomically store the decision and editable
  message reference; durable write failures stay unanswered for retry
- grant requests require `client_request_id`; retained grants report
  `status: retained` with zero usable capacity
- fake-notifier tests for the approval path
- fixed-command executor orchestration with fake-runner tests
- non-interactive `sudo -u` compatibility runner code path with sudo list
  preflight, non-cached auth preflight, separate sudo `-D` cwd probe, dynamic
  process-group cleanup preflight, sudo-applied cwd, non-secret
  command-template grant binding, key-only target-env preservation, and
  start/end audit metadata
- Linux systemd setup that writes root-owned config, secrets, state, and unit
  files without putting broker or Telegram secrets in the environment file
- broker-managed shell session lifecycle for approved `session.shell` grants:
  session id allocation, grant consumption, start/list/terminate endpoints,
  expiry-bounded process lifetime, and start/end audit metadata
- authenticated interactive PTY attach over WebSocket, including terminal
  resize, single-owner attachment, disconnect cleanup, and grant-expiry cleanup
- `sudo-broker doctor isolation` for Linux and macOS identity, listener,
  credential, policy/catalog, and state-path isolation checks
- root-owned credential-switch command and PTY execution on Linux and macOS
- fail-closed grant settlement: failures before a command or shell starts
  release the reservation, while uncertain post-start bookkeeping retains the
  use and closes further access

On macOS, run the daemon as root with `--runner setuid`, directly or under a
root-owned launchd job. The binary-only installer deliberately does not create
or modify services.

## Install

Install the latest release globally:

```sh
curl -fsSL https://raw.githubusercontent.com/osolmaz/sudo-broker/main/install.sh | sh
```

Pinned install:

```sh
curl -fsSL https://raw.githubusercontent.com/osolmaz/sudo-broker/main/install.sh | VERSION=v0.1.0 sh
```

## Server

Run a local broker process:

```sh
sudo-broker serve \
  --policy /etc/sudo-broker/policy.json \
  --catalog /etc/sudo-broker/catalog.json \
  --secrets /etc/sudo-broker/secrets \
  --grants /var/lib/sudo-broker/grants.json \
  --bind-addr 127.0.0.1:8082 \
  --operator-bind-addr 127.0.0.1:8083 \
  --operator-secrets /etc/sudo-broker/operator-secrets
```

Add Telegram approval:

```sh
sudo-broker serve \
  --policy /etc/sudo-broker/policy.json \
  --catalog /etc/sudo-broker/catalog.json \
  --secrets /etc/sudo-broker/secrets \
  --telegram-bot-token "$SUDO_BROKER_TELEGRAM_BOT_TOKEN" \
  --telegram-chat-id "$SUDO_BROKER_TELEGRAM_CHAT_ID"
```

The operator listener is separate from the agent listener. Its credential is
for trusted backends such as mlclaw and must never be placed in an agent's
client config or sent to a browser. Telegram is optional; pending approvals
remain available through the operator inbox when it is absent or unavailable.

On Linux, production service setup uses the root-owned `setuid` runner. For
same-user smoke tests use `--runner direct`; for constrained sudo-based
deployments use `--runner sudo` with matching sudoers rules.

## Linux Service Setup

`setup systemd` installs the broker as a root-owned systemd service layout. It
does not put raw broker client secrets, operator secrets, or Telegram bot
tokens in the environment file.

Dry-run first:

```sh
sudo-broker setup systemd \
  --policy-file ./policy.json \
  --catalog-file ./catalog.json \
  --host "$(hostname)" \
  --dry-run
```

Write files without starting the service:

```sh
sudo sudo-broker setup systemd \
  --policy-file ./policy.json \
  --catalog-file ./catalog.json \
  --host "$(hostname)" \
  --no-start
```

Enable Telegram approval by supplying a private token file and chat id:

```sh
sudo sudo-broker setup systemd \
  --policy-file ./policy.json \
  --catalog-file ./catalog.json \
  --telegram-bot-token-file ./telegram-token \
  --telegram-chat-id "$TELEGRAM_CHAT_ID"
```

Rerunning setup without both Telegram flags disables Telegram and deletes the
managed token only after the restarted broker passes its health check.
`--no-start` writes the new configuration without retiring the old token.

Default Linux paths:

```text
/etc/sudo-broker/env
/etc/sudo-broker/secrets
/etc/sudo-broker/operator-secrets
/etc/sudo-broker/policy.json
/etc/sudo-broker/catalog.json
/var/lib/sudo-broker/grants.json
/etc/systemd/system/sudo-broker.service
```

The generated service uses `SUDO_BROKER_RUNNER=setuid` by default. The daemon
must run as root, then it switches only to the catalog-declared target user and
executes the catalog argv directly without sudo or a shell. The `sudo` runner is
an explicit compatibility backend for hosts that choose sudoers-based
enforcement.

## Client Setup

`setup client` writes only broker client material:

```sh
sudo-broker setup client \
  --client bob \
  --url http://127.0.0.1:8082 \
  --secret-file /etc/sudo-broker/secrets \
  --home-dir /home/bob
```

The generated `client.env` contains `SUDO_BROKER_URL` and
`SUDO_BROKER_SHARED_SECRET`. It does not contain target-user credentials,
approval tokens, command output, session transcripts, or privileged helper
material.

After setup, bob can call:

```sh
sudo-broker request exec smoke-true --reason "need to run the declared command"
sudo-broker grants
sudo-broker run smoke-true
```

Request commands generate a `client_request_id` automatically. Reuse an
explicit `--client-request-id` when retrying the same logical request.

For shell access, bob first requests an identity grant and then starts a
broker-managed session after approval:

```sh
sudo-broker request shell --as deploy --reason "debug deploy state" --minutes 5
sudo-broker shell --as deploy
sudo-broker sessions
sudo-broker terminate <session-id>
```

The interactive shell owns the local terminal until it exits, disconnects, or
the approved grant expires. Output and transcripts are not stored by default.

Verify the installed boundary with:

```sh
sudo-broker doctor isolation --agent-user bob --target-user deploy
```

## License

[MIT](LICENSE)
