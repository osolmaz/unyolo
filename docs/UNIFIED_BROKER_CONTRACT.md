# Unified Broker Contract

This is the shared contract for `hf-broker`, `gh-broker`, and `sudo-broker`.
The goal is one install, setup, config, policy, approval, audit, and release
shape, with only the dangerous platform adapter kept in each broker.

The model is cutover. When a broker adopts one part of this contract, the old
broker-local duplicate should be removed in the same change.

## Boundary

brokerkit owns the reusable broker control plane:

- binary install conventions
- service setup helpers and file layout conventions
- client setup conventions
- strict config and secret-file helpers
- named-client authentication
- policy schema and registry mechanics
- grant lifecycle
- approval workflow
- notification interfaces and shared Telegram transport
- audit event schema and no-secret helpers
- local durable storage helpers
- doctor check building blocks
- release asset conventions

Each broker owns only its platform adapter:

- `hf-broker`: Hugging Face Git, LFS, Xet, Hub tokens, mirrors, and HF wording
- `gh-broker`: GitHub REST/Git, GitHub App tokens, PRs, webhooks, rulesets, and
  GitHub wording
- `sudo-broker`: Unix users, command catalogs, shells, sudo/systemd/launchd or
  privileged helpers, and Unix wording

brokerkit must not grow provider-specific credentials, API calls, command
execution, or user-facing approval text.

## Binary Install

Every broker binary should have the same install shape:

```sh
curl -fsSL https://raw.githubusercontent.com/osolmaz/<broker>/main/install.sh | sh
```

Common environment variables:

```text
VERSION      optional release tag, for example v0.1.0
INSTALL_DIR  optional install directory
```

The installer should:

- detect `linux` and `darwin`
- detect `amd64` and `arm64`
- download the release tarball for the selected version
- download and verify `checksums.txt`
- install only the binary
- prefer `$INSTALL_DIR`, then `/usr/local/bin` with `sudo`, then
  `$HOME/.local/bin`
- print the installed binary path and `--version`

The installer must not create users, service files, config files, token files,
launchd plists, or systemd units. Privileged setup is a separate command.

## Release Assets

Every broker release should publish:

```text
<broker>_linux_amd64.tar.gz
<broker>_linux_arm64.tar.gz
<broker>_darwin_amd64.tar.gz
<broker>_darwin_arm64.tar.gz
checksums.txt
```

Each tarball should contain:

```text
<broker>
README.md
LICENSE
```

Every broker should support:

```sh
<broker> --version
<broker> version
```

## Privileged Setup

Linux service setup should use one common UX:

```sh
sudo <broker> setup systemd [broker-specific flags]
```

Common flags:

```text
--user <name>          default: <broker>
--group <name>         default: <broker>
--config-dir <path>    default: /etc/<broker>
--state-dir <path>     default: /var/lib/<broker>
--systemd-dir <path>   default: /etc/systemd/system
--binary <path>        default: resolved current binary
--client <name>        default: bob or broker-specific default
--shared-secret <s>    optional; generated when omitted
--bind-addr <addr>     default: 127.0.0.1
--port <port>          broker-specific default
--dry-run
--no-start
```

`setup systemd` should:

- require root unless a test-only flag is used
- create the broker service user and group when missing
- create root-owned config directories
- create service-owned private secret files
- create service-owned state directories
- write an env file
- write the broker policy file
- write the systemd unit
- enable and start the service unless `--no-start` is set
- print the broker URL and client setup instructions

The exact broker-specific secret files stay broker-local. Examples:

- `hf-broker`: Hugging Face token file
- `gh-broker`: GitHub App private key, app id, webhook secret, or dev PAT file
- `sudo-broker`: command catalog, policy, host identity, privileged helper or
  sudo compatibility configuration

## File Layout

The default Linux layout should be:

```text
/etc/<broker>/env
/etc/<broker>/secrets
/etc/<broker>/scope.json
/var/lib/<broker>/
/etc/systemd/system/<broker>.service
```

Rules:

- `/etc/<broker>` is root-owned and group-readable only when needed.
- `/etc/<broker>/secrets` contains named broker clients and their broker
  client secrets.
- Upstream credentials are separate files, owned by the service user or root as
  required, mode `0600`.
- `/var/lib/<broker>` is owned by the service user.
- Agents receive only broker client config, never upstream credentials.

The named client secret file format is shared:

```text
client-name = generated-secret
```

Secrets must be at least 32 bytes of entropy-equivalent material and must never
be printed by diagnostics after initial setup.

## Environment

Common environment names should follow each broker prefix:

```text
<PREFIX>_BIND_ADDR
<PREFIX>_PORT
<PREFIX>_SCOPE_FILE
<PREFIX>_SECRETS_FILE
<PREFIX>_STATE_DIR
```

Broker-specific secret fields should prefer file paths:

```text
HF_BROKER_HF_TOKEN_FILE
GH_BROKER_GITHUB_APP_PRIVATE_KEY_FILE
GH_BROKER_GITHUB_TOKEN_FILE
SUDO_BROKER_CATALOG_FILE
```

Raw secret values in environment variables may exist for development, but
service setup should prefer file paths.

## Client Setup

Every broker should expose the same client setup concept:

```sh
<broker> setup client --client bob [flags]
```

That command should write a client-owned config file under:

```text
~/.config/<broker>/client.env
```

The file should contain only:

```text
<PREFIX>_BROKER_URL=<url>
<PREFIX>_BROKER_SHARED_SECRET=<client-secret>
```

It may also write Git credential helper snippets when the broker speaks Git.
The client setup must not write upstream provider credentials.

## Policy

brokerkit owns the policy schema and decision engine. Brokers register their
operation, target, and attr vocabulary.

Common rule shape:

```json
{
  "rules": [
    {
      "id": "example",
      "effect": "allow",
      "clients": ["bob"],
      "operations": ["operation.name"],
      "targets": [{"kind": "target-kind"}],
      "attrs": {},
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

Decision order is shared:

```text
deny > active generated grant > allow > request > no_match
```

Unknown operations, target kinds, attrs, and fields fail closed unless the
broker registry explicitly allows them.

## Grants And Approval

brokerkit owns:

- pending, active, denied, expired, consumed, canceled, and revoked states
- idempotency keys
- request TTL
- approved access duration
- use budgets and reservations
- generated temporary allow rules
- approval tokens
- approve, deny, cancel, revoke, and status update flows
- Telegram callback parsing and verification

Brokers own the approval summary text and the provider-specific fields shown to
the operator.

The common HTTP API is:

```text
GET  /healthz
POST /api/grants
GET  /api/grants
GET  /api/grants/{id}
POST /api/grants/{id}/approve
POST /api/grants/{id}/deny
POST /api/grants/{id}/revoke
```

Brokers may add platform-specific routes, such as Git smart-HTTP routes,
GitHub pull request routes, or sudo session routes.

## Audit

Every broker should emit JSON audit events with the same common fields:

```text
time
broker
client
operation
target
attrs
decision
reason
matched_rule_ids
grant_id
approver
status
duration
error_code
extensions
```

Audit output must never include:

- upstream tokens
- broker client secrets
- approval tokens
- Telegram bot tokens
- request bodies that may contain secrets
- Git pack contents
- command input or command output by default
- raw upstream responses
- token metadata

Broker-specific metadata belongs under typed extension fields.

## Doctor Checks

Every broker should provide:

```sh
<broker> doctor
<broker> doctor isolation
```

brokerkit should provide reusable doctor helpers for:

- service user and agent user separation
- root-equivalent group checks
- config and secret file ownership and mode checks
- state directory ownership checks
- process environment readability checks
- socket readability and writability checks
- service status checks
- secret-safe JSON output

Brokers add provider-specific checks:

- `hf-broker`: Hugging Face token file, mirrors, and Git/LFS reachability
- `gh-broker`: GitHub App credentials, installation token minting, webhook
  secret, ruleset visibility
- `sudo-broker`: command catalog, target users, sudo/systemd/launchd helper
  permissions, privileged socket, and execution backend safety

## Test Contract

Every broker cutover should test:

- install script platform selection and checksum handling
- `setup systemd --dry-run`
- `setup systemd --no-start` file rendering in temp directories
- service unit content without starting real services in CI
- client config rendering without printing secrets
- auth accepts valid clients and rejects invalid clients
- policy rejects unknown operations, targets, attrs, and fields
- deny overrides active grants
- generated grants match only the approved client, operation, target, attrs,
  duration, and use budget
- Telegram is covered by a fake Bot API server or fake notifier in CI
- audit output contains no secrets

Live provider tests should be explicit manual or staging checks. CI must not
send real Telegram messages or mutate real external repositories.
