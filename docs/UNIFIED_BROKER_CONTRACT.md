# Unified Broker Contract

This is the shared contract for `hf-broker`, `gh-broker`, and `sudo-broker`.
It defines one install, setup, config, policy, approval, audit, and release
shape. Each broker keeps only its dangerous platform adapter.

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
- semantic notification interfaces and shared canonical Telegram renderer and
  transport
- audit event schema and no-secret helpers
- local durable storage helpers
- doctor check building blocks
- release asset conventions

Each broker owns only its platform adapter:

- `hf-broker`: Hugging Face Git, LFS, Xet, Hub tokens, mirrors, and HF wording
- `gh-broker`: GitHub REST/Git, GitHub App tokens, PRs, webhooks, rulesets, and
  GitHub wording
- `sudo-broker`: Unix users, exact command catalogs, the privileged helper,
  systemd/host integration, and Unix wording

brokerkit must not grow provider-specific credentials, API calls, command
execution, or user-facing approval text.

## Operator Inbox

Every broker exposes the shared `operatorapi` contract on a protected operator
listener or Unix socket. The agent listener remains client-scoped and cannot
make operator decisions or read cross-client history.

Each broker provides only its `operatorinbox.Presenter`, operator transport,
credential loading, and broker name. Brokerkit owns bounded queries, safe
records, revision-checked decisions, durable events/SSE, operator auth
primitives, audit fields, the Go client, and conformance fixtures. Telegram is
an optional notification view over the same grant store, not a separate
approval state machine.

Trusted web applications call the operator API from their server backend.
They must not send operator credentials to browsers or accept browser-supplied
provider plans. A decision is always applied by the broker to its canonical
stored request.

## Binary Install

Every broker binary uses a component-local wrapper around BrokerKit's shared
installer:

```sh
BROKERKIT_REV=<verified-40-character-commit-sha>
curl -fsSL "https://raw.githubusercontent.com/osolmaz/brokerkit/$BROKERKIT_REV/brokers/huggingface/install.sh" | sh
curl -fsSL "https://raw.githubusercontent.com/osolmaz/brokerkit/$BROKERKIT_REV/brokers/github/install.sh" | sh
curl -fsSL "https://raw.githubusercontent.com/osolmaz/brokerkit/$BROKERKIT_REV/brokers/sudo/install.sh" | sh
```

Common environment variables:

```text
VERSION      optional release tag, for example v0.1.0
INSTALL_DIR  optional absolute writable install directory; defaults to $HOME/.local/bin
```

The installer should:

- detect `linux` and `darwin`
- detect `amd64` and `arm64`
- download the release tarball for the selected version
- download and verify `checksums.txt`
- verify both files' GitHub attestations against the BrokerKit release workflow
  and selected tag with a checksum-pinned verifier
- install only the binary
- default to `$HOME/.local/bin` and require an explicit writable
  `$INSTALL_DIR` for any other destination
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
--client <name>        required client identity
--operator <name>      required operator identity when the inbox is enabled
--shared-secret-file <path> optional; read client secret from a file
--shared-secret-stdin       optional; read client secret from stdin
--endpoint <uri>       complete deployment-owned agent endpoint
--operator-endpoint <uri> distinct deployment-owned operator endpoint
--dry-run
--no-start
```

`setup systemd` should:

- require root unless a test-only flag is used
- create the broker service user and group when missing
- create root-owned config directories
- create service-owned private secret files
- create service-owned state directories
- generate a client secret when no secret file or stdin input is supplied
- write an env file
- write the broker policy file
- write the systemd unit
- enable and start the service unless `--no-start` is set
- print the broker endpoint and client setup instructions

`setup systemd` must never accept raw secret values as command-line arguments.
Those leak through shell history and process listings.

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
/etc/<broker>/<policy-file>
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

The policy file name is broker-local. `hf-broker` and `gh-broker` currently use
`scope.json`; `sudo-broker` uses `policy.json`.

The named client secret file format is shared:

```text
client-name = generated-secret
```

Secrets must be at least 32 bytes of entropy-equivalent material and must never
be printed by diagnostics after initial setup.

## Environment

Common environment names should follow each broker prefix:

```text
<PREFIX>_AGENT_ENDPOINT
<PREFIX>_OPERATOR_ENDPOINT
<PREFIX>_DEVELOPMENT
<PREFIX>_NETWORK_EXPOSURE
<PREFIX>_SCOPE_FILE or <PREFIX>_POLICY_FILE
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
<broker> setup client \
  --client agent-a \
  --endpoint unix:///run/brokerkit/<provider>/agent/broker.sock \
  --git-endpoint "tcp://127.0.0.1:${BROKER_GIT_PORT}" \
  --secret-file /etc/<broker>/secrets \
  --home-dir /home/agent-a
```

That command should write a client-owned config file under:

```text
~/.config/<broker>/client.env
```

The file should contain only:

```text
export <PREFIX>_AGENT_ENDPOINT=<endpoint-uri>
export <PREFIX>_SHARED_SECRET=<client-secret>
export <PREFIX>_GIT_ENDPOINT=<explicit-loopback-tcp-uri>
```

For Git-speaking brokers, `<broker> git install` owns the user-level URL
rewrites and exact-origin credential-helper configuration. `setup client`
does not edit Git configuration. Neither command writes upstream provider
credentials.
The client can source this protected file directly; both values must be
exported to broker client processes.

## Policy

brokerkit owns the policy schema and decision engine. Brokers register their
operation, target, and attr vocabulary.

Common rule shape:

```json
{
  "rules": [
    {
      "id": "example",
      "effect": "request",
      "clients": ["agent-a"],
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
- operator approve, deny, and revoke flows
- requester-owned cancellation of pending requests
- status update flows
- atomic approve/deny plus callback-notification recovery
- Telegram callback parsing and verification
- token-bound Telegram decisions through the owning broker's canonical
  Operator V1 path
- transient route failures that leave the affected message retryable without
  blocking callbacks for healthy brokers

Brokers own bounded semantic titles, summaries, targets, risk, warnings, and
provider-specific facts shown to the operator. BrokerKit owns presentation
validation, Telegram layout and escaping, fixed controls, callback answers,
terminal wording, and durable presentation/render digests.

Protocol and window-grant brokers expose the shared request shape through:

```text
GET  /healthz
POST /api/grants
GET  /api/grants
GET  /api/grants/{id}
```

Provider surfaces may add requester-owned cancellation or revocation where the
underlying protocol uses a grant outside Agent V1. Agent V1 operations use the
shared operation cancellation route instead.

Operator decisions use the separate Operator V1 routes documented in
[OPERATOR_INBOX.md](OPERATOR_INBOX.md). Agent credentials cannot approve or
deny requests.

Brokers may add platform-specific streaming and read routes, such as Git
smart-HTTP. Discrete approved operations use the common Agent V1 lifecycle
rather than provider-specific execution routes.

## Agent MCP Lifecycle

Agent-facing MCP execution submission tools use an optional `request_id`. When
omitted, the broker generates a cryptographically random ID before durable
admission. Supplying the same request ID with the same immutable request
returns the existing operation; conflicting reuse returns a bounded
`request_id_conflict`. The internal Agent V1 API continues to call this value
`idempotency_key`, but that name is not exposed by MCP.

Submission returns the transcript-safe operation immediately, including its
`id`, `request_id`, state, revision, timestamps, and safe presentation. It
never waits for approval. Each provider exposes `<prefix>operation_get`,
`<prefix>operation_wait`, and `<prefix>operation_list`; waits are bounded to 25
seconds and list/recovery is scoped to the authenticated client.

The stable handle vocabulary is:

```text
request_id    exact admission/retry identity
operation_id  durable operation lifecycle identity
approval_id   internal approval linkage, not exposed by MCP
transfer_id   bounded stream correlation handle
credential_slot encrypted destination for generated credentials
```

Provider-native request and result schemas stay provider-owned. Providers
project public names that collide with supported transcript redactors, while
real secrets remain sealed or credential-slot-backed. The checked-in provider
compatibility manifests summarize catalog-wide conformance against the pinned
host profile.

Authorization mode does not select MCP dispatch. Every ordinary operation tool
submits one durable Agent V1 operation. A matching active window grant may
authorize that operation; otherwise policy may allow, request approval, or
deny it. Approval resumes the stored operation, and retrying its `request_id`
cannot create a second execution. Explicit grant lifecycle tools are reserved
for callers intentionally managing access used later by a native protocol
such as Git. They are not an automatic preflight for operation tools.

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

Every broker should test:

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
