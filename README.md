# BrokerKit

BrokerKit is a monorepo and Go toolkit for brokered access-control services.
It keeps protected credentials and Unix privilege boundaries in dedicated
services while untrusted clients receive only narrowly scoped broker access.

This repository contains the shared runtime plus three separate broker
executables:

- [HF Broker](brokers/huggingface/README.md) for Hugging Face credentials and
  Git, LFS, Hub, and inference operations.
- [GH Broker](brokers/github/README.md) for GitHub App credentials, repository
  reads, Git operations, and pull requests.
- [Sudo Broker](brokers/sudo/README.md) for approved exact-command execution as
  another Unix user.
- [OpenClaw BrokerKit](plugins/openclaw/README.md), an independently packaged
  approvals UI and channel integration.

All brokers use BrokerKit for authentication, policy, grants, operator APIs,
audit, notification state, Telegram transport, setup, and installation. Each
broker remains a separate process with separate credentials and provider logic.

BrokerKit stays focused: it is not a full application framework, and it does
not contain provider-specific Hugging Face, GitHub, or Unix privilege logic.

The `controlplane` package is the standard assembly path for grant storage,
client and operator authentication, the protected operator API, audit export,
and approval-channel decisions. `secretfile` owns the named credential format,
and `conformance` provides the black-box contract suite consumed by every
broker.

## Design

The common broker shape is:

```text
client request
        ↓
authenticate broker client
        ↓
classify request into client + operation + target + attrs
        ↓
policy decision: deny / active grant / allow / request / no_match
        ↓
optional approval grant
        ↓
provider-specific executor
        ↓
audit log
```

brokerkit owns the reusable control plane. Each broker still owns its dangerous
domain boundary:

- `hf-broker` owns Hugging Face Git/LFS, mirrors, append-only checks, and Hub
  token use.
- `gh-broker` owns GitHub API/Git behavior, pull requests, installations, and
  GitHub ruleset compatibility.
- `sudo-broker` owns exact cataloged Unix command execution, target identity
  switching, the privileged helper, and OS-specific host validation. V1 has no
  shell or TTY mode.

The canonical ownership boundary is in [docs/OWNERSHIP.md](docs/OWNERSHIP.md).
The security boundaries and fail-closed behavior are in
[docs/security/THREAT_MODEL.md](docs/security/THREAT_MODEL.md).
The shared install, setup, policy, grant, approval, audit, doctor, and release
contract is in
[docs/UNIFIED_BROKER_CONTRACT.md](docs/UNIFIED_BROKER_CONTRACT.md).

## Shared Packages

The main reusable packages are:

- `auth`: shared-secret bearer/basic authentication for named clients
- `policy`: generic rule evaluation with broker-owned operation registries
- `grants`: durable short-lived grants, use reservations, crash recovery, and
  notification delivery state
- `agentapi`, `agentclient`, `agentconformance`, `grantclient`, and `clienthttp`:
  shared Agent V1 server, clients and black-box contract tests, temporary-grant
  clients, and credential-safe HTTP defaults
- `usebudget`: finite/default/unlimited approval use-budget values
- `audit`: secret-safe structured audit helpers
- `httpx`: proxy-safe header filtering and bounded body helpers
- `clientconfig`: shared client env rendering for
  `~/.config/<broker>/client.env`
- `setup`: shared client command parsing, secret input/generation, and common
  systemd setup options
- `service`: hardened provider-neutral systemd unit rendering
- `doctor`: portable identity, root-equivalent group, service separation, and
  fail-closed secret-path, ACL, and mode checks with secret-safe reports
- `installer`: the canonical parameterized POSIX binary installer used by
  thin component-local broker wrappers
- `notify`: approval notification interfaces, callback answers, and a stateless
  Telegram adapter with send, explicit status edit, and long-poll callbacks
- `operatorinbox`, `operatorauth`, and `operatorapi`: bounded safe operator
  projections, separate operator authority, typed decisions, and durable SSE
- `operatorclient` and `operatorfake`: trusted-host integration and contract
  testing for operator applications
- `gitx`: generic Git smart-HTTP parsing helpers shared by HF and GH brokers
- `store`: atomic file storage and lock helpers used by grants and audit

Provider-specific execution code does not belong in brokerkit.

## Status

The brokers and OpenClaw plugin use the shared Operator V1 control plane.
Telegram delivery is deliberately stateless:
brokers persist notification references and use `brokerkit/grants` to drive
every status transition and retry after a restart. The shared operational
runtime is described in
[docs/OPERATIONS_RUNTIME.md](docs/OPERATIONS_RUNTIME.md).

The operator backend and trusted web-host integration contract is documented
in [docs/OPERATOR_INBOX.md](docs/OPERATOR_INBOX.md).
The maintained documentation map is in [docs/README.md](docs/README.md).

## License

[MIT](LICENSE)
