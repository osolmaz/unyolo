# brokerkit

brokerkit is a Go library for building broker-style access-control services.
It provides shared primitives for projects where an untrusted client receives a
broker secret while the service keeps the real credential or privilege boundary
server-side.

The first intended users are `hf-broker`, `gh-broker`, and `sudo-broker`.
brokerkit is the long-term shared base for those projects. Each broker should
cut over to brokerkit for shared auth, policy, grants, approval workflow,
audit, notification, Telegram approval transport, common storage/config
helpers, and generic Git parsing helpers instead of maintaining a parallel
compatibility runtime.

brokerkit should stay small: it is not a full broker framework, and it should
not contain provider-specific Hugging Face, GitHub, or Unix privilege logic.

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
- `sudo-broker` should own Unix user switching, command catalogs, TTY sessions,
  and sudo/systemd/launchd integration.

The canonical ownership boundary is in [docs/OWNERSHIP.md](docs/OWNERSHIP.md).
The shared install, setup, policy, grant, approval, audit, doctor, and release
contract is in
[docs/UNIFIED_BROKER_CONTRACT.md](docs/UNIFIED_BROKER_CONTRACT.md).

## Packages

Implemented package candidates are:

- `auth`: shared-secret bearer/basic authentication for named clients
- `policy`: generic rule evaluation with broker-owned operation registries
- `grants`: durable short-lived grants, use reservations, crash recovery, and
  notification delivery state
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
  thin broker repository wrappers
- `notify`: approval notification interfaces, callback answers, and a stateless
  Telegram adapter with send, explicit status edit, and long-poll callbacks
- `operatorinbox`, `operatorauth`, and `operatorapi`: bounded safe operator
  projections, separate operator authority, typed decisions, and durable SSE
- `operatorclient` and `operatorfake`: trusted-host integration and contract
  testing for web applications such as mlclaw
- `gitx`: generic Git smart-HTTP parsing helpers, if shared cleanly by
  `hf-broker` and `gh-broker`
- `store`: atomic file storage and lock helpers, if needed by grants/audit

Provider-specific execution code does not belong in brokerkit.

The packages above have initial Go implementations.

## Status

This repository now contains the shared Go packages plus the design documents
that define the cutover boundary. Telegram delivery is deliberately stateless:
brokers persist notification references and use `brokerkit/grants` to drive
every status transition and retry after a restart. The shared operational
runtime is described in
[docs/OPERATIONS_RUNTIME.md](docs/OPERATIONS_RUNTIME.md).

The live cross-repository implementation order and remaining work are tracked
in [docs/CUTOVER_STATUS.md](docs/CUTOVER_STATUS.md).
The operator backend and trusted web-host integration contract is documented
in [docs/OPERATOR_INBOX.md](docs/OPERATOR_INBOX.md).

## License

[MIT](LICENSE)
