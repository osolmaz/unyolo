# brokerkit

brokerkit is a Go library for building broker-style access-control services.
It provides shared primitives for projects where an untrusted client receives a
broker secret while the service keeps the real credential or privilege boundary
server-side.

The first intended users are `hf-broker`, `gh-broker`, and `sudo-broker`.
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

brokerkit owns only the reusable middle pieces. Each broker still owns its
dangerous domain boundary:

- `hf-broker` owns Hugging Face Git/LFS, mirrors, append-only checks, and Hub
  token use.
- `gh-broker` owns GitHub API/Git behavior, pull requests, installations, and
  GitHub ruleset compatibility.
- `sudo-broker` should own Unix user switching, command catalogs, TTY sessions,
  and sudo/systemd/launchd integration.

## Planned Packages

The first stable package candidates are:

- `auth`: shared-secret bearer/basic authentication for named clients
- `policy`: generic rule evaluation with broker-owned operation registries
- `grants`: short-lived pending/active/expired/revoked grants
- `audit`: secret-safe structured audit helpers
- `httpx`: proxy-safe header filtering and bounded body helpers
- `notify`: approval notification interfaces

Provider-specific execution code does not belong in brokerkit.

## Status

This repository currently contains the design documents for extracting shared
broker primitives. Implementation should begin only after the docs describe a
boundary that works for `hf-broker`, `gh-broker`, and `sudo-broker`.

## License

[MIT](LICENSE)
