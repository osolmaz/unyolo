# sudo-broker

sudo-broker lets an authenticated local agent request and run one exact,
operator-approved command as another Unix user. Commands come from a root-owned
catalog. It does not accept shell strings, arbitrary executables, interactive
shells, TTYs, stdin, or caller-controlled environment variables.

The runtime has two processes:

- `sudo-broker` is an unprivileged HTTP frontend using BrokerKit policy,
  grants, Operator V1, and Telegram approval.
- `sudo-broker-exec` is a root helper reachable only through a private Unix
  socket by the dedicated frontend account.

## Install

Install the latest checksummed release on Linux or macOS:

```sh
curl -fsSL https://raw.githubusercontent.com/osolmaz/brokerkit/main/brokers/sudo/install.sh | sh
```

The frontend is installed in the selected binary directory. The helper is
installed in the adjacent `libexec` directory and is not added to ordinary
user command paths.

## Configure On Linux

Start from [catalog.example.json](catalog.example.json) and
[policy.example.json](policy.example.json), then run:

```sh
sudo sudo-broker setup systemd \
  --catalog-file ./catalog.json \
  --policy-file ./policy.json
```

Setup generates independent client and operator secrets, installs a root helper
unit and an unprivileged frontend unit, and starts them in dependency order.
Use `--no-start` to write the configuration without enabling or starting it,
or `--dry-run` to validate and print the unit shape without changing the host.

Write a client config for an agent account:

```sh
sudo sudo-broker setup client \
  --client bob \
  --url http://127.0.0.1:8084 \
  --secret-file /etc/sudo-broker/secrets \
  --home-dir /home/bob
```

Verify host isolation and helper readiness:

```sh
sudo sudo-broker doctor host --agent bob
```

## Use

```sh
sudo-broker request nginx-reload \
  --as root \
  --reason "Apply reviewed nginx configuration"

sudo-broker status REQUEST_ID

sudo-broker run nginx-reload --as root
```

For typed catalog slots, repeat `--arg-json NAME=JSON` on both `request` and
`run`. Reuse a stable `--request-id` when retrying a request and a stable
`--execution-id` when reconciling one execution. Never retry an ambiguous
execution under a new id.

See [the threat model](../../docs/security/THREAT_MODEL.md) for the security
boundary and platform-specific guarantees.

[MIT](LICENSE)
