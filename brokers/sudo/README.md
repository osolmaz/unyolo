# sudo-broker

sudo-broker is a privileged-command broker for Unix hosts. It lets an
authenticated local agent request and run one exact, operator-approved
command as another Unix user. Commands come from a root-owned catalog; it
does not accept shell strings, arbitrary executables, interactive shells,
TTYs, stdin, or caller-controlled environment variables.

The runtime has two processes:

- `sudo-broker` is an unprivileged HTTP frontend using BrokerKit policy,
  grants, Operator V1, and optional Telegram approval.
- `sudo-broker-exec` is a root helper reachable only through a private Unix
  socket by the dedicated frontend account.

## Install

Fetch the bootstrap from a reviewed BrokerKit commit. It resolves the latest
Sudo Broker release to its exact commit, verifies release checksums, and
installs to `$HOME/.local/bin`:

```sh
BROKERKIT_REV=<verified-40-character-commit-sha>
curl -fsSL "https://raw.githubusercontent.com/osolmaz/brokerkit/$BROKERKIT_REV/brokers/sudo/install.sh" | sh
```

Pin a release from [BrokerKit releases](https://github.com/osolmaz/brokerkit/releases)
with `VERSION=<version>`. The frontend is installed in the selected binary
directory. The helper is installed in the adjacent `libexec` directory and is
not added to ordinary user command paths.

## Configure on Linux

Write the command catalog and policy, starting from
[catalog.example.json](catalog.example.json) and
[policy.example.json](policy.example.json). The catalog fixes each command's
exact executable, arguments, target users, timeout, and output limit; the
rules for authoring it are in [docs/catalog.md](docs/catalog.md). Then run:

```sh
sudo sudo-broker setup systemd \
  --catalog-file ./catalog.json \
  --policy-file ./policy.json \
  --client agent-a \
  --operator operator-a \
  --agent-user agent-a \
  --operator-user operator-a
```

Setup generates independent client and operator secrets, installs a root
helper unit and an unprivileged frontend unit, and starts them in dependency
order. Use `--no-start` to write the configuration without enabling or
starting it, or `--dry-run` to validate and print the unit shape without
changing the host.

Write a client config for an agent account:

```sh
sudo sudo-broker setup client \
  --client agent-a \
  --endpoint unix:///run/brokerkit/sudo/agent/broker.sock \
  --secret-file /etc/sudo-broker/secrets \
  --home-dir /home/agent-a
```

This writes `/home/agent-a/.config/sudo-broker/client.env` with only
`SUDO_BROKER_ENDPOINT` and `SUDO_BROKER_SHARED_SECRET`. The `run` client
reads the endpoint as `SUDO_BROKER_AGENT_ENDPOINT`, so the agent sources its
own generated file and maps the name (this is the current
generated-file/CLI name mapping):

```sh
. "$HOME/.config/sudo-broker/client.env"
export SUDO_BROKER_AGENT_ENDPOINT="$SUDO_BROKER_ENDPOINT"
```

Verify host isolation and helper readiness:

```sh
sudo sudo-broker doctor host --agent agent-a
```

## Use

The client reads `SUDO_BROKER_AGENT_ENDPOINT` and
`SUDO_BROKER_SHARED_SECRET` from the environment:

```sh
sudo-broker run nginx-reload \
  --as root \
  --reason "Apply reviewed nginx configuration" \
  --operation-id nginx-reload-config-refresh
```

`run` submits one Agent V1 operation, waits for approval, and executes the
exact cataloged command through the privileged helper, then prints the
command's output and exits with its exit code. For typed catalog slots,
repeat `--arg-json NAME=JSON`. Reuse a stable `--operation-id` when retrying;
never retry an ambiguous execution under a new id.

See [the threat model](../../docs/security/THREAT_MODEL.md) for the security
boundary and platform-specific guarantees.

## License

[MIT](LICENSE)
