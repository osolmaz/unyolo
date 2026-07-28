# sudo-broker

sudo-broker is a privileged-command broker for Unix hosts. It lets an
authenticated local agent request and run one exact, operator-approved
command as another Unix user. Commands come from a root-owned catalog; it
does not accept shell strings, arbitrary executables, interactive shells,
TTYs, stdin, or caller-controlled environment variables.

The runtime has two processes:

- `sudo-broker` is an unprivileged HTTP frontend using unYOLO policy,
  grants, Operator V1, and optional Telegram approval.
- `sudo-broker-exec` is a root helper reachable only through a private Unix
  socket by the dedicated frontend account.

## Install

Fetch the bootstrap from a reviewed unYOLO commit. It resolves the latest
Sudo Broker release to its exact commit, verifies release checksums, and
installs to `$HOME/.local/bin`:

```sh
UNYOLO_REV=<verified-40-character-commit-sha>
curl -fsSL "https://raw.githubusercontent.com/osolmaz/unyolo/$UNYOLO_REV/brokers/sudo/install.sh" | sh
```

Pin a release from [unYOLO releases](https://github.com/osolmaz/unyolo/releases)
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
  --endpoint unix:///run/unyolo/sudo/agent/broker.sock \
  --secret-file /etc/sudo-broker/secrets \
  --home-dir /home/agent-a
```

This writes `/home/agent-a/.config/sudo-broker/client.json` using the closed
client V1 schema. The CLI loads this owner-only file directly, without shell
startup edits or inherited credentials.

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

When Telegram notifications are configured, sudo-broker supplies only the
cataloged command description, target user, bounded arguments, timeout, and
risk. unYOLO renders the same escaped rich approval layout and fixed
Approve/Deny controls used by the other brokers; raw executables, environment
values, and unrestricted command lines are never notification fields.

See [the threat model](../../docs/security/THREAT_MODEL.md) for the security
boundary and platform-specific guarantees.

## License

[MIT](LICENSE)
