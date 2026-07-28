---
title: systemd and launchd
description: The unified setup command, the hardened unit baseline, file layout, and the two typed policies that vary.
---

Every broker uses one privileged setup command with the same shape, and BrokerKit renders the
service definition from a shared hardened baseline. This page covers the flags, the file layout the
setup produces, and the two policies a broker may vary.

## The setup command

```sh
sudo <broker> setup systemd [broker-specific flags]
```

macOS uses `setup launchd` with the same credential flags. Flags common to all three brokers:

```text
--user <name>                default: <broker>
--group <name>               default: <broker>
--config-dir <path>          default: /etc/<broker>
--state-dir <path>           default: /var/lib/<broker>
--systemd-dir <path>         default: /etc/systemd/system
--binary <path>              default: resolved current binary
--client <name>              required client identity
--operator <name>            required operator identity when the inbox is enabled
--shared-secret-file <path>  optional; read client secret from a file
--shared-secret-stdin        optional; read client secret from stdin
--endpoint <uri>             deployment-owned agent endpoint
--operator-endpoint <uri>    distinct deployment-owned operator endpoint
--dry-run
--no-start
```

Setup requires root unless a test-only flag is used. It creates the service user and group when
missing, creates root-owned config directories, creates service-owned private secret files and
state directories, generates a client secret when none is supplied, writes an env file, writes the
policy file, writes the unit, and enables and starts the service unless `--no-start` is set.
Finally it prints the broker endpoint and the client setup instructions.

<div class="callout callout--danger">
<span class="callout__title">No raw secrets on the command line</span>
<p><code>setup systemd</code> never accepts a raw secret value as a command-line argument. Those
leak through shell history and process listings. Use <code>--shared-secret-file</code> or
<code>--shared-secret-stdin</code>.</p>
</div>

Broker-specific secret files stay broker-local: a Hugging Face token file for `hf-broker`; a GitHub
App private key, app ID, webhook secret, or dev PAT file for `gh-broker`; a command catalog, policy,
host identity, and privileged helper configuration for `sudo-broker`.

## File layout

```text
/etc/<broker>/env
/etc/<broker>/secrets
/etc/<broker>/<policy-file>
/var/lib/<broker>/
/etc/systemd/system/<broker>.service
```

`/etc/<broker>` is root-owned and group-readable only where needed. `/etc/<broker>/secrets` holds
named broker clients and their secrets. Upstream credentials live in separate files owned by the
service user or root as required, mode `0600`. `/var/lib/<broker>` is owned by the service user.
Agents receive only broker client config and never an upstream credential.

The policy file name is broker-local. `hf-broker` and `gh-broker` use `scope.json`; `sudo-broker`
uses `policy.json`.

The named client secret file format is shared:

```text
client-name = generated-secret
```

Secrets must be at least 32 bytes of entropy-equivalent material and are never printed by
diagnostics after setup.

## Environment variables

Common names follow each broker's prefix:

```text
<PREFIX>_AGENT_ENDPOINT
<PREFIX>_OPERATOR_ENDPOINT
<PREFIX>_DEVELOPMENT
<PREFIX>_NETWORK_EXPOSURE
<PREFIX>_SCOPE_FILE or <PREFIX>_POLICY_FILE
<PREFIX>_SECRETS_FILE
<PREFIX>_STATE_DIR
```

Broker-specific secret fields should be file paths:

```text
HF_BROKER_HF_TOKEN_FILE
GH_BROKER_GITHUB_APP_PRIVATE_KEY_FILE
GH_BROKER_GITHUB_TOKEN_FILE
SUDO_BROKER_CATALOG_FILE
```

Raw secret values in environment variables exist for development. Service setup prefers file paths,
and the two Git-speaking brokers report inline credential values as inconclusive in their doctor
output.

`internal/config/envfile` reads the literal `KEY=VALUE` files setup generates. It bounds input to
1 MiB, rejects duplicate or malformed assignments, does not interpret shell syntax, and provides an
overlay lookup where explicit process environment values take precedence. Broker doctor commands
use it to inspect installed configuration without inheriting the systemd process environment.

## The hardened baseline

`internal/host/service` renders a common systemd baseline:

```text
network-online ordering
explicit user and group
private environment file
absolute ExecStart
restart on failure
PrivateTmp=true
ProtectSystem=strict
explicit read-only config and writable state paths
```

Consumers may append only explicitly allowed additive hardening directives. Extensions cannot
override the shared identity, execution, restart, filesystem, or hardening directives through
equivalent systemd settings, and paths containing systemd specifier or tokenization syntax are
rejected rather than rendered ambiguously.

Trusted service paths are always rejected below `/home`, `/root`, and `/run/user`, even when a
broker's operations may access those trees. Service binaries, config, environment files, and state
must be installed outside user-controlled home directories. Existing trusted path components must
be root-owned, non-symlinked, and not writable by group or other users. The final state directory
may instead be owned by the dedicated service account, and the writable state path may never be
`/`.

## The two typed policies

Two things vary per broker, and both default to the restrictive setting.

**Home access** defaults to `deny`. `read-only` is available for read-only integrations, and
`allow` only when a provider's reviewed operations must reach user home directories. On systemd,
`allow` adds explicit writable exceptions for `/home`, `/root`, and `/run/user` while
`ProtectSystem=strict` continues to protect the rest of the filesystem. `sudo-broker` V1 keeps home
access denied and requires root-trusted executable and working directory chains.

**Privilege escalation** defaults to denied with `NoNewPrivileges=true`. A broker that deliberately
performs an identity transition, which in practice means `sudo-broker` and its root helper, must
explicitly select `PrivilegeEscalationAllow`, and BrokerKit then renders `NoNewPrivileges=false`.

`PathValidationPreview` exists only for dry-runs and non-root temporary-directory fixtures.
Installable units use the zero-value strict policy.

## Client setup

```sh
<broker> setup client \
  --client agent-a \
  --endpoint unix:///run/brokerkit/<provider>/agent/broker.sock \
  --git-endpoint tcp://127.0.0.1:38471 \
  --secret-file /etc/<broker>/secrets \
  --home-dir /home/agent-a
```

This writes `~/.config/<broker>/client.json` using the closed `brokerkit.io/client/v1` schema. It
does not edit Git configuration; `<broker> git install` owns that. Neither command writes an
upstream provider credential.

## Production services and bundles

Setup commands write config and units, which is the right granularity for a single broker on a
development host. For a production host running several brokers plus the Telegram ingress,
activate them together as one signed immutable bundle so a partial upgrade cannot leave two
processes speaking different contract versions.

Native service definitions then use exact component paths below a root-controlled `current`
pointer, and production setup rejects standalone mutable executables. See
[runtime bundles](/docs/deploy/runtime-bundles).
