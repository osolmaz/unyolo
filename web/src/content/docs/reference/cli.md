---
title: CLI commands
description: Find commands for brokers, host setup, and Telegram approvals.
---

Brokers use the same command names for shared tasks. The sections below group commands by task and
show where a broker behaves differently.

## Shared across every broker

```sh
<broker> --version
<broker> version
<broker> doctor
<broker> doctor isolation
<broker> setup systemd [flags]
<broker> setup launchd [flags]
<broker> setup client [flags]
<broker> state check   --state-dir /absolute/state [--full]
<broker> state backup  --state-dir /absolute/state --output /absolute/new-backup
<broker> state restore --state-dir /absolute/state --backup /absolute/backup
<broker> state export  --state-dir /absolute/state --output /absolute/new-export.json
```

Doctor exit codes are `0` for OK, `1` for unsafe, `2` for inconclusive, and `64` for invalid
arguments. State commands require the service to be stopped, because they acquire the state lease.

### Common setup flags

```text
--user <name>                default: <broker>
--group <name>               default: <broker>
--config-dir <path>          default: /etc/<broker>
--state-dir <path>           default: /var/lib/<broker>
--systemd-dir <path>         default: /etc/systemd/system
--binary <path>              default: resolved current binary
--client <name>              required client identity
--operator <name>            required operator identity when the inbox is enabled
--shared-secret-file <path>  read the client secret from a file
--shared-secret-stdin        read the client secret from stdin
--operator-secret-file <path> preserve or rotate the operator credential
--endpoint <uri>             deployment-owned agent endpoint
--operator-endpoint <uri>    distinct deployment-owned operator endpoint
--agent-user <name>
--operator-user <name>
--telegram-bot-token-file <path>
--telegram-chat-id <id>
--dry-run
--no-start
```

Raw secret values are never accepted as command-line arguments.

### Git-speaking brokers

```sh
<broker> git install
<broker> git doctor
<broker> git status --json
<broker> git uninstall
```

## hf-broker

```sh
hf-broker                                  # run in the foreground
hf-broker mcp                              # stdio MCP server

hf-broker credential repair
hf-broker credential inspect --token-stdin --json
hf-broker credential status

hf-broker doctor policy \
  --profile /etc/hf-broker/policy-profile.json \
  --scope /etc/hf-broker/scope.json \
  --manifest /etc/hf-broker/policy-manifest.json

hf-broker client repo create   --target-json '…' --arguments-json '…'
hf-broker client repo delete   --target-json '…' --arguments-json '…'
hf-broker client bucket object list  --target-json '…' --arguments-json '…'
hf-broker client bucket object write --target-json '…' --arguments-json '…' --source ./file

hf-broker client operation wait <operation-id>

hf-broker client grant request <operation> <owner>/<name> [flags]
hf-broker client grant get    <grant-id>
hf-broker client grant wait   <grant-id>
hf-broker client grant cancel <grant-id>
hf-broker client grant revoke <grant-id>
```

Grant request flags include `--type model|dataset|space`, repeatable `--ref` and `--path` for
repositories, repeatable `--key` for buckets, `--minutes`, `--max-uses` (a positive integer or
`unlimited`), `--reason`, and `--request-id`.

Setup-specific flags: `--hf-token-file`, `--xet-python`, `--repo owner/name`,
`--repo-type model|dataset|space`, repeatable `--deny-operation <exact-name>`, `--replace-policy`,
and `--reset-denied-operations`.

## gh-broker

```sh
gh-broker mcp

gh-broker operations list --family pull_request
gh-broker operations describe repo.visibility.update

gh-broker operation submit <operation> \
  --target-json '…' \
  --arguments-json '…' \
  [--reason '…'] [--request-id '…'] [--wait]
gh-broker operation get    <id>
gh-broker operation wait   <id>
gh-broker operation cancel <id>

gh-broker doctor github --repo owner/name --agent-user agent-a --service-user gh-broker

gh-broker setup github-user enroll \
  --state-dir /var/lib/gh-broker \
  --credential-file ./user-credential.json \
  --github-app-client-id-file ./app-client-id \
  --github-app-client-secret-file ./app-client-secret
gh-broker setup github-user rotate [same flags]
gh-broker setup github-user revoke --user-id 1234 --state-dir /var/lib/gh-broker
```

Setup-specific flags: `--github-app-id-file`, `--github-app-private-key-file`,
`--github-app-client-id-file`, `--github-app-client-secret-file`, `--github-user-id`,
`--github-webhook-secret-file`, `--scope-file`, `--git-endpoint`, `--dev-token-fallback`, and
`--github-token-file`.

`doctor github` accepts `--env-file <path>` for a nonstandard installation, or `--env-file ''` to
use only the current process environment.

Agent V1 broker commands keep operation data on stdout and lifecycle guidance on stderr. A
nonterminal result says that the requested action is not complete and prints the exact wait command
for the same operation ID. Only `succeeded` means the action completed. Completion waits return a
failure status for `failed`, `denied`, `expired`, or `canceled` operations.
`--wait-timeout` is an internal retry interval; it is not a total operation deadline.

## sudo-broker

```sh
sudo-broker serve --admission-config /absolute/path

sudo-broker run <command-id> \
  --as <target-user> \
  --reason '…' \
  --operation-id <stable-id> \
  [--arg-json NAME=JSON]

sudo sudo-broker doctor host --agent agent-a
```

Setup-specific flags: `--catalog-file` and `--policy-file`.

The privileged helper `sudo-broker-exec` is installed in the adjacent `libexec` directory and is
not invoked directly.

## unyolo host command

```sh
unyolo setup [--accessible] [--no-open]
unyolo setup --resume <session-id>
unyolo status [--json]
unyolo repair [--accessible] [--no-open]
unyolo reconfigure [--accessible] [--no-open]
unyolo remove [--remove-state] [--accessible]
unyolo session list [--json]
unyolo session discard --confirm <session-id>
unyolo session discard --confirm --all
unyolo version

unyolo completion bash
unyolo completion zsh
unyolo completion fish

unyolo system profile lock          --profile /path/to/deployment
unyolo system profile lock --check  --profile /path/to/deployment

unyolo system validate --profile /path/to/deployment
unyolo system plan     --profile /path/to/deployment --output /tmp/plan.json
unyolo system apply    --profile /path/to/deployment \
  --expect-plan sha256:<digest> \
  --secret-file <slot>=/absolute/path
unyolo system verify   --profile /path/to/deployment
unyolo system export   --profile /path/to/deployment --json

unyolo system install  --manifest manifest.json --signature manifest.sig --public-key release.pub
unyolo system upgrade  --manifest manifest.json --signature manifest.sig --public-key release.pub
unyolo system status [--json]
unyolo system doctor [--json]
unyolo system rollback
```

Run `unyolo --help` for the normal workflow, `unyolo help <command>` for one command, and
`unyolo system --help` for low-level host operations. Help exits successfully and invalid command
syntax exits with status 2. Misspelled command names suggest a close match without executing it.

Run `system` commands through the root-owned worker the verified bootstrap installed at
`/opt/unyolo/bootstrap/v<version>/unyolo`. Never run a user-local binary with `sudo`. The CLI
refuses interactive root execution.

## unyolo-telegram

```sh
sudo unyolo-telegram setup systemd \
  --telegram-bot-token-file ./telegram-bot-token \
  --telegram-chat-id 123456789 \
  --hf-operator-token-file ./hf-operator-secret \
  --gh-operator-token-file ./gh-operator-secret \
  --sudo-operator-token-file ./sudo-operator-secret
```

Omit a provider token flag when that provider is not installed. Endpoint and group flags exist for
non-default layouts.

## Installer environment

```text
VERSION                     release tag, for example v0.1.0
INSTALL_DIR                 absolute writable install directory
UNYOLO_VERIFIER_FILE     absolute path to a separately verified verifier
UNYOLO_VERIFY_ONLY       download and verify without installing
UNYOLO_VERIFY_RELEASE_SET  verify every platform archive, the manifest, and the SBOM
```
