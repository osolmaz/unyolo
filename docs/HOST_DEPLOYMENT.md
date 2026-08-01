# Host deployment

This document defines the internal configuration used to install credential services on a host. A
configuration records the required accounts, groups, files, sockets, services, client connections,
and checks. It contains no provider credentials.

Most users should not create this configuration by hand. The guided installer collects a plain setup
intent and generates the internal files only when the selected path installs credential services on
the local machine. Client-only and command-only setup do not generate a host deployment.

The current host engine supports complete managed deployment on Linux. macOS service and account
management must use native launchd and local-account adapters and pass the platform requirements in
[`GUIDED_INSTALLATION.md`](GUIDED_INSTALLATION.md) before the installer offers managed macOS setup.
Darwin binaries alone do not make that path supported.

## Relationship to guided setup

The guided installer separates four user goals:

- install credential services and connect a local agent
- install credential services only
- connect an agent to existing credential services
- install the unYOLO command only

Only the first two goals produce a host deployment configuration. The selected agent account and
client name flow into the generated groups, client files, policies, and checks. The generator must
not replace those choices with fixed `agent` or `unyolo-agent` names.

The default internal name is `default`. The installer asks for another name only when more than one
local deployment exists or a collision requires a choice. Generated files stay under the user
configuration root: `$XDG_CONFIG_HOME/unyolo/deployments/<name>/` on Linux by default and
`~/Library/Application Support/unyolo/deployments/<name>/` on macOS.

The unprivileged installer shows a plain summary before administrator work. A technical-details view
may show the configuration path and plan digest. After confirmation, a verified root worker checks
the same locked configuration, rejects changed host state, and applies one transaction. Credentials
move through one-use anonymous pipes and are never written to the setup session or configuration.

Incomplete sessions can be inspected or resumed:

```sh
unyolo status
unyolo session list
unyolo setup --resume <session-id>
```

## Deployment configuration

`deployment.json` binds the runtime and Unix identities to selected components
plus any optional integrations. Every other file is referenced by a relative path and exact
SHA-256 digest. Unknown fields, symlinks, path escapes, unlocked references,
and group-writable inputs are rejected.

A component profile uses its provider-specific V1 API and the shared bounded
resource shape. This example shows the important fields without credentials:

```json
{
  "api_version": "unyolo.io/github-deployment/v1",
  "accounts": [
    {
      "name": "gh-broker",
      "group": "gh-broker",
      "home": "/var/lib/gh-broker",
      "shell": "/usr/sbin/nologin"
    }
  ],
  "groups": [
    { "name": "gh-broker" },
    { "name": "gh-broker-agent", "members": ["bob"] },
    { "name": "gh-broker-operator", "members": ["onur"] }
  ],
  "directories": [
    {
      "id": "config",
      "destination": "/etc/gh-broker",
      "mode": 488,
      "owner": "root",
      "group": "gh-broker"
    }
  ],
  "files": [
    {
      "id": "policy",
      "source": {
        "path": "policies/github.json",
        "sha256": "sha256:<64 lowercase hex characters>"
      },
      "destination": "/etc/gh-broker/scope.json",
      "mode": 416,
      "owner": "root",
      "group": "gh-broker",
      "restart": true
    }
  ],
  "credentials": [
    {
      "slot": "github-client-secret",
      "destination": "/etc/gh-broker/secrets",
      "mode": 416,
      "owner": "root",
      "group": "gh-broker",
      "encoding": "client_secret_file",
      "client_id": "bob"
    }
  ],
  "clients": [
    {
      "agent_id": "bob",
      "broker_name": "gh-broker",
      "env_prefix": "GH_BROKER",
      "secret_slot": "github-client-secret",
      "endpoint": "unix:///run/unyolo/github/agent/broker.sock",
      "git_endpoint": "tcp://127.0.0.1:38471"
    }
  ],
  "services": ["gh-broker.service"]
}
```

JSON modes are decimal: `488` is `0750`, and `416` is `0640`.

The signed runtime component names its fixed adapter arguments and ownership
envelope. The host copies the verified adapter into a private root-owned staging
directory before executing it. An adapter cannot claim a path, account, group,
or service outside that signed envelope.

## Declarative commands

Lock after editing any referenced file:

```sh
unyolo system profile lock --profile "$PWD/deployment"
unyolo system profile lock --check --profile "$PWD/deployment"
```

Protected validation and planning use the same engine as guided setup, as does
apply. Invoke the root-owned worker installed by the verified bootstrap. Never
run a user-local binary with `sudo`:

```sh
worker=/opt/unyolo/bootstrap/v<reviewed-version>/unyolo

sudo "$worker" system validate --profile "$PWD/deployment"

sudo "$worker" system plan \
  --profile "$PWD/deployment" \
  --output /tmp/unyolo-plan.json

sudo "$worker" system apply \
  --profile "$PWD/deployment" \
  --expect-plan sha256:<reviewed-plan-digest> \
  --secret-file github-client-secret=/run/unyolo-secrets/github-client-secret

sudo "$worker" system verify --profile "$PWD/deployment"
sudo "$worker" system export --profile "$PWD/deployment" --json
```

Apply replans under the host lock. Changed files, account state, group state,
credentials, clients, or services make the reviewed digest stale before any
mutation. An unchanged deployment performs no writes or restarts and still runs
runtime checks plus authenticated discovery from the real agent identity.

Credentials are retained by default. Set a credential declaration's `action`
to `rotate`, review the resulting credential and client-file actions, apply it
with the matching `--secret-file`, then return the declaration to `retain` and
lock the configuration again.

Client commands load `~/.config/<broker>/client.json` directly. Production does
not rely on shell startup files or exported broker credentials.
