---
title: Host deployment
description: The internal configuration and administrator commands used to install credential services.
---

Host deployment installs credential services, local endpoints, and their supporting accounts on one
machine. It is the server-side part of unYOLO setup. Agent-connection-only and command-only setup do
not need a host deployment.

The current managed host engine supports Linux. macOS support requires native launchd and local-
account management plus real installation and rollback tests, including removal. The presence of a macOS
binary does not mean managed macOS setup is available.

## Guided setup relationship

The target installer first asks whether the user wants credential services, an agent connection, or
both. When local credential services are selected, it generates the locked configuration described
below. Account choices such as an existing `bob` account or a newly created restricted account must
flow into that configuration.

Version 0.6.3 still uses a fixed Linux host flow with client name `agent` and account
`unyolo-agent`. See the
[guided installation contract](https://github.com/osolmaz/unyolo/blob/main/docs/GUIDED_INSTALLATION.md)
for the replacement flow and its platform requirements.

The unprivileged installer shows a plain summary before any administrator work. After confirmation,
a separately checked root process inspects the host, lists the exact changes, and asks for a second
confirmation. Changed host state invalidates the reviewed plan before any write.

Credentials move through one-use anonymous pipes. They are never written to the saved setup answers
or host configuration.

Incomplete local sessions can be inspected and resumed:

```sh
unyolo status
unyolo session list
unyolo setup --resume <session-id>
```

## Deployment configuration

`deployment.json` binds the runtime, the Unix identities, the components, and any optional
integrations. Every other file is referenced by a relative path and an exact SHA-256 digest.
Unknown fields, symlinks, path escapes, unlocked references, and group-writable inputs are all
rejected.

A component profile uses its provider-specific V1 API plus the shared bounded resource shape. This
example shows the important fields with no credentials in it:

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

<div class="callout callout--note">
<span class="callout__title">Modes are decimal</span>
<p>JSON has no octal literal, so file modes are written as decimal integers. <code>488</code> is
<code>0750</code> and <code>416</code> is <code>0640</code>.</p>
</div>

The signed runtime component names its fixed adapter arguments and its ownership envelope. The host
copies the verified adapter into a private root-owned staging directory before executing it, and an
adapter cannot claim a path, account, group, or service outside that signed envelope.

## Declarative commands

Lock the configuration after editing any referenced file:

```sh
unyolo system profile lock --profile "$PWD/deployment"
unyolo system profile lock --check --profile "$PWD/deployment"
```

Protected validation and planning use the same engine as guided setup, as does apply. Invoke the
root-owned worker installed by the verified bootstrap. Never run a user-local binary with `sudo`:

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

Apply replans under the host lock. Changed files, account state, group state, credentials, clients,
or services make the reviewed digest stale before any mutation happens, so a plan you approved
cannot be applied to a host that moved underneath it.

An unchanged deployment performs no writes and no restarts. It still runs runtime checks and
authenticated discovery from the real agent identity, which makes `apply` safe to run on a schedule
as a drift check.

## Rotating a credential

Credentials are retained by default. Rotation is a deliberate three-step edit:

1. Set the credential declaration's `action` to `rotate` and lock the configuration.
2. Review the resulting credential and client-file actions in the plan, then apply with the
   matching `--secret-file`.
3. Return the declaration to `retain` and lock the configuration again.

Leaving it on `rotate` would make every subsequent apply rotate the credential again. Returning it
to `retain` prevents that repeated rotation.

See [credential lifecycle](/docs/guides/rotate-credentials) for what happens during the cutover and
what gets retired.

## Client configuration

Client commands load `~/.config/<broker>/client.json` directly. Production does not rely on shell
startup files or exported broker credentials, which is why a deployment can provision an agent
account without ever writing a secret into a profile script.
