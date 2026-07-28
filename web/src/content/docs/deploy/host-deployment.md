---
title: Host deployment
description: Provisioning a complete Linux agent host from one locked, non-secret deployment pack.
---

unYOLO can install or reconcile a complete Linux agent host from one locked, non-secret
deployment pack. The same pack drives the guided setup wizard and the unattended commands, so what
you review interactively is what an automated apply executes.

Darwin binaries remain available for existing-account and client workflows. Guided host
provisioning on macOS fails closed until native launchd and account provisioning are implemented
and tested.

## Guided setup

Run the bootstrap as the trusted operator, not as root, and pin both the source commit and the
release:

```sh
curl -fsSL \
  "https://raw.githubusercontent.com/osolmaz/unyolo/<reviewed-commit>/install/bootstrap.sh" \
  | sh -s -- --release unyolo/v<reviewed-version> setup
```

The bootstrap verifies the archive checksum, the exact tagged release workflow, and the GitHub
build attestation. It installs only the user CLI below `~/.local/bin`. The root phase separately
verifies and pins the attested unYOLO runtime public key before any deployment adapter can run,
and production validation and planning reject a missing or different key. The CLI refuses
interactive root execution.

The guide explains the operator and agent boundary, then opens a locked deployment kit. Recommended
and Custom setup materialize the verified profile graph and signed runtime artifacts below
`~/.config/unyolo/deployments/<deployment-name>/`. Existing deployment mode reviews the selected
pack in place. Setup validates every signed component adapter and shows the complete plan before
starting the matching root-owned worker.

Credential values move through one-use anonymous pipes. They are never written to the setup session
or into the pack.

Use `--accessible` for the screen-reader prompt path and `--no-open` on a remote terminal.
Incomplete local sessions can be inspected and resumed:

```sh
unyolo setup status
unyolo setup --resume <session-id>
```

## The deployment pack

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
    { "name": "gh-broker-agent", "members": ["unyolo-agent"] },
    { "name": "gh-broker-operator", "members": ["operator"] }
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
      "client_id": "unyolo-agent"
    }
  ],
  "clients": [
    {
      "agent_id": "agent",
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

Lock the pack after editing any referenced file:

```sh
unyolo system profile lock --profile "$PWD/deployment"
unyolo system profile lock --check --profile "$PWD/deployment"
```

Protected validation, planning, and apply use the same engine as guided setup. Invoke the
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

1. Set the credential declaration's `action` to `rotate` and lock the pack.
2. Review the resulting credential and client-file actions in the plan, then apply with the
   matching `--secret-file`.
3. Return the declaration to `retain` and lock the pack again.

Leaving it on `rotate` would mean every subsequent apply rotates the credential again, so the
return step is part of the procedure rather than tidying up afterwards.

See [credential lifecycle](/docs/guides/rotate-credentials) for what happens during the cutover and
what gets retired.

## Client configuration

Client commands load `~/.config/<broker>/client.json` directly. Production does not rely on shell
startup files or exported broker credentials, which is why a deployment can provision an agent
account without ever writing a secret into a profile script.
