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

Run the default command as the trusted operator, not as root:

```sh
curl -fsSL https://unyolo.io/install.sh | sh
```

The bootstrap resolves one exact release, verifies its checksum and GitHub build attestation, and
runs the CLI from private staging. The first screen lets the operator select GitHub, Hugging Face,
or both. Ctrl-C there removes staging and exits without an installation or setup session.

Recommended and Custom setup filter the verified deployment kit to the selected providers and
materialize its locked graph below `~/.config/unyolo/deployments/<deployment-name>/`. Pass an
existing pack with `unyolo setup --profile <absolute-path>` to review or repair its bound provider
set without replacing it.

Setup validates every signed component adapter and shows the deployment review. The next
confirmation atomically activates the same verified CLI release before the root worker starts. The
root phase independently verifies the release archive's GitHub attestation and stores its exact
runtime templates in root-owned host state. Production validation and planning reject a runtime
manifest, signature, or public key that differs from those templates, and the CLI refuses
interactive root execution.

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
