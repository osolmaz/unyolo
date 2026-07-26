# Host deployment

BrokerKit can install or reconcile a complete agent host from one locked,
nonsecret deployment pack. The same pack drives guided setup and unattended
commands.

## Start guided setup

Run the bootstrap as the trusted operator, not as root. Pin both the source
commit and release:

```sh
curl -fsSL \
  "https://raw.githubusercontent.com/osolmaz/brokerkit/<reviewed-commit>/install/bootstrap.sh" \
  | sh -s -- --release brokerkit/v<reviewed-version> setup
```

The bootstrap verifies the archive checksum, exact tagged release workflow,
and GitHub build attestation. It installs only the user CLI below
`~/.local/bin`. The root phase separately verifies and pins the attested
BrokerKit runtime public key before any deployment adapter can run. Production
validation and planning reject a missing or different key. The CLI refuses
interactive root execution.

The guide explains the operator and agent boundary and opens a locked deployment
kit. Recommended and Custom setup materialize only its verified profile graph
and signed runtime artifacts below
`~/.config/brokerkit/deployments/<deployment-name>/`; Existing deployment mode
reviews the selected pack in place. Setup validates every signed component
adapter and shows the complete plan. Only then does it start the matching
root-owned worker. Credential values move
through one-use anonymous pipes and are not written to the setup session or
pack.

Use `--accessible` for the screen-reader prompt path and `--no-open` on a remote
terminal. Incomplete local sessions can be inspected with:

```sh
brokerkit setup status
brokerkit setup --resume <session-id>
```

## Deployment pack

`deployment.json` binds the runtime, Unix identities, components, and optional
integrations. Every other file is referenced by a relative path and exact
SHA-256 digest. Unknown fields, symlinks, path escapes, unlocked references,
and group-writable inputs are rejected.

A component profile uses its provider-specific V1 API and the shared bounded
resource shape. This example shows the important fields without credentials:

```json
{
  "api_version": "brokerkit.io/github-deployment/v1",
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
    { "name": "gh-broker-agent", "members": ["brokerkit-agent"] },
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
      "client_id": "brokerkit-agent"
    }
  ],
  "clients": [
    {
      "agent_id": "agent",
      "broker_name": "gh-broker",
      "env_prefix": "GH_BROKER",
      "secret_slot": "github-client-secret",
      "endpoint": "unix:///run/brokerkit/github/agent/broker.sock",
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
brokerkit system profile lock --profile "$PWD/deployment"
brokerkit system profile lock --check --profile "$PWD/deployment"
brokerkit system validate --profile "$PWD/deployment"
```

Protected planning and apply use the exact same engine as guided setup:

```sh
sudo brokerkit system plan \
  --profile "$PWD/deployment" \
  --output /tmp/brokerkit-plan.json

sudo brokerkit system apply \
  --profile "$PWD/deployment" \
  --expect-plan sha256:<reviewed-plan-digest> \
  --secret-file github-client-secret=/run/brokerkit-secrets/github-client-secret

sudo brokerkit system verify --profile "$PWD/deployment"
sudo brokerkit system export --profile "$PWD/deployment" --json
```

Apply replans under the host lock. Changed files, account state, group state,
credentials, clients, or services make the reviewed digest stale before any
mutation. An unchanged deployment performs no writes or restarts and still runs
runtime checks plus authenticated discovery from the real agent identity.

Client commands load `~/.config/<broker>/client.json` directly. Production does
not rely on shell startup files or exported broker credentials.
