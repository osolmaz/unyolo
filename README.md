![unYOLO](assets/logo-wordmark.svg?v=5)

# unYOLO

unYOLO is an access-control framework for coding agents. It keeps provider
credentials in separate broker processes and checks each requested operation
against a policy you control.

An agent can push its own branch and open a pull request without ever receiving
a GitHub token. A force-push to `main` can be refused outright or kept waiting
for an operator. The same model applies to Hugging Face and privileged Unix
commands.

The repository includes ready-to-run GitHub and Hugging Face brokers.
`sudo-broker` handles approved Unix commands, and the OpenClaw plugin provides
an approvals UI.

## Policy example

Policy lives in ordinary JSON. This rule gives `agent-a` read access to one
repository and allows fast-forward pushes under its own branch namespace:

```json
{
  "rules": [
    {
      "id": "agent-a-branches",
      "effect": "allow",
      "clients": ["agent-a"],
      "operations": ["contents.read", "git.fetch", "git.push.fast_forward"],
      "targets": [{ "kind": "repo", "owner": "acme", "name": "api" }],
      "attrs": { "refs": ["refs/heads/agent-a/**"] }
    }
  ]
}
```

No rule grants access to `refs/heads/main` or `git.push.force`, so both requests
are denied. Git remotes stay as ordinary GitHub URLs and contain no credential:

```console
$ git push origin agent-a/parser-fix
   4d1e07c..9f2c1ab  agent-a/parser-fix -> agent-a/parser-fix

$ git push --force origin main
 ! [remote rejected] main -> main
   (gh-broker: no rule allows git.push.force on refs/heads/main)
```

Set a rule's effect to `request` when the operation needs a human decision. The
broker keeps the original command blocked and resumes it after approval.

## Request path

Every broker uses the same request path:

```text
authenticate client
classify into client + operation + target + attrs
policy decision: deny / active grant / allow / request / no_match
optional operator approval
provider executor
audit log
```

An unclassified request is refused. A `deny` rule also overrides any active
grant it covers. Provider-specific code is limited to classification and
execution.

## Included components

| Directory | Component |
| --- | --- |
| [brokers/github](brokers/github/README.md) | `gh-broker` holds GitHub App credentials and handles Git, pull requests, and the GitHub APIs |
| [brokers/huggingface](brokers/huggingface/README.md) | `hf-broker` handles Hugging Face Git, LFS, Hub operations, and inference |
| [brokers/sudo](brokers/sudo/README.md) | `sudo-broker` runs one approved command as another Unix user |
| [plugins/openclaw](plugins/openclaw/README.md) | OpenClaw approvals UI and broker skills |
| [protocol](protocol/README.md) | Agent V1 and Operator V1 wire contracts |

Each broker has its own process, listener, credential domain, state directory,
release artifact, and audit stream.

## Build

Use the Go version declared in [go.mod](go.mod):

```sh
go build ./brokers/github/cmd/gh-broker
go build ./brokers/huggingface/cmd/hf-broker
go build ./brokers/sudo/cmd/sudo-broker ./brokers/sudo/cmd/sudo-broker-exec
go build ./cmd/unyolo ./cmd/unyolo-telegram
```

A broker's `setup` command writes its configuration and protected credential
files, then installs the service. For a production host, `unyolo system
install` activates every service as one signed bundle. See
[docs/OPERATIONS_RUNTIME.md](docs/OPERATIONS_RUNTIME.md).

## Custom brokers

A custom broker supplies a request classifier and executor along with an
operation registry and approval text. The shared packages handle
authentication, policy, grants, the operator inbox, audit records, service
installation, and host checks.

`scripts/check-architecture.sh` rejects shared code that imports a provider.
Package ownership rules are documented in
[docs/OWNERSHIP.md](docs/OWNERSHIP.md).

## Security boundary

Provider credentials stay inside the broker and are never returned to clients.
They must never appear in logs or errors. Agent credentials and operator
credentials are separate, and every endpoint except `GET /healthz` requires
authentication.

Run each broker where its clients cannot inspect the broker process or read its
files. The `<broker> doctor` command checks that boundary. See
[docs/security/THREAT_MODEL.md](docs/security/THREAT_MODEL.md) for the complete
threat model.

## License

[MIT](LICENSE)
