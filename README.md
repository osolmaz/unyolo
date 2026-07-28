![BrokerKit](assets/logo-wordmark.svg)

# BrokerKit

BrokerKit is a Go framework for building credential brokers. A broker holds a
real credential and hands an untrusted client a separate one that works only
for the operations you allowed.

The point is to let a coding agent work in your accounts without holding the
credential that would let it destroy something. It can push branches and open
pull requests without being able to force-push over `main` or delete a
repository.

Three brokers ship ready to run, covering GitHub, Hugging Face, and Unix
privilege.

## Example

Policy is a JSON file you edit by hand. This lets one agent work on one
repository, in its own branch namespace:

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

Nothing names `refs/heads/main` or `git.push.force`, so both are denied. Git
remotes stay ordinary GitHub URLs and hold no credential:

```console
$ git push origin agent-a/parser-fix
   4d1e07c..9f2c1ab  agent-a/parser-fix -> agent-a/parser-fix

$ git push --force origin main
 ! [remote rejected] main -> main
   (gh-broker: no rule allows git.push.force on refs/heads/main)
```

Change `allow` to `request` and the broker holds the push open, notifies an
operator, and resumes it once approved.

## Request path

Every broker handles a request the same way:

```text
authenticate client
classify into client + operation + target + attrs
policy decision: deny / active grant / allow / request / no_match
optional operator approval
provider executor
audit log
```

Requests the policy cannot classify are refused. `deny` beats an approved
grant, so adding a deny rule immediately neuters every grant it covers.

Only classification and execution know anything about the provider. The rest is
shared code.

## Components

| Directory | What it is |
| --- | --- |
| [brokers/github](brokers/github/README.md) | `gh-broker`: GitHub App credentials, Git, pull requests, REST and GraphQL |
| [brokers/huggingface](brokers/huggingface/README.md) | `hf-broker`: Hugging Face token, Git, LFS, Hub, inference |
| [brokers/sudo](brokers/sudo/README.md) | `sudo-broker`: one exact command as another Unix user |
| [plugins/openclaw](plugins/openclaw/README.md) | Approvals tab and client skills for OpenClaw |
| [protocol](protocol/README.md) | Agent V1 and Operator V1 wire contracts |

Each broker is its own process with its own listener, credentials, state
directory, and audit stream.

## Build

One Go module, built with the version in [go.mod](go.mod):

```sh
go build ./brokers/github/cmd/gh-broker
go build ./brokers/huggingface/cmd/hf-broker
go build ./brokers/sudo/cmd/sudo-broker ./brokers/sudo/cmd/sudo-broker-exec
go build ./cmd/brokerkit ./cmd/brokerkit-telegram
```

Each broker's `setup` command writes credentials, policy, and service files.
For a production host, `brokerkit system install` activates every service as
one signed bundle. See [docs/OPERATIONS_RUNTIME.md](docs/OPERATIONS_RUNTIME.md).

## Building your own broker

You write a classifier, a registry, an executor, and the approval wording.
Authentication, policy, grants, the operator inbox, audit, installers, and
doctor checks come from the framework. `scripts/check-architecture.sh` fails a
build where shared code imports a provider. Start at
[docs/OWNERSHIP.md](docs/OWNERSHIP.md).

## Security

Credentials are write-only inside a broker. No API, log line, or error path
returns one. Agent and operator credentials are separate, and every endpoint
except `GET /healthz` requires authentication.

Run a broker where its clients cannot read its process or its files, and use
`<broker> doctor` to check that they cannot. The full boundary is in
[docs/security/THREAT_MODEL.md](docs/security/THREAT_MODEL.md).

## Documentation

[docs/](docs/README.md) holds the maintained contracts. [web/](web/README.md)
builds the same material into a documentation site.

## License

[MIT](LICENSE)
