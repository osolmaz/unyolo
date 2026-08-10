---
title: Why unYOLO
description: Design goals and limits.
---

unYOLO lets an untrusted process use a credential it cannot read. It is meant
for coding agents that need narrow, reviewable access to accounts you care
about.

Use unYOLO when an agent needs limited account access and must not receive the
provider credential. The limits below explain what unYOLO does not protect.

## Design goals

### Capability delegation

A caller names an operation and a target. The broker chooses the upstream
credential and performs the operation on the caller's behalf. Client requests
never select token scopes, GitHub installations, or permission sets.

### Reviewable policy

Authorization lives in a JSON file that can be read directly and reviewed in a
pull request. unYOLO does not infer permissions from observed traffic. A
`deny` rule always wins, including when an operator has already approved a
grant.

### Operator approval

A rule with the `request` effect keeps the original operation waiting for a
human decision. Approval resumes that same operation. The agent does not need
to poll a separate workflow or repeat the command.

### Provider boundary

The shared code owns authentication, policy evaluation, grants, approval
records, audit fields, and host setup. Each broker owns its provider
credential. It supplies the request classifier and executor together with the
approval wording. This keeps
GitHub, Hugging Face, and Unix privilege logic in separate processes.

### Closed failure behavior

Unknown operations and malformed policy stop the request or the service.
Corrupted state and contract drift do the same. There is no permissive default
or transport downgrade.

### Host checks

Every broker has a `doctor` command for checking the local security boundary.
It verifies that the agent account cannot read credential files, inspect the
broker environment, write to protected sockets, or gain equivalent access
through groups such as `docker`.

## Limits

### Provider code

unYOLO does not sandbox a broker's executor. A bug in provider-specific parsing
or execution can still perform the wrong operation. Each broker must validate
its own inputs and upstream behavior.

### Registered operations

Only registered operations are available. The GitHub and Hugging Face brokers
do not expose arbitrary forwarding routes with a provider credential attached.
This takes more work than a general proxy, but it gives policy and audit records
stable operation names.

### Command catalog

`sudo-broker` executes one exact command from a root-owned catalog with typed
argument slots. Its contract excludes shell sessions and TTYs as well as stdin
or caller-supplied environments.

### Credential storage

unYOLO stores the credentials its brokers need. It is not a general secret
distribution system. Replacing a broker-client secret invalidates the old
secret immediately, and clients must receive the new configuration through a
separate trusted channel.

### Compromised hosts

The security boundary ends when an attacker controls the broker account, its
state files, the operator credential, or the provider credential. The
[threat model](/docs/security/threat-model) lists the assumed protections and
failure cases.

## Operational tradeoffs

Policy changes require editing a file and reloading the broker. Provider setup
installs a `request-all-agent-operations` preset that allows safe reads and
requires approval for writes, leaving further restriction to the operator.

A production host runs one service per broker. The `unyolo` host command
activates them as one signed bundle so a partial upgrade cannot leave two
processes on different contract builds.

State format changes use replacement. The old service stops, its state
directory is archived, and the new service starts with fresh current-format
state. Rollback restores the archived directory with the previous executable.

Approval adds latency. A `request` operation blocks until a human decides or
the request expires. Git brokers release provider locks while waiting, then
reacquire the lock and reclassify the transaction before execution.
