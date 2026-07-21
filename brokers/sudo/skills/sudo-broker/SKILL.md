---
name: sudo-broker
description: Use BrokerKit for approved Unix privilege and identity transitions when sudo-broker is installed. Use for privileged, sudo, root, run-as-user, or cataloged host command requests instead of invoking sudo, su, doas, pkexec, or unrestricted shell escalation directly.
metadata:
  { "openclaw": { "emoji": "🛡️", "requires": { "bins": ["sudo-broker"] } } }
---

# Sudo Broker

Use `sudo-broker` for every privileged or cross-user host operation. The broker
can execute only an operator-defined command ID with bounded arguments,
working directory, target user, timeout, and output.

Do not invoke `sudo`, `su`, `doas`, `pkexec`, setuid helpers, or container-based
privilege escalation as a fallback.

## Authenticate to BrokerKit

The runtime normally provides `SUDO_BROKER_AGENT_ENDPOINT` and
`SUDO_BROKER_SHARED_SECRET`. If either is missing and the client file is
readable, load it before running broker commands:

```sh
. "$HOME/.config/sudo-broker/client.env"
```

The BrokerKit secret authenticates the enrolled client; it is not a Unix
password. Never print or persist it elsewhere.

## Run a cataloged command

Use the exact command ID and target user approved for the task:

```sh
sudo-broker run COMMAND-ID \
  --as TARGET-USER \
  --reason "Concrete reason for this operation" \
  --operation-id STABLE-OPERATION-ID
```

For typed catalog slots, repeat `--arg-json NAME=JSON`. Do not invent command
IDs, executable paths, environment variables, or free-form shell fragments.
If the required command is not cataloged, report that the operator must add a
narrow command and policy rule.

Use a stable operation ID for retries. Never retry an ambiguous execution with
a new ID.

## Approval behavior

A pending request means the operation is waiting for an authorized decision;
it does not mean the client credential is missing. Keep the request alive or
report its durable identifier as appropriate. Do not approve your own request,
modify policy, or access operator credentials.

After approval, treat the broker's exit status and bounded output as the
command result. Confirm the intended host effect separately when the original
workflow requires end-to-end verification.
