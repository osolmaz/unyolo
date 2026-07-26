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

`sudo-broker` loads its private client V1 document directly from
`~/.config/sudo-broker/client.json`. Do not source it or copy its credential
into the environment. Environment configuration is only for isolated
development.

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
a new ID. `sudo-broker run` stays attached until approval and command execution
finish. If the caller times out or is interrupted, immediately rerun the exact
request with the same operation ID to recover it.

Approval waiting is part of the same agent turn. Do not return control to the
user while the operation remains pending. Keep the blocking command alive, or
recover it with the same operation ID, until the user clicks or otherwise
records a decision and execution reaches a terminal state. Stop only for a
terminal result, an explicit user cancellation, or an unrecoverable broker
error.

## Approval behavior

A pending request means the operation is waiting for an authorized decision;
it does not mean the client credential is missing. Keep the request alive
without ending the agent turn. Do not approve your own request, modify policy,
or access operator credentials.

After approval, treat the broker's exit status and bounded output as the
command result. Confirm the intended host effect separately when the original
workflow requires end-to-end verification.
