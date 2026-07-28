---
title: Why unYOLO
description: What unYOLO sets out to do, the constraints it accepts, and the things it deliberately refuses.
---

unYOLO exists to make one narrow thing routine: letting an untrusted process act through a
credential it never sees. Everything else follows from that, including several features it does
not have. This page is the honest version of the pitch, so you can rule the project out quickly if
it does not match your problem.

## Goals

**Delegate capabilities rather than credentials.** A caller names an operation and a target. It
never names a credential kind, a token scope, a GitHub installation, or a permission set. The
broker resolves what upstream authority the operation needs and spends it server-side.

**Make the authorization decision readable.** Policy is a JSON file a human wrote and can review in
a pull request. It is not derived from observed traffic, and there is no learning mode. Reading the
file tells you what an agent can do, and `deny` rules always win, including over an approved grant.

**Put a human in front of the dangerous operations.** Force pushes, ref deletions, repository
deletion, and admin merges are the operations people actually worry about. Marking one `request`
holds the caller's original request open, notifies an operator, and resumes the exact same
operation once approved. The agent does not have to know it was approved out of band.

**Keep the shared control plane provider-neutral.** Authentication, policy, grants, approvals,
audit, install, service rendering, and doctor checks are written once. A broker contributes its
classifier, its credentials, its executor, and its approval wording. This is why the sudo broker,
whose protected resource is a Unix identity rather than an API token, uses the same engine as the
two credential brokers.

**Fail closed on anything ambiguous.** Unknown operations, unrecognized target kinds, unsupported
attrs, unknown JSON fields, malformed policy, corrupted state, contract drift between processes,
and an unverifiable binary all stop the request or the service. There is no permissive fallback and
no transport downgrade.

**Make the boundary verifiable on the host.** Running a broker on the same machine as the agent is
the common case and the easiest one to get wrong. Every broker ships a `doctor` command that checks
whether the agent account can read the token file, inspect the broker's process environment, write
to its socket, or reach root through a group like `docker`. It reports `unsafe` when the host does
not match the threat model.

## Non-goals

unYOLO does not sandbox provider code, and it does not make a dangerous executor safe. If a
broker's own execution path has a bug, the control plane in front of it does not save you. Each
broker is responsible for parsing, validating, and executing its own operations correctly.

It is not a general-purpose API proxy. There is no route that forwards an arbitrary request to
GitHub or Hugging Face with the real credential attached. Operations are registered, typed, and
generated from pinned provider definitions, which is deliberately more work than proxying and is
the reason the audit log means something.

It does not validate arbitrary shell strings. `sudo-broker` V1 executes one exact command from a
root-owned catalog with typed argument slots. There is no shell session, TTY, stdin, or
caller-supplied environment. Parsing untrusted shell input safely is a problem the project declines
to take on.

It is not a secret manager. unYOLO stores the credentials its brokers need and rotates them
through an exact-replacement flow, but it does not distribute secrets to other systems, and it has
no dual-secret window. When a broker's client secret is replaced, clients holding the old one fail
immediately and must be given the new config as a separate deliberate step.

It does not protect a host that is already compromised. If the broker account, its state files, the
operator secret, the provider credential, or the privileged helper socket is in an attacker's
hands, none of the invariants hold. The
[threat model](/docs/security/threat-model) lists these non-protections explicitly.

## Constraints the design accepts

Some of the friction in unYOLO is intentional, and it is worth knowing about before you deploy
it.

Policy is written by hand, so adding a capability means editing a file and restarting or reloading
the broker. Provider setup installs a `request-all-agent-operations` preset that allows safe reads
and requires approval for writes, which gives you a working starting point, but tightening it is
your work.

Because every broker is a separate process with its own state and release artifact, a production
host runs several services. The `unyolo` host command exists to activate them as one signed
bundle so a partial upgrade cannot leave two processes speaking different contract versions.

State format changes are replacements rather than migrations. The old service stops, its state
directory is archived beside the original, and the new one starts with fresh current-format state.
There are no compatibility readers, and rollback restores the archive with the old executable.

Approval latency is real. An operation marked `request` blocks until a human answers or the request
expires. For Git, the broker releases the provider lock while waiting and then reacquires it and
reclassifies the exact transaction, so a pending approval does not block every other push to the
repository, but the caller still waits.
