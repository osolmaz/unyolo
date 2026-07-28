# sudo-broker Operations

## Runtime Layout

The supported Linux installation has two units:

| Unit | Identity | State | Purpose |
| --- | --- | --- | --- |
| `sudo-broker.service` | `sudo-broker` | `/var/lib/sudo-broker/frontend` | Agent V1 operations, policy, approvals, plans, and audit. |
| `sudo-broker-exec.service` | `root` | `/var/lib/sudo-broker/helper` | Peer-authenticated exact-command execution and replay state. |

The helper creates `/run/sudo-broker/helper.sock` through a private systemd
runtime directory. The frontend requires and starts after the helper. Other
brokers and the OpenClaw plugin do not share either identity or state root.

Configuration is rooted at `/etc/sudo-broker`. Catalog and policy are
root-owned and group-readable by the frontend. Client, operator, and Telegram
credentials are readable only by the frontend account. The helper receives no
broker, operator, or Telegram credential.

## Installation

```sh
UNYOLO_REV=<verified-40-character-commit-sha>
curl -fsSL "https://raw.githubusercontent.com/osolmaz/unyolo/$UNYOLO_REV/brokers/sudo/install.sh" | sh

sudo sudo-broker setup systemd \
  --catalog-file ./catalog.json \
  --policy-file ./policy.json
```

Use `--dry-run` for validation with no writes and `--no-start` to install files
and units without activation. `setup systemd` is Linux-only. macOS uses the
same binaries and protocol but currently requires an operator-managed launch
configuration; no launchd installer is claimed.

## Verification

```sh
sudo sudo-broker doctor host --agent agent-a
systemctl status sudo-broker-exec.service sudo-broker.service
```

Doctor fails when the agent is root-equivalent, the frontend shares the agent
uid, trusted paths are mutable, the socket is unsafe, the helper is offline, or
Linux descriptor execution is unavailable. macOS reports its path
revalidation fallback as a warning.
The helper accepts UID 0 only for its bounded readiness ping so root-run host
diagnostics work; execution frames remain restricted to the frontend UID.

The live acceptance probe must use a disposable harmless catalog command. Test
submission, approval, one execution, replay with the same operation id, denial,
expiry, and an ambiguous helper disconnect. Never use a production mutation or
package-management command as the first probe.

## Recovery

- Repeating an operation with the same idempotency key and identical fields is
  idempotent across frontend restarts and returns its terminal result.
- A lost helper response after dispatch closes the grant use. Do not retry with
  a new execution id.
- Incomplete helper records are retained indefinitely. Completed records may be
  removed after 30 days, so operation ids should remain globally unique.
- Corrupt or unsupported grant, plan, helper protocol, or execution state fails
  closed.

Before replacing policy or catalog, validate with `setup systemd --dry-run`.
Activation validation and the helper both reject catalog, identity, and host
drift. Reapproval is required after a security-relevant catalog change.
