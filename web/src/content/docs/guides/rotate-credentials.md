---
title: Rotate credentials
description: Exact-replacement rotation, what setup does on failure, revocation paths per credential class, and doctor reporting.
---

unYOLO uses one exact-replacement model for installed credentials. It does not keep old and new
secrets active at the same time. This applies to broker client and operator secrets, provider
credentials, Telegram bot tokens, GitHub App keys and OAuth secrets, and any other protected file
broker setup manages.

## Rotation sequence

Run the broker's native `setup systemd` or `setup launchd` command again with the complete desired
configuration and the replacement credential inputs. Setup then:

1. validates every input before changing the installation;
2. snapshots the bounded set of existing managed files and the service definition;
3. writes protected files atomically, switching the environment or service definition last;
4. restarts the broker and waits for bounded readiness;
5. retires obsolete credential files only after readiness succeeds; and
6. clears in-process rollback copies before exiting.

If file installation, service activation, or readiness fails, setup restores the previous files and
reactivates the previous service definition when one existed. The replacement becomes active only
after readiness passes.

No setup command prints a credential value.

## No dual-secret window

Client configuration is replaced atomically with `setup client`. Because there is no overlap
period, clients still holding the previous broker secret fail as soon as the broker cutover
succeeds. They must receive the new config as a separate, deliberate step.

Plan the two changes together. The usual sequence is to rotate the broker, confirm readiness, then
run `setup client` for each agent account and restart whatever holds the old config.

<div class="callout callout--warn">
<span class="callout__title">Rotating the Telegram inbox key</span>
<p>The ingress inbox encryption key is created once and preserved on rerun. Losing or rotating it
while callbacks are pending makes those callbacks unreadable rather than falling back to plaintext
authority. Drain pending callbacks before touching it.</p>
</div>

## Audit events

After a successful cutover, setup emits one `credential.lifecycle` audit event per created,
rotated, or locally retired credential class. Each event contains the actor, the class, the
outcome, and truncated SHA-256 identifiers for the old and new protected material. It carries no
credential values, paths, provider targets, or raw errors.

If audit output fails after readiness succeeds, setup reports that partial operational failure
without restoring an old credential. A committed cutover stays committed.

## Revocation paths

Local cutover and upstream retirement are different steps, and unYOLO automates the second only
where the provider exposes a supported API and the broker holds the exact authority and identifier
needed.

| Credential class | Local cutover | Upstream retirement |
| --- | --- | --- |
| Broker client and operator secrets | Exact replacement after readiness | Not applicable |
| GitHub App user OAuth credentials | Encrypted-store replacement | Automatic GitHub revocation; rotation rolls back if revocation fails |
| GitHub installation credentials | In-memory invalidation or expiry | Automatic revocation for bootstrap and invalidation-race tokens; normal cached tokens expire |
| GitHub App private key, client secret, webhook secret | Exact protected-file replacement | Manual in GitHub App settings after readiness |
| GitHub development token | Exact protected-file replacement | Manual in GitHub token settings after readiness |
| Hugging Face user token | Exact protected-file replacement | Manual in Hugging Face token settings after readiness |
| Telegram bot token | Exact protected-file replacement or retirement | Manual through BotFather after readiness |

unYOLO does not call undocumented endpoints and does not broaden provider permissions to
automate static-key cleanup. Provider revocation failures are recorded as failed lifecycle events.
A successful local cutover stays active; an old credential is never restored merely to make it
usable again.

## Repairing a Hugging Face token

`hf-broker` has an interactive repair flow for the case where the installed token was revoked or
was created with the wrong scopes:

```sh
hf-broker credential repair
```

It opens the fine-grained token form, prints the exact URL, and reads the token through a hidden
terminal prompt. The final panel reports only the verified subject and the capability count. The
token form starts empty, so the operator chooses the permissions and resources the broker may use.
Policy and operator approval can narrow that authority but can never expand it.

For automation, use bounded standard input and explicit JSON output. Non-interactive repair never
invokes `sudo` itself, so the caller enters an approved privilege boundary explicitly:

```sh
printf '%s\n' "$CANDIDATE_TOKEN" | hf-broker credential inspect --token-stdin --json
printf '%s\n' "$CANDIDATE_TOKEN" | sudo hf-broker credential repair --no-open --token-stdin --json
hf-broker credential status
```

Credential lifecycle events stay in the protected append-only `credential-lifecycle.jsonl` in the
installed config directory, `/etc/hf-broker` on Linux, rather than being mixed into terminal
output. Add `--verbose` to mirror those secret-safe JSON records to standard error while
troubleshooting.

## Doctor reporting

Doctor output includes a `credentials` list. Each entry contains only the stable credential class,
the source kind (`protected-file`, `inline`, or `encrypted-store`), a bounded installed age, an
expiry state (`valid`, `within-14-days`, `expired`, or `not-reported`), the exact RFC 3339 expiry
when the opaque store provides one, a rotation state (`not-due`, `due`, or `unknown`), and a
revocation mode (`automatic`, `local-only`, or `manual-upstream`).

Protected-file age comes from file metadata without opening the file. The default rotation age is
90 days.

`not-reported` is distinct from an unlimited or verified lifetime. A static provider credential
that exposes no expiry metadata reports `not-reported`, which means unYOLO does not know rather
than that the credential does not expire.

Supply every relevant installed path when running the Hugging Face isolation doctor:

```sh
hf-broker doctor isolation \
  --token-file /etc/hf-broker/hf-token \
  --client-secrets-file /etc/hf-broker/secrets \
  --operator-secrets-file /etc/hf-broker/operator-secrets \
  --telegram-token-file /etc/hf-broker/telegram-bot-token
```

GitHub doctor derives credential sources from the loaded broker configuration. Sudo doctor uses its
installed paths by default and accepts explicit path flags for custom layouts.

## Rotating inside a deployment pack

For a host managed by a deployment pack, rotation is a pack edit rather than a setup rerun. Set the
credential declaration's `action` to `rotate`, lock the pack, review the resulting credential and
client-file actions in the plan, apply with the matching `--secret-file`, then return the
declaration to `retain` and lock again. See [host deployment](/docs/deploy/host-deployment).
