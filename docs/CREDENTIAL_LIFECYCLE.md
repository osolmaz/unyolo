# Credential Lifecycle

BrokerKit uses one exact-replacement model for installed credentials. It does
not keep old and new secrets active together. This applies to broker client and
operator secrets, provider credentials, Telegram bot tokens, GitHub App keys
and OAuth secrets, and other protected files managed by broker setup.

Run the broker's native `setup systemd` or `setup launchd` command again with
the complete desired configuration and replacement credential inputs. Setup:

1. validates every input before changing the installation;
2. snapshots the bounded set of existing managed files and service definition;
3. writes protected files atomically, with the environment or service
   definition switched last;
4. restarts the broker and waits for bounded readiness;
5. retires obsolete credential files only after readiness succeeds; and
6. clears in-process rollback copies before setup exits.

After a successful cutover, setup emits one `credential.lifecycle` audit event
for each created, rotated, or locally retired credential class. Events contain
the actor, class, outcome, and truncated SHA-256 identifiers for the old and
new protected material. They never contain credential values, paths, provider
targets, or raw errors. If audit output fails after readiness, setup reports
that partial operational failure without restoring an old credential.

If file installation, service activation, or readiness fails, setup restores
the previous files and reactivates the previous service definition when one
existed. The replacement remains active only after the readiness check passes.
No setup command prints credential values.

Client configuration is replaced atomically with `setup client`. Because there
is no dual-secret window, clients using the previous broker secret fail as soon
as the broker cutover succeeds and must receive the newly generated config as a
separate, deliberate step.

## Revocation Paths

| Credential class | Local cutover | Upstream retirement |
| --- | --- | --- |
| Broker client and operator secrets | Exact replacement after readiness | Not applicable |
| GitHub App user OAuth credentials | Encrypted-store replacement | Automatic GitHub revocation; rotation rolls back if revocation fails |
| GitHub installation credentials | In-memory invalidation or expiry | Automatic revocation for bootstrap and invalidation-race tokens; normal cached tokens expire |
| GitHub App private key, client secret, and webhook secret | Exact protected-file replacement | Manual in GitHub App settings after readiness |
| GitHub development token | Exact protected-file replacement | Manual in GitHub token settings after readiness |
| Hugging Face user token | Exact protected-file replacement | Manual in Hugging Face token settings after readiness |
| Telegram bot token | Exact protected-file replacement or retirement | Manual through BotFather after readiness |

BrokerKit automates upstream revocation only where the provider exposes a
supported API and the broker has the exact authority and identifier needed for
that credential. It does not call undocumented endpoints or broaden provider
permissions to automate static-key cleanup. Provider revocation failures are
recorded as failed lifecycle events. A successful local cutover remains active;
an old credential is never restored merely to make it usable again.

## Doctor Output

Doctor reports include a `credentials` list. Each entry contains only:

- the stable credential class;
- the source kind (`protected-file`, `inline`, or `encrypted-store`);
- bounded installed age;
- expiry state (`valid`, `within-14-days`, `expired`, or `not-reported`);
- exact RFC 3339 expiry when the opaque store provides one;
- rotation state (`not-due`, `due`, or `unknown`); and
- revocation mode (`automatic`, `local-only`, or `manual-upstream`).

Protected-file age is derived from file metadata without opening the file.
Static provider credentials that do not expose expiry metadata report
`not-reported`; this is distinct from an unlimited or verified lifetime. The
default rotation age is 90 days.

Supply every relevant installed path when using the HF isolation doctor:

```sh
hf-broker doctor isolation \
  --token-file /etc/hf-broker/hf-token \
  --client-secrets-file /etc/hf-broker/secrets \
  --operator-secrets-file /etc/hf-broker/operator-secrets \
  --telegram-token-file /etc/hf-broker/telegram-bot-token
```

GitHub doctor derives credential sources from the loaded broker configuration.
Sudo doctor uses its installed paths by default and accepts explicit path flags
for custom layouts.
