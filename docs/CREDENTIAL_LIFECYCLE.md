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

If file installation, service activation, or readiness fails, setup restores
the previous files and reactivates the previous service definition when one
existed. The replacement remains active only after the readiness check passes.
No setup command prints credential values.

Client configuration is replaced atomically with `setup client`. Because there
is no dual-secret window, clients using the previous broker secret fail as soon
as the broker cutover succeeds and must receive the newly generated config as a
separate, deliberate step.

Replacing a local provider credential does not itself revoke the credential at
Hugging Face, GitHub, Telegram, or another upstream. Revoke the old upstream
credential through that provider after BrokerKit readiness succeeds. If
upstream revocation fails, keep the new BrokerKit configuration active, record
the provider-side cleanup failure, and retry revocation; do not restore the old
local credential merely to make it usable again.
