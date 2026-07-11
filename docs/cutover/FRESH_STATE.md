# Fresh-State Cutover

The coordinated BrokerKit cutover does not read or migrate an older broker
configuration, grant file, plan store, route, or plugin database. Archive old
state read-only and start every component with a new empty state directory.

## Before Exposure

1. Deny, revoke, consume, or allow every old pending and active grant to
   expire.
2. Stop old broker processes and snapshot their config, state, and audit paths
   read-only for forensic retention.
3. Create new client and operator secret files. Do not reuse one value in both
   authority domains.
4. Validate policy, provider credentials, immutable-plan directories, source
   registration, and SecretRefs without printing resolved secrets.
5. Start each broker against an empty state directory and an operator-only
   listener or Unix socket.
6. Require `/readyz` to return `200` before routing traffic. A malformed or
   unsupported state file must return `503 temporarily_unavailable`.
7. Run request, approve, deny, revoke, expiry, restart, and lost-response probes
   against the exact release artifacts and checksums selected for cutover.
8. Verify the OpenClaw plugin can lose and rebuild its cache without changing
   broker authority.
9. Expose traffic only after an operator authorizes the switch.

## Rollback

Before exposure, stop the new deployment, repair it, create another empty
state directory, and rerun the complete gate. Never point old and new binaries
at the same state or add a temporary compatibility reader. After exposure,
revoke new authority and follow the incident procedure for the affected
provider; do not restore stale grants from the archived state.

The automated proof for the state boundary is
`TestLoadRejectsLegacyScalarGrantValues`; readiness corruption behavior is
covered by `TestOperatorV1ReadinessChecksDurableState`.
