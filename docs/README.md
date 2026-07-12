# BrokerKit Documentation

BrokerKit's documentation index separates maintained contracts from
dated implementation records.

## Start Here

- [Architecture](ARCHITECTURE.md)
- [Unified broker contract](UNIFIED_BROKER_CONTRACT.md)
- [Ownership boundaries](OWNERSHIP.md)
- [Security threat model](security/THREAT_MODEL.md)
- [Policy core](POLICY_CORE.md)
- [Operator inbox](OPERATOR_INBOX.md)
- [Operations runtime](OPERATIONS_RUNTIME.md)

## Components

- [Hugging Face broker](../brokers/huggingface/README.md)
- [GitHub broker](../brokers/github/README.md)
- [sudo broker](../brokers/sudo/README.md)
- [OpenClaw plugin](../plugins/openclaw/README.md)
- [Operator V1 protocol](../protocol/README.md)

## Deployment

- [Systemd install runtime](SYSTEMD_INSTALL_RUNTIME.md)
- [Fresh-state cutover](cutover/FRESH_STATE.md)

## Implementation Records

Date-prefixed plans, component adoption plans, the extraction plan, and the
implementation handoff record why the current design exists. Their status
headers record completion, but maintained contracts above take precedence if a
historical plan differs from current code. The retired standalone repositories
remain private read-only archives; provider-specific documentation worth
maintaining lives with its component in this monorepo.

- [Final cutover status](2026-07-12-cutover-status.md)
- [Implementation handoff](2026-07-11-implementation-handoff.md)
- [Monorepo consolidation plan](2026-07-11-monorepo-consolidation-plan.md)
- [Universal platform plan](2026-07-11-universal-broker-platform-plan.md)
- [OpenClaw plugin plan](2026-07-11-openclaw-plugin-implementation-plan.md)
- [Extraction plan](2026-07-08-extraction-plan.md)
- [Source import ledger](cutover/2026-07-11-import-ledger.md)
- [Component plans](components/)
