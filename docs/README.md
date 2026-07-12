# BrokerKit Documentation

BrokerKit's documentation index separates maintained contracts from
implementation records and retired repository snapshots.

## Start Here

- [Architecture](ARCHITECTURE.md)
- [Unified broker contract](UNIFIED_BROKER_CONTRACT.md)
- [Ownership boundaries](OWNERSHIP.md)
- [Security threat model](security/THREAT_MODEL.md)
- [Policy core](POLICY_CORE.md)
- [Operator inbox](OPERATOR_INBOX.md)
- [Operations runtime](OPERATIONS_RUNTIME.md)
- [Cutover status](CUTOVER_STATUS.md)

## Components

- [Hugging Face broker](../brokers/huggingface/README.md)
- [GitHub broker](../brokers/github/README.md)
- [sudo broker](../brokers/sudo/README.md)
- [OpenClaw plugin](../plugins/openclaw/README.md)
- [Operator V1 protocol](../protocol/README.md)

## Deployment

- [Systemd install runtime](SYSTEMD_INSTALL_RUNTIME.md)
- [Fresh-state cutover](cutover/FRESH_STATE.md)
- [Import ledger](cutover/import-ledger.md)

## Implementation Records

Date-prefixed plans, component adoption plans, the extraction plan, and the
implementation handoff record why the current design exists. Their status
headers record completion, but maintained contracts above take precedence if a
historical plan differs from current code.

## Archive

The [standalone repository archive](archive/standalone-repositories/README.md)
preserves the final Markdown snapshots from the retired private repositories.
Archived files are historical and non-normative.
