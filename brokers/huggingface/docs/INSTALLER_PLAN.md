# Installer Plan

The standalone installer plan has been superseded by the monorepo release and
installer contract in
[`docs/2026-07-11-monorepo-consolidation-plan.md`](../../../docs/2026-07-11-monorepo-consolidation-plan.md)
and [`docs/UNIFIED_BROKER_CONTRACT.md`](../../../docs/UNIFIED_BROKER_CONTRACT.md).

The supported entry point is `brokers/huggingface/install.sh`; it delegates to
the shared checksum-verifying installer and selects `hf-broker/*` releases from
`osolmaz/brokerkit`.
