# BrokerKit Protocols

`openapi/operator-v1.yaml` and `openapi/agent-v1.yaml` are the sole canonical
HTTP contracts. Every payload lives under `components/schemas`. The closed
JSON Schemas under `schema/` and `agent-schema/`, generated Go clients and Echo
interfaces, and generated TypeScript types and validators are committed build
artifacts. Run `scripts/generate-protocol.sh` after editing either document;
CI runs `scripts/check-protocol.sh` and rejects stale or invalid output.

Operator V1 is `brokerkit.io/operator/v1`. Provider execution plans and
credentials are deliberately absent from this protocol.

Agent Operations V1 is `brokerkit.io/agent/v1`. It lets authenticated agents
submit and resume typed provider operations without receiving the provider
credential. Providers own target, argument, execution, and result validation;
the shared contract owns only identity, idempotency, lifecycle, presentation,
and safe errors.
