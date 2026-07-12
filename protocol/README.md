# BrokerKit Protocols

`openapi/operator-v1.yaml` is the canonical HTTP contract. The closed JSON
Schemas under `schema/` define individual resources and commands. Go and
TypeScript bindings must match these files, and CI validates examples and
fixtures against the same version.

Operator V1 is `brokerkit.io/operator/v1`. Provider execution plans and
credentials are deliberately absent from this protocol.

`openapi/agent-v1.yaml` and the closed schemas under `agent-schema/` define
Agent Operations V1, `brokerkit.io/agent/v1`. It lets authenticated agents
submit and resume typed provider operations without receiving the provider
credential. Providers own target, argument, execution, and result validation;
the shared contract owns only identity, idempotency, lifecycle, presentation,
and safe errors.
