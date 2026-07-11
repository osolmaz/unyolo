# BrokerKit Operator Protocol

`openapi/operator-v1.yaml` is the canonical HTTP contract. The closed JSON
Schemas under `schema/` define individual resources and commands. Go and
TypeScript bindings must match these files, and CI validates examples and
fixtures against the same version.

Operator V1 is `brokerkit.io/operator/v1`. Provider execution plans and
credentials are deliberately absent from this protocol.
