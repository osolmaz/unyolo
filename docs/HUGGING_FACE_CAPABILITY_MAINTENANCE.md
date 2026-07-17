# Hugging Face Capability Maintenance

The weekly `Hugging Face capability drift` workflow compares the reviewed Hub
OpenAPI snapshot with the live official document and maintains one issue when
the structural surface changes.

The monitor reports:

- added and removed HTTP operations;
- changed operation identifiers or schemas;
- authentication changes; and
- deprecation changes.

Descriptions, summaries, tags, and external documentation do not create
capability drift. The workflow never updates snapshots, generated artifacts,
policies, releases, or branches.

Run the same comparison locally:

```sh
go run ./brokers/huggingface/cmd/check-hf-drift
```

Treat a drift issue as a review prompt. Inspect the official changes, update
the dated snapshot and [operation inventory](2026-07-13-hugging-face-operation-inventory.md)
together, regenerate affected capability artifacts, and run the full HF Broker
conformance suite. New operations must receive an explicit implementation
disposition and policy effect before they become agent-facing.
