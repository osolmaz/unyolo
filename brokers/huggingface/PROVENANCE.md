# Import Provenance

- Source: `https://github.com/osolmaz/hf-broker` (private and archived)
- Frozen source commit: `d277504f78fbdb44601a139ec5b94882767a709c`
- Historical source tag: `v0.1.0`
- No-squash subtree merge: `1bba2bc16c01b84bd973b14f891daaaa228222f3`
- Destination: `brokers/huggingface`

The coordinated source import is recorded in the
[dated import ledger](../../docs/cutover/2026-07-11-import-ledger.md).

Verified during import:

```sh
git merge-base --is-ancestor d277504f78fbdb44601a139ec5b94882767a709c HEAD
git diff --exit-code d277504f78fbdb44601a139ec5b94882767a709c^{tree} HEAD:brokers/huggingface
go test -race ./...
```
