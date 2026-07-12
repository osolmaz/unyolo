# Import Provenance

- Source: `https://github.com/osolmaz/gh-broker` (private and archived)
- Frozen source commit: `7b7f5f11c9c3caf6471b5bc2d772fbea2c1c7532`
- Historical source tag: `v0.1.0`
- No-squash subtree merge: `6f75d6c83d8d06f93a5928b70b2b4738d9dde7c4`
- Destination: `brokers/github`

The coordinated source import is recorded in the
[dated import ledger](../../docs/cutover/2026-07-11-import-ledger.md).

Verified during import:

```sh
git merge-base --is-ancestor 7b7f5f11c9c3caf6471b5bc2d772fbea2c1c7532 HEAD
git diff --exit-code 7b7f5f11c9c3caf6471b5bc2d772fbea2c1c7532^{tree} HEAD:brokers/github
go test -race ./...
```
