# Consolidation Import Ledger

Date frozen: 2026-07-11

This ledger records the immutable source tips used by the coordinated
BrokerKit monorepo cutover. Source repositories remain intact and are not
deleted.

| Component | Source | Frozen commit | Source tag | Open work | Ruleset |
| --- | --- | --- | --- | --- | --- |
| BrokerKit | `https://github.com/osolmaz/brokerkit` | `e2afa6362e8aac4d0528d5f6fb2054d2e5c58ccf` | `v0.1.0` | none | `github-sane-defaults: default branch` |
| HF broker | `https://github.com/osolmaz/hf-broker` | `d277504f78fbdb44601a139ec5b94882767a709c` | `v0.1.0` | none | `github-sane-defaults: default branch` |
| GH broker | `https://github.com/osolmaz/gh-broker` | `7b7f5f11c9c3caf6471b5bc2d772fbea2c1c7532` | `v0.1.0` | none | `github-sane-defaults: default branch` |
| sudo broker | `https://github.com/osolmaz/sudo-broker` | `75d1c452dbfe36bf121f85aeefa7593a69414081` | `v0.1.0` | none | `github-sane-defaults: default branch` |

All four `v0.1.0` releases and their assets were present at freeze time. Their
tag names collide, so imports fetch `main` with `--no-tags`. Future component
tags are qualified as defined in ADR 0001.

## Baseline Verification

Each frozen checkout passed:

```sh
go test -race ./...
```

External recovery bundles were created under
`~/scratch/brokerkit-consolidation-backups/` using `git bundle create --all`.

History scans used Gitleaks 8.28.0. HF and sudo reported no findings. The two
reviewed findings were non-secret fixtures:

- BrokerKit's documented Operator V1 idempotency-key example.
- GH broker's historical repeated-hex `testAdminToken` fixture.

The consolidated scanner configuration narrowly allowlists those fixtures and
does not suppress the corresponding rule globally.

## Import Verification

After each no-squash subtree import, record its merge commit and verify:

```sh
git merge-base --is-ancestor <frozen-source-sha> HEAD
git log --follow -- <representative-imported-file>
git diff --stat <frozen-source-sha> <import-merge>:<provider-prefix>
go test -race ./...
```

| Component | Destination | Import merge | Verification |
| --- | --- | --- | --- |
| HF broker | `brokers/huggingface` | `1bba2bc16c01b84bd973b14f891daaaa228222f3` | ancestor and tree identity verified |
| GH broker | `brokers/github` | `6f75d6c83d8d06f93a5928b70b2b4738d9dde7c4` | ancestor and tree identity verified |

The temporary source remotes are removed after ancestry and tree verification.
