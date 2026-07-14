# Hugging Face Policy Presets

hf-broker can render a provider-owned policy from a small operator profile. A
preset is installation convenience, not a second policy engine: the resulting
`scope.json` is an ordinary explicit rule file and is validated by the same
strict parser used at broker startup.

## Default preset

`request-all-agent-operations` is the default for a fresh service setup. It
materializes one exact rule for every operation in the embedded Hugging Face
catalog. It does not contain operation-family wildcards.

The catalog stores an explicit `default_policy_effect` for each operation:

- `allow`: safe reads, discovery, and inference run directly.
- `request`: writes, administration, and destructive actions require operator
  approval. Execution-scoped actions receive exact, one-use grants.
- `deny`: internal, non-agent, and credential-output operations cannot be
  requested by the agent.

These effects are data in the reviewed provider catalog. The renderer never
guesses from an operation name or risk label. Catalog validation also prevents
high-risk, critical, execution-scoped, explicit-only, or sealed operations from
defaulting to `allow`.

An operator can hard-deny additional exact operations:

```sh
sudo hf-broker setup systemd \
  --hf-token-file ./hf-token \
  --client agent \
  --deny-operation repo.delete
```

Unknown and duplicate deny overrides are rejected.

## Render without installing

Render the profile, concrete policy, and manifest together:

```sh
hf-broker policy render \
  --preset request-all-agent-operations \
  --client agent \
  --deny-operation repo.delete \
  --profile-out policy-profile.json \
  --output scope.json \
  --manifest-out policy-manifest.json
```

The command refuses to replace any output unless `--replace` is present. It
stages all three artifacts before committing them, creates without clobbering,
and rolls back a partial replacement; `scope.json` is the final commit point.
All three files use deterministic, newline-terminated JSON. `policy check`
validates any concrete policy with the broker's startup parser:

```sh
hf-broker policy check --file scope.json
```

## Managed artifacts and drift

Default systemd setup installs these root-owned, non-secret files:

```text
/etc/hf-broker/policy-profile.json
/etc/hf-broker/scope.json
/etc/hf-broker/policy-manifest.json
```

The manifest binds the profile, policy, and embedded operation catalog by
SHA-256 digest. It also records each operation's revision, effect, risk,
authorization mode, and grant lifecycle. Check the installed artifacts without
changing them:

```sh
hf-broker doctor policy \
  --profile /etc/hf-broker/policy-profile.json \
  --scope /etc/hf-broker/scope.json \
  --manifest /etc/hf-broker/policy-manifest.json
```

Status values are:

| Status | Meaning | Exit code |
|---|---|---:|
| `current` | Profile, policy, manifest, and current catalog match. | 0 |
| `stale` | The embedded operation catalog changed after rendering. | 1 |
| `modified` | A profile or policy no longer matches its manifest. | 1 |
| `invalid` | An artifact cannot be parsed or validated. | 2 |

Use `--json` for automation. Catalog drift reports added, removed, and changed
operation names when available. Doctor never edits policy files or contacts a
live broker. Exact deny overrides for retired operations remain valid
diagnostic input when they are present in the installed manifest, allowing
Doctor to report the removal instead of treating the profile as malformed.

## Replacement and upgrades

Installing a newer binary never widens an existing `scope.json`. Rerunning
service setup stops if a managed policy already exists. Inspect it and opt in to
replacement explicitly:

```sh
sudo hf-broker setup systemd \
  --hf-token-file ./hf-token \
  --client agent \
  --replace-policy
```

For a deliberately narrow installation, supply `--repo` and `--repo-type`.
That explicit mode retains the single-repository policy and does not install a
preset profile or manifest.

## Integration contract

Wrappers such as ML Claw should invoke `hf-broker policy render` or the default
setup command. They should not copy an operation list, infer effects, or create
BrokerKit-owned profile and manifest formats themselves. BrokerKit owns catalog
classification, deterministic rendering, and drift diagnostics.
