# Hugging Face policy presets

hf-broker can render a provider-owned policy from a small operator profile. A
preset is installation convenience, not a second policy engine: the resulting
`scope.json` is an ordinary explicit rule file and is validated by the same
strict parser used at broker startup.

## Default preset

`request-all-agent-operations` is the default for a fresh service setup. It
materializes one exact rule for every operation in the embedded Hugging Face
catalog. It does not contain operation-family wildcards.

The catalog stores an explicit `default_policy_effect` for each operation:

| Effect | Behavior |
|---|---|
| `allow` | Safe reads and discovery plus inference run directly. |
| `request` | Writes and administration plus destructive actions require operator approval. Execution-scoped actions receive exact, one-use grants. |
| `deny` | Internal and non-agent operations plus credential-output operations cannot be requested by the agent. |

These effects are data in the reviewed provider catalog. The renderer never
guesses from an operation name or risk label. An operation marked
`blocked-upstream` is always rendered as deny even if its future target effect
would otherwise be allow or request. Catalog validation also prevents
high-risk, critical, execution-scoped, explicit-only, or sealed operations from
defaulting to `allow`.

Reusable window grants in this preset default to their catalog ceiling. Routine
repository and bucket operations allow up to `1000000` uses for up to seven
days, which avoids repeated approval during large uploads and artifact runs.
`git.push.force`, `git.ref.delete`, and `git.tag.update` remain capped at 25
uses for one hour. Execution-scoped operations remain single-use. Every grant
keeps the exact client, operation, target, and attribute scope that was
approved.

An operator can hard-deny additional exact operations:

```sh
sudo hf-broker setup systemd \
  --hf-token-file ./hf-token \
  --client agent \
  --deny-operation repo.delete
```

Unknown and duplicate deny overrides are rejected.
On later setup runs, installed deny overrides are preserved and new
`--deny-operation` values are added to them. Clear all installed overrides only
with the explicit pair `--replace-policy --reset-denied-operations`; any new
`--deny-operation` values on that invocation become the replacement set.

Use an exact protected target when a broker-managed resource must remain
unreachable under every catalog operation. This rule overrides allow and
request rules:

```sh
sudo hf-broker setup systemd \
  --hf-token-file ./hf-token \
  --client agent \
  --protect-bucket acme/mlclaw-state \
  --protect-repo dataset:acme/private-state
```

`--protect-bucket` accepts `OWNER/NAME`. `--protect-repo` accepts
`TYPE:OWNER/NAME`. Wildcards are rejected. Setup preserves installed protected
targets during replacement, including a deny-operation reset.

## Render without installing

Render the profile, concrete policy, and manifest together:

```sh
hf-broker policy render \
  --preset request-all-agent-operations \
  --client agent \
  --deny-operation repo.delete \
  --protect-bucket acme/mlclaw-state \
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

The manifest binds the profile and policy together with the embedded operation
catalog by SHA-256 digest. It also records each operation's revision, catalog default
effect, final policy effect after operator overrides, risk,
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
| `current` | Profile and policy match the manifest and current catalog. | 0 |
| `stale` | The embedded operation catalog changed after rendering. | 1 |
| `modified` | A profile or policy no longer matches its manifest. | 1 |
| `invalid` | An artifact cannot be parsed or validated. | 2 |

Use `--json` for automation. Catalog drift reports which operation names were
added or removed and which ones changed. Doctor never edits policy files or contacts a
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

Replacement verifies the installed profile and manifest against the scope
before carrying forward hard-denies. Inconsistent artifacts stop setup and require a
Doctor check or an explicit `--reset-denied-operations`.

Before refusing an unconfirmed replacement, setup prints the current and
candidate policy digests and the allow and request counts plus deny and total
operation-count changes. `--dry-run` prints the same preview without writing files. Review that
output before rerunning with `--replace-policy`.

For a deliberately narrow installation, supply `--repo` and `--repo-type`.
That explicit mode retains the single-repository policy and does not install a
preset profile or manifest.

## Integration contract

Wrappers such as ML Claw should invoke `hf-broker policy render` or the default
setup command. ML Claw passes its state bucket through `--protect-bucket` so the
generated deny remains part of the managed profile. Wrappers should not copy an
operation list, infer effects, or create unYOLO-owned profile and manifest
formats themselves. unYOLO owns catalog classification, deterministic
rendering, and drift diagnostics.
