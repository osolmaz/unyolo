# HF Broker Request-All Policy Preset Plan

Date: 2026-07-14

## Objective

Make a BrokerKit-owned HF Broker policy preset the default for new HF Broker
installations. The preset must expose every supported agent-facing Hugging Face
operation through an explicit policy decision:

- safe read and discovery operations may run directly;
- normal writes, administrative actions, and destructive actions may be
  requested but require human approval;
- credential-output, broker-internal, and non-agent-facing operations remain
  denied;
- operators may completely opt individual operations out with explicit deny
  overrides.

The intended experience is that an agent can ask to create or delete an exact
repository without an operator manually adding a new allowlist entry first,
but it cannot execute either mutation until the exact immutable request is
approved.

## Decision

The preset belongs to HF Broker inside the BrokerKit monorepo, not to ML Claw
and not to BrokerKit's provider-neutral `policy` package.

HF Broker owns the Hugging Face operation catalog, target vocabulary, risk
metadata, grant modes, and immutable operation plans. The shared policy package
continues to own only generic rule validation and decision semantics. ML Claw
selects the released HF Broker preset; it does not maintain a second Hugging
Face operation list.

The stable preset identifier is:

```text
request-all-agent-operations
```

New `hf-broker setup` installations select this preset by default. BrokerKit
and HF Broker still fail closed when no valid policy has been configured. A
library caller, hand-started broker process, or malformed installation never
receives an implicit policy.

## Current State

HF Broker now has a catalog of 258 operations under
`brokers/huggingface/internal/opcatalog`. The descriptors already record:

- operation name and revision;
- risk class;
- target kind;
- agent-facing and internal status;
- implementation status;
- window versus execution approval mode;
- explicit-only and sealed behavior;
- maximum uses and approval lifetimes;
- credential-output type, when applicable.

The setup command still renders a narrow, hand-written single-repository scope.
ML Claw separately carries its own hand-written `hf-broker.scope.json`. These
files can lag behind the catalog, which is why a newly supported operation can
exist in the broker but receive `no_match` instead of creating an approval.

## Security Invariants

1. The runtime policy remains an explicit list of rules. No wildcard means
   "all present and future operations."
2. Updating the HF Broker binary must never silently authorize a newly added
   operation. Existing materialized policies remain unchanged.
3. Every catalog operation must declare its preset effect. Adding an operation
   without that declaration fails catalog validation and CI.
4. High-risk, critical-risk, execution-mode, explicit-only, sealed, or
   mutating operations cannot default to `allow`.
5. Credential-output operations default to `deny`, even when they are
   agent-facing. An operator must configure them explicitly outside this
   preset.
6. Internal and non-agent-facing operations are never emitted as requestable
   rules.
7. Request approval remains bound to the exact operation revision, target,
   arguments, immutable plan digest, client, expiry, and use budget.
8. Execution approvals remain one-use. Approval does not create a standing
   wildcard grant for a related resource or operation.
9. Explicit user deny rules override preset allow rules, request rules, and
   active grants.
10. Policy generation, diagnostics, manifests, and errors never contain the
    Hugging Face token, broker client secrets, sealed payloads, or credential
    output.

## Catalog Classification

Add a required provider-owned field to each HF operation descriptor:

```json
{
  "default_policy_effect": "allow | request | deny"
}
```

This is policy-generation metadata, not a runtime decision and not a generic
BrokerKit concept. Risk alone is insufficient: a medium-risk inference call
may need to run directly for an agent harness, while a low-cost mutation must
still require approval.

Initial classification rules:

| Descriptor | Default effect |
| --- | --- |
| Read-only identity, metadata, listing, discovery, logs, metrics, and repository content operations | `allow` |
| Router model listing and inference required by an agent harness | `allow` |
| Agent-facing writes, creation, updates, administration, deletion, jobs, endpoints, and other mutations | `request` |
| Credential-output operations | `deny` |
| Internal or non-agent-facing operations | `deny` |

Catalog validation must reject these combinations:

- missing or unknown default effect;
- `allow` on high or critical risk;
- `allow` on execution-mode, explicit-only, sealed, internal, or
  credential-output operations;
- `request` on internal, non-agent-facing, non-grantable, or
  credential-output operations;
- an agent-facing implemented operation that has no valid preset decision.

The classification is reviewed alongside every operation implementation. No
generator infers mutation safety from operation-name suffixes.

## Materialized Policy

Implement a provider-owned generator under the HF Broker subtree, for example:

```text
brokers/huggingface/internal/policypreset
```

It consumes the validated operation catalog and HF policy registry and emits a
normal explicit `scope.json`. The running broker continues to parse the same
policy format; it does not expand presets while serving requests.

Generate one stable rule per operation. This is intentionally verbose but
auditable, remains below the existing 1,000-rule limit, keeps explicit-only
operations exact, and avoids grouping operations with incompatible target or
grant semantics.

Each generated rule contains:

- a stable ID derived from the preset and exact operation name;
- the selected client names;
- the exact operation name, never an operation-family glob;
- a provider-valid wildcard target matcher for that operation's target kind;
- `allow`, `request`, or `deny` from the catalog classification;
- for `request`, grant mode and bounds derived from the descriptor;
- a generated description that names the preset and operation.

Request rules omit argument constraints so the agent may propose any valid
closed-schema argument set. The approval workflow still binds the exact
validated arguments and immutable execution plan. Operation executors retain
all provider-side precondition and upstream permission checks.

The output must be deterministic: sorted operations, canonical field order,
stable whitespace, and no timestamps. Identical catalog, profile, and override
inputs produce byte-identical policy and digest output.

## Profile And Opt-Outs

Keep user intent separate from generated rules in a small version-1 profile:

```json
{
  "version": 1,
  "preset": "request-all-agent-operations",
  "clients": ["agent"],
  "denied_operations": ["repo.delete"]
}
```

`denied_operations` accepts only exact registered operation names. It cannot
contain globs, and duplicates are rejected. The generator emits explicit deny
rules whose precedence completely removes those operations from the agent's
requestable surface.

This profile is not accepted as an authorization policy by the running broker.
It is trusted installation input used to produce the explicit runtime
`scope.json`. Users needing resource-specific rules, custom allows, or more
complex constraints may provide a complete custom scope instead of the
preset.

Store a secret-free manifest beside generated policies:

```json
{
  "version": 1,
  "preset": "request-all-agent-operations",
  "catalog_digest": "sha256:...",
  "profile_digest": "sha256:...",
  "policy_digest": "sha256:...",
  "operation_counts": {
    "allow": 0,
    "request": 0,
    "deny": 0
  }
}
```

The real counts are generated from the current catalog. The manifest contains
no targets proposed by agents, approval records, arguments, credentials, or
token metadata.

## CLI And Setup

Add deterministic, non-interactive commands:

```sh
hf-broker policy render \
  --preset request-all-agent-operations \
  --client agent \
  --profile-out profile.json \
  --manifest-out manifest.json \
  --output scope.json

hf-broker policy check --file scope.json
```

Support repeatable `--deny-operation` during rendering as a convenience for
creating the profile. Refuse to overwrite existing output unless the operator
passes an explicit replacement flag. Never print policy files containing
operator-added sensitive target data in ordinary diagnostics.

Change new `hf-broker setup systemd` installations to select
`request-all-agent-operations` when neither a custom policy nor another preset
is specified. Setup writes the profile, manifest, and materialized scope before
starting the service and validates the final scope with the production parser.

The setup summary must say plainly:

```text
Safe reads and inference can run directly.
Writes and destructive operations require approval.
Credential-output and explicitly denied operations are unavailable.
```

Setup must not silently replace an existing scope. Reconfiguration renders a
candidate, shows the affected operation counts and digest change, and requires
an explicit replace action.

The current single-repository setup remains available only as an explicitly
selected restrictive preset or as a custom policy. It is no longer the default
for a fresh general-purpose HF Broker installation.

## Upgrade And Doctor Behavior

Existing generated policies do not dynamically gain operations after a binary
upgrade. `hf-broker doctor` compares the installed manifest with the current
catalog and reports:

- operations added since materialization;
- operations removed or renamed;
- operations whose default effect, risk, grant mode, revision, or lifecycle
  bounds changed;
- missing or invalid deny overrides;
- mismatch between profile, policy, manifest, and on-disk digests.

Doctor never widens policy automatically. It prints the exact command for
rendering a candidate policy. The operator reviews the diff and explicitly
installs it. A stale but valid explicit policy continues to run and new
operations receive `no_match` until the reviewed update is installed.

If the installed policy claims to be preset-managed but its digest no longer
matches, Doctor reports local modification and refuses automated replacement.
The operator may keep it as a custom policy or regenerate from the saved
profile.

## ML Claw Integration

After the BrokerKit implementation is released, ML Claw must:

1. delete its hand-maintained Hugging Face operation allowlist;
2. invoke the released HF Broker policy renderer while building or updating a
   Space or local gateway;
3. select `request-all-agent-operations` by default;
4. preserve the user's exact deny-operation profile across updates and local
   versus Space migration;
5. include the profile, manifest, and materialized scope in Doctor checks;
6. show policy drift without exposing any broker or Hugging Face credential;
7. require an explicit user action before adopting newly cataloged operations.

ML Claw may add product-specific deny overrides, but it must not copy operation
names or reconstruct grant policies. BrokerKit remains the single source of
truth.

## Implementation Work

1. Extend `opcatalog.Descriptor` and `catalog.json` with the required default
   effect and enforce the catalog invariants above.
2. Classify all 258 current operations and add coverage tests proving every
   descriptor has one reviewed decision.
3. Implement deterministic HF target templates and the provider-owned preset
   renderer using the production HF policy registry.
4. Add profile parsing, exact deny-operation validation, canonical rendering,
   and the secret-free digest manifest.
5. Add `hf-broker policy render` and `hf-broker policy check` with atomic file
   writes, overwrite protection, and secret-safe output.
6. Integrate the preset into `setup systemd` as the fresh-install default while
   retaining an explicit restrictive/custom-policy path.
7. Extend Doctor with catalog/profile/policy drift reporting and candidate
   regeneration guidance. Do not add live policy reload or mutation endpoints.
8. Update HF Broker policy, setup, security, and operator documentation.
9. Replace ML Claw's static HF policy with released renderer output in a
   downstream change.

## Tests

Add focused tests for:

- exact catalog coverage and invalid default-effect combinations;
- deterministic byte-for-byte rendering and stable digests;
- production parser acceptance of generated policy;
- every agent-facing operation resolving to `allow`, `request`, or explicit
  `deny`, never accidental `no_match` in a freshly generated policy;
- no high-risk, critical-risk, execution, explicit-only, sealed, internal, or
  credential-output operation receiving default `allow`;
- request rules matching descriptor grant mode, TTL, and use limits;
- exact deny overrides winning over allow, request, and active grants;
- malformed profiles, globs in deny lists, unknown operations, duplicate
  operations, and overwrite attempts failing closed;
- a catalog addition making old manifests stale without changing the old
  runtime policy;
- setup selecting the preset by default and custom policy selection remaining
  explicit;
- Doctor detecting stale, modified, missing, and internally inconsistent
  generated artifacts;
- policy and manifest output containing no protected credential values;
- a live disposable HF flow where a safe read succeeds, `repo.create` creates
  one exact approval, approval executes once, and `repo.delete` creates a
  separate exact approval before deletion;
- an opted-out `repo.delete` refusing without creating an approval.

Run the full BrokerKit and HF Broker quality gates, including race tests,
coverage, lint, vulnerability scanning, Slophammer checks, and generated
artifact consistency.

## Acceptance Criteria

- A fresh default HF Broker installation covers every current agent-facing
  operation without hand-maintained operation lists outside the HF catalog.
- Safe reads and required inference work immediately.
- Writes and destructive operations create exact approval requests instead of
  returning policy `no_match`.
- Credential-output, internal, and explicitly opted-out operations remain
  unavailable.
- Existing installations never gain new authority merely because the binary
  was upgraded.
- Doctor reports catalog drift and supports a reviewable candidate update.
- ML Claw can consume the released preset without carrying its own HF operation
  policy inventory.

