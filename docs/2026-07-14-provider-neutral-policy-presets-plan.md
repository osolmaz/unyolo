# Provider-Neutral Policy Presets Plan

Date: 2026-07-14

Status: complete

## Implementation Result

Completed on 2026-07-15 as part of the production-readiness cutover.

- The root `policypreset` package owns versioned profiles and manifests,
  canonical digests, drift reports, deny overrides, replacement previews, and
  transactional artifact updates.
- Hugging Face and GitHub keep provider-local catalogs, classifications,
  renderers, target rules, and grant bounds while using the shared lifecycle.
- Both brokers install `request-all-agent-operations` on fresh setup, require
  explicit replacement for existing managed policy, and support deliberate
  deny preservation or reset.
- Cross-provider, corruption, drift, replacement, and setup tests enforce the
  ownership boundary and fail-closed artifact behavior.

## Goal

Give every unYOLO provider the same reliable policy-preset lifecycle without
making provider-specific security decisions part of shared infrastructure.

The Hugging Face broker already ships the
`request-all-agent-operations` preset. A future GitHub preset should provide the
same operator experience: ordinary safe operations may run directly, supported
sensitive operations can be requested for human approval, explicitly excluded
operations remain denied, and local deny overrides survive policy refreshes.

When GitHub implements this behavior, extract only the lifecycle machinery that
is proven identical across both brokers. Keep each provider's operation catalog,
default effects, risk metadata, target rules, grant bounds, descriptions, and
policy rendering decisions inside its own `brokers/<provider>` directory.

## Design Principle

Policy presets have two distinct layers:

1. **Provider policy:** which operations exist and whether each operation should
   default to `allow`, `request`, or `deny` for that provider.
2. **Preset lifecycle:** canonical profile and manifest handling, deterministic
   digests, drift checks, replacement previews, transactional artifact writes,
   and preservation of local deny overrides.

Only the second layer belongs in unYOLO's shared root packages.

This avoids two bad outcomes:

- duplicating complex artifact and replacement behavior in every broker;
- centralizing Hugging Face or GitHub security policy in a generic package that
  cannot understand provider semantics.

## Extraction Trigger

Do not move the current Hugging Face implementation merely to make it look
reusable. Begin the extraction while implementing the GitHub preset, after the
GitHub operation catalog has explicit default effects and the first complete
GitHub render works inside `brokers/github`.

At that point, compare both implementations and extract code only when it has
the same inputs, invariants, failure behavior, and tests in both providers.
Provider-specific branches or callbacks that merely hide copied provider logic
are not an acceptable shared abstraction.

## Ownership Boundaries

### Shared unYOLO packages own

- strict version 1 profile and manifest envelopes;
- canonical JSON encoding and SHA-256 digest generation;
- operation-count summaries;
- operation fingerprint comparison and drift reporting;
- validation that profile, manifest, policy, and catalog agree;
- preservation and reset semantics for exact deny overrides;
- candidate-versus-installed replacement summaries;
- all-or-nothing artifact creation and replacement, using or minimally
  extending the existing shared setup and service primitives where possible;
- rollback, cleanup, file synchronization, and fail-closed partial-set checks;
- provider-neutral test fixtures and conformance tests for the lifecycle.

### Each provider broker owns

- its operation catalog and catalog generator;
- operation names, revisions, risks, and authorization modes;
- the default `allow`, `request`, or `deny` classification;
- preset names and operator-facing descriptions;
- target selectors and policy-rule shapes;
- request and approval TTLs, use limits, and grant bounds;
- rendering catalog entries into that broker's concrete scope policy;
- provider CLI wording and setup defaults;
- tests asserting that every provider operation has a deliberate classification.

Shared packages must not import `brokers/`, and one provider must never import
another provider's preset package.

## Proposed Architecture

Add a small provider-neutral package at the repository root, tentatively
`policypreset/`. It should operate on typed generic inputs supplied by a
provider adapter, not load provider catalogs itself.

```go
type Profile struct {
    Version          int
    Preset           string
    Clients          []string
    DeniedOperations []string
}

type Operation struct {
    Name                string
    Revision            int
    DefaultEffect       Effect
    AuthorizationDigest string
}

type ProviderRenderer interface {
    ProviderID() string
    PresetName() string
    Operations() []Operation
    Render(Profile) (policy []byte, fingerprints []OperationFingerprint, err error)
}
```

The exact API should be derived from the two real implementations. Provider
code should compute the authorization digest from a canonical, strictly typed
provider descriptor. The shared API must not accept `map[string]any` or attempt
to understand provider fields. Provider tests must prove that the digest covers
every field whose change can alter authorization behavior.

The provider package remains responsible for constructing the renderer and
validating its concrete policy with its existing policy parser. The shared
package returns canonical profile, policy, and manifest bytes plus a typed
summary suitable for CLI output and setup plans.

## Artifact Contract

Every managed preset installation continues to contain three files:

- `policy-profile.json`: small operator-editable preset input;
- the broker's concrete scope policy file;
- `policy-manifest.json`: immutable render evidence and operation fingerprints.

All unYOLO-owned persisted formats remain version 1. Before unYOLO's
first public release, incompatible changes replace version 1 in place through a
coordinated fresh-state cutover. Do not add compatibility readers, format
aliases, dual writes, or migrations.

The manifest must identify the provider and preset so artifacts cannot be
checked or installed by the wrong broker. It must bind the canonical profile,
concrete policy, operation catalog, operation counts, and complete
authorization-relevant fingerprints with SHA-256 digests.

## GitHub Preset

The GitHub broker should introduce its own
`request-all-agent-operations` preset after its operation inventory is complete.
The shared name communicates the operator intent; it does not imply identical
operation classifications across providers.

The GitHub provider must classify every catalog operation explicitly:

- `allow` only for low-risk operations that are safe for unattended agents;
- `request` for supported mutations or administrative operations that can be
  bound to an exact target and reviewed before execution;
- `deny` for credential disclosure, unsupported authorization shapes, or
  operations that cannot be made safe through immutable approval.

No operation may inherit an effect from a name prefix, HTTP method, or fallback
rule. Catalog generation and tests must fail when an operation has no explicit
classification.

## CLI and Setup Behavior

Each broker keeps its own executable and commands, but the behavior should be
consistent:

```text
<provider>-broker policy render
<provider>-broker policy check
<provider>-broker doctor policy
<provider>-broker setup systemd --policy-preset request-all-agent-operations
```

Fresh setup defaults to the provider's request-all preset. Existing explicit
narrow-scope setup flags continue to select the narrow policy mode. Managed
policy replacement requires an explicit replacement flag and displays current
and candidate digests plus `allow`, `request`, `deny`, and total count changes
before writing anything.

Exact deny overrides persist across reruns and catalog refreshes. Removing them
requires an explicit replacement and reset action. Partial, modified, malformed,
cross-provider, or digest-mismatched artifact sets fail closed with a command
that tells the operator how to inspect or deliberately replace them.

## Implementation Order

1. Complete explicit default-effect coverage in the GitHub operation catalog.
2. Implement a provider-local GitHub preset render and end-to-end test first.
3. Compare the Hugging Face and GitHub implementations and list only truly
   identical lifecycle responsibilities.
4. Introduce the root provider-neutral package and move those responsibilities
   behind typed inputs.
5. Convert Hugging Face to the shared lifecycle without changing its generated
   artifacts or setup behavior.
6. Convert GitHub to the same lifecycle while retaining its own renderer and
   classifications.
7. Deduplicate CLI and setup helpers only where doing so does not introduce
   provider conditionals into shared packages.
8. Run cross-provider conformance, failure-injection, setup, doctor, and live
   approval tests before removing the old provider-local lifecycle code.

Each conversion should be a coordinated cutover. Do not retain parallel old
and new artifact paths.

## Testing

Shared lifecycle tests must cover:

- deterministic rendering and byte-for-byte stable artifacts;
- malformed, partial, modified, stale, and cross-provider artifact sets;
- every manifest digest and authorization-relevant fingerprint field;
- operation additions, removals, revisions, and effect changes;
- deny preservation, retired-operation cleanup, and explicit reset;
- current-versus-candidate replacement previews;
- create, replace, rollback, interrupted-write, and cleanup failures;
- no interval where a previously existing output path disappears;
- file modes, directory synchronization, and absence of leftover staging files.

Provider tests must cover:

- explicit classification of every generated catalog operation;
- exact expected counts for `allow`, `request`, and `deny`;
- concrete policy parsing and authorization behavior;
- immutable request, approval, execution, reconciliation, and result flow;
- representative safe, approval-required, denied, and adversarial operations;
- setup reruns and provider-specific narrow-policy escape hatches.

Run the normal Go quality gates, race tests, coverage checks, Slophammer, secret
scanning, and one compiled CLI end-to-end test for both brokers.

## ML Claw Impact

ML Claw should not render or interpret provider policy presets. It continues to
start and connect to separate broker processes through unYOLO's version 1
operator contract. Installation may select each broker's default preset, but
the preset profile, manifest, policy, drift checks, and replacement lifecycle
remain owned by that broker.

This keeps ML Claw provider-agnostic while allowing an installation to expose
Hugging Face and GitHub approval requests in the same operator inbox.

## Acceptance Criteria

- Hugging Face and GitHub use one shared preset lifecycle implementation.
- Both providers keep independent catalogs, classifications, renderers, and
  credentials.
- The Hugging Face preset preserves its existing behavior and generated policy.
- GitHub fresh setup installs a deliberate request-all preset by default.
- Every provider operation has an explicit tested effect.
- Drift and replacement behavior is equivalent across both brokers.
- Local deny overrides survive ordinary setup reruns and catalog upgrades.
- Corrupt, partial, modified, or cross-provider artifacts fail closed.
- No shared package imports a provider directory or switches on provider names.
- ML Claw requires no provider-specific policy logic.

## Non-Goals

- one universal operation catalog across providers;
- identical default effects for similarly named provider operations;
- a single broker process, credential domain, state directory, or audit stream;
- policy presets authored or rendered by ML Claw;
- arbitrary user-authored preset plugins in the first implementation;
- compatibility with pre-release artifact formats other than the current
  coordinated version 1 cutover.
