# GitHub Operation Coverage Plan

Date: 2026-07-14

Status: implemented and validated

## Objective

Make GH Broker a comprehensive, policy-gated GitHub capability broker with the
same operation architecture and security guarantees as HF Broker. A coding
agent must be able to request any supported GitHub action without receiving a
GitHub credential or a generic HTTP or GraphQL escape hatch.

The cutover covers Git smart HTTP, the GitHub REST API, the GitHub GraphQL API,
GitHub App lifecycle operations, user-attributed operations, binary transfers,
and asynchronous GitHub workflows. Every official capability in the pinned
inventory must be implemented or assigned a precise non-agent disposition.

This is a coordinated fresh-state cutover. Do not preserve the current 15-item
registry, `pr.create`-specific Agent lifecycle, old operation names, old plan
shape, compatibility aliases, or old state readers.

## Non-Goals

- Do not expose a generic REST proxy, arbitrary GraphQL, arbitrary GitHub CLI,
  or local shell execution.
- Do not return GitHub App keys, tokens, refresh tokens, PATs, webhook secrets,
  or other original credentials through any route or result.
- Do not bypass GitHub permissions, installation consent, SSO, rulesets, branch
  protection, environments, required reviews, or billing controls.
- Do not silently claim GitHub Enterprise Server parity from the GitHub.com
  catalog. A GHES release requires its own pinned product/version inventory and
  dispositions; the transport may still validate an explicitly configured GHES
  base URL.
- Do not automate GitHub App permission elevation or installation re-consent.
  Generate the required manifest and let the operator approve it on GitHub.
- Do not preserve pre-release compatibility or make mutation testing a gate.

## Current Baseline

GH Broker currently registers 15 operations:

- five Git push mutations plus fetch and receive-pack advertisement;
- pull request create, update, and merge policy names;
- repository metadata, contents, and checks reads;
- installation repository listing; and
- inbound GitHub webhook receipt.

Only pull request creation is submitted and executed through Agent V1. The
remaining JSON API is a small set of handwritten routes, and the GitHub App
implementation hand-rolls JWT signing, installation discovery, and token
minting.

HF Broker now provides the target architecture: one validated provider-owned
catalog, generated policy/CLI/MCP/documentation surfaces, closed input schemas,
immutable plans, one generic lifecycle, sealed secret handling, reconciliation,
and exhaustive coverage tests.

The GH Broker-specific instruction that forbids organization administration,
workflow administration, member management, repository deletion, and broad
GitHub operations must be replaced during this cutover. Those actions are not
categorically unsupported. They are separately typed, explicit-only, one-use,
high- or critical-risk operations that require matching policy and approval.

## Shared BrokerKit Extraction

Do not copy HF Broker's generic operation machinery into GH Broker. Before the
GitHub catalog lands, extract the provider-neutral parts into root BrokerKit
packages and migrate HF Broker to them without changing behavior.

The shared boundary owns:

- the generic capability descriptor type and structural validation;
- registry lookup, uniqueness, schema, mode, TTL, use, and surface invariants;
- Agent V1 submission, idempotency, authorization-or-request, approval binding,
  authority consumption, worker dispatch, cancellation, restart recovery,
  reconciliation, stable outcomes, and audit correlation;
- encrypted single-use payload and credential-output lifecycle primitives;
- descriptor-driven CLI/MCP/capability-document generation; and
- provider-neutral adapter contract tests.

Provider brokers register callbacks and data. Shared packages do not import a
broker or know GitHub/Hugging Face operation names, targets, credentials,
schemas, API clients, presentation wording, or reconciliation semantics.

The provider-owned adapter contract may use a shared envelope equivalent to:

```go
type Adapter interface {
    Descriptor() capability.Descriptor
    Decode(target, arguments json.RawMessage) (Input, error)
    Resolve(context.Context, Input) (Plan, error)
    Authorize(Plan) policy.Request
    Present(Plan) agentv1.Presentation
    Execute(context.Context, Plan) (json.RawMessage, error)
    Reconcile(context.Context, Plan) (agentops.Outcome, error)
}
```

HF and GH retain their own concrete adapters and plan payloads while the shared
runtime drives the lifecycle. The extraction is complete only when HF's current
258-operation behavior and tests pass against the shared runtime and GH does
not introduce a second copy of the orchestration.

## Pinned Sources of Truth

Freeze all upstream inputs in the repository. Network access is never required
to compile, test, or validate a release.

1. Pin GitHub's official stable REST OpenAPI bundle at API version `2026-03-10`
   and an exact commit from
   [`github/rest-api-description`](https://github.com/github/rest-api-description).
   The 2026-07-10 snapshot at commit
   `3b43edf675308c515b5e92a3eb89db17f6e6d806` contains 1,196 REST operations,
   945 of which declare `x-github.enabledForGitHubApps: true`.
2. Use the stable OpenAPI 3.0 bundle as the upstream fidelity artifact because
   GitHub describes `descriptions-next` OpenAPI 3.1 as subject to breaking
   changes. Generate BrokerKit-owned closed JSON Schema 2020-12/OpenAPI 3.1
   operation schemas from the pinned stable input.
3. Pin a full GitHub GraphQL introspection result and schema fingerprint. The
   2026-07-14 live schema exposes 32 root query fields and 252 root mutation
   fields. GitHub documents introspection as the discovery mechanism for the
   [public GraphQL schema](https://docs.github.com/en/graphql/guides/introduction-to-graphql).
   The inventory must map every root mutation and every query capability used
   by a broker operation.
4. Pin the official
   [GitHub App endpoint-permission matrix](https://docs.github.com/en/rest/authentication/permissions-required-for-github-apps)
   and API-version documentation used to classify app JWT, installation access
   token, and user access token support. GitHub App permissions remain an
   upstream ceiling; BrokerKit policy can only narrow them.
5. Pin webhook event schemas used for installation changes, authorization
   revocation, repository transfers/deletion, workflow completion, and other
   reconciliation signals.

Store source metadata beside each snapshot: source URL, source commit or schema
fingerprint, retrieval date, API version, content digest, and license notice.
CI must reject an unpinned or locally edited upstream snapshot.

## Coverage Definition

"Comprehensive" means that every item from every pinned source has a row in a
machine-readable coverage map. It does not mean that every item is exposed to
agents.

Each REST operation receives exactly one disposition:

- `implemented`: exposed as a typed broker operation;
- `protocol`: implemented by Git smart HTTP, a bounded binary stream, or
  another non-JSON protocol adapter;
- `graphql`: represented by a named persisted GraphQL document and exposed only
  after every variable that selects authority is bound to the validated target;
- `internal`: required for broker credential, installation, webhook, health,
  or reconciliation machinery and never agent-facing;
- `operator-only`: available only on the protected operator surface;
- `local`: a local CLI concern that does not require broker authority;
- `duplicate`: intentionally represented by another canonical operation, with
  that operation named in the binding;
- `blocked-credential`: valid GitHub behavior that the configured credential
  model cannot perform, with the required credential kind recorded; or
- `blocked-upstream`: documented but unavailable on the selected GitHub product
  or API version, with the exact reason recorded.

No route may be omitted. GitHub App-disabled routes are not automatically
dropped; they are mapped to a user-token operation, operator-only behavior, or
a precise blocked disposition.

GraphQL coverage follows the same rule. Every root mutation maps to a canonical
broker operation, a REST-backed duplicate, or a precise non-agent disposition.
GraphQL root queries and nested fields used by the broker are listed in the
persisted-query manifest. GH Broker never accepts caller-provided GraphQL text,
fragments, field selections, directives, or operation names.

Nested GraphQL fields are representation choices rather than independently
authorizable mutations. They are covered through the reviewed result projection
of a cataloged read operation, not counted as separate agent operations.

## Canonical Operation Catalog

Add `brokers/github/internal/opcatalog` using the shared BrokerKit descriptor
and registry validation extracted from HF. One sorted `catalog.json` is the
provider-owned source for policy, Agent V1, MCP, CLI, operator presentation,
documentation, and runtime dispatch.

Each descriptor contains at least:

```text
name
operation_revision
summary
risk
disposition
implementation_status
authorization_mode
explicit_only
family_glob_allowed
max_uses
request_ttl_seconds
approval_ttl_seconds
target_kind
target_schema
argument_schema
result_schema
credential_kind
required_github_permissions
required_repository_selection
sealed_input_paths
credential_output_kind
upstream_binding_ids
executor_kind
reconciler_kind
agent_facing
mcp_tool
cli_command
```

Catalog validation must reject duplicate or unsorted names, unknown target
kinds, unsupported disposition combinations, missing schemas, unbound upstream
routes, unsafe family globs, secret-bearing window grants, execution grants with
more than one use, and agent-facing operations without CLI/MCP metadata.

Generate `brokers/github/docs/generated/capabilities.json` and the human
capability reference from the catalog. Do not hand-maintain operation lists in
the README, policy package, CLI, MCP server, or tests.

## Operation Naming and Taxonomy

Use stable semantic names rather than GitHub SDK method names or REST paths.
Split broad upstream update endpoints into independently approvable fields. For
example, `PATCH /repos/{owner}/{repo}` does not become `repo.update`; it binds to
separate operations such as `repo.description.update`,
`repo.visibility.update`, `repo.default_branch.update`, and
`repo.feature.update`.

Use these top-level families:

- `git.*`, `repo.*`, `commit.*`, `branch.*`, `tag.*`, and `release.*`;
- `issue.*`, `pull_request.*`, `review.*`, `discussion.*`, `comment.*`,
  `label.*`, `milestone.*`, and `reaction.*`;
- `check.*`, `deployment.*`, `environment.*`, `workflow.*`, `action_run.*`,
  `artifact.*`, `cache.*`, and `runner.*`;
- `ruleset.*`, `branch_protection.*`, `security.*`, `advisory.*`,
  `code_scanning.*`, `secret_scanning.*`, and `dependabot.*`;
- `project.*`, `team.*`, `member.*`, `collaborator.*`, `organization.*`,
  `enterprise.*`, and `installation.*`;
- `package.*`, `pages.*`, `codespace.*`, `gist.*`, `notification.*`,
  `migration.*`, `campaign.*`, `copilot.*`, and `agent_task.*`;
- `webhook.*`, `app.*`, `oauth.*`, and `credential.*` for internal or
  operator-only control actions.

Canonicalize current names during the cutover:

- `pr.create`, `pr.update`, and `pr.merge` become
  `pull_request.create`, `pull_request.update`, and `pull_request.merge`;
- `contents.read` becomes `repo.contents.read`;
- `checks.read` becomes the exact `check.*` list/read operations;
- branch creation and fast-forward pushes are classified as
  `git.push.append` where their authorization semantics are identical;
- `git.push.advertise` and inbound webhook receipt become internal protocol
  operations; and
- installation repository listing becomes `installation.repo.list`.

There are no aliases for the removed names.

## Targets and Policy Attributes

Add a GitHub-owned target registry. Use immutable numeric or node IDs in plans
when GitHub exposes them, while retaining the human owner/name/number fields for
policy and presentation. Targets include repository, organization, enterprise,
user, installation, app, team, issue, pull request, discussion, comment,
project, workflow, run, job, artifact, cache, deployment, environment, release,
package, codespace, gist, advisory, alert, webhook, ruleset, ref, commit, check,
label, milestone, and notification thread.

Path-derived IDs are not trusted as canonical identity. Resolution verifies
that the resource belongs to the requested parent and records the observed
immutable identity.

Register only attributes that policy can compare safely, including exact refs,
paths, base/head refs, actor logins or IDs, roles, permissions, visibility,
environment, workflow/ref, labels, merge method, release state, and bounded
resource identifiers. Do not put request bodies, GraphQL, arbitrary JSON, URLs,
regexes, or secrets into policy attributes.

Default policy behavior remains fail-closed:

- no match is denied;
- read operations may use bounded reusable window grants;
- every mutation is an immutable execution operation;
- destructive, identity, membership, permission, billing, workflow, ruleset,
  secret, credential-vending, and organization/enterprise administration
  operations are explicit-only and one-use;
- explicit-only operations cannot match `*` or family globs; and
- an upstream GitHub permission never substitutes for BrokerKit policy.

GitHub rulesets, branch protection, required reviews, environments, and other
native controls remain an independent upstream enforcement layer. GH Broker
must not attempt to bypass or weaken them implicitly.

## Credential Domains

Treat credential selection as broker-owned plan metadata, never caller input.
Support these distinct credential kinds:

1. `app-jwt`: app identity for installation discovery and app-management
   endpoints. Agent-facing use is normally forbidden.
2. `installation`: short-lived installation access tokens for repository and
   organization resources. Mint them for the exact installation, repository
   set, and minimum permission map required by the descriptor.
3. `user`: expiring GitHub App user access tokens for actions that must be
   attributed to or authorized by a user. Store and rotate refresh tokens in an
   encrypted broker-owned store and process authorization-revocation webhooks.
4. `development-token`: protected-file PAT fallback for local development only.
   Doctor must mark it non-production and no credential value may have a
   readback path.

Adopt `ghinstallation/v2` for app JWT transport and token lifecycle only where
it supports the required bounded behavior. Use `google/go-github` installation
token options to request exact repositories and minimum permissions. Cache only
by the full tuple of installation, repository IDs, permissions, API host, and
expiry; never reuse a broader token for a narrower operation merely because it
is available.

Use `google/go-github` for typed resources, pagination, rate limits, webhook
validation/parsing, and API error classification. Wrap it behind GH-owned
interfaces with deadlines, response limits, redirect policy, redaction,
deterministic clocks, and GitHub Enterprise base-URL validation. The SDK does
not define operation coverage and must not leak its types into policy or shared
BrokerKit packages.

Delete the replaced JWT, installation-token, pagination, and narrow REST code
in `internal/githubapp` and `internal/githubapi` in the same cutover. Do not
source-vendor these libraries without a separate supply-chain or maintenance
justification.

## REST Binding Layer

Add `brokers/github/internal/opbinding` generated from the pinned official
OpenAPI snapshot plus a small reviewed override file. A binding records the
catalog operation, upstream operation ID, HTTP method, path template, credential
kind, media type, parameter projection, request schema projection, response
projection, byte limits, pagination mode, conditional-request support, and
reconciliation strategy.

The runtime may use a bounded generic REST adapter for simple bindings. This is
not a generic API proxy:

- callers submit a catalog operation, typed target, and closed arguments;
- method, host, path template, headers, API version, and response projection
  come only from the immutable binding;
- unknown query/body fields fail closed;
- target-derived path parameters override caller-controlled values;
- redirects are disabled unless the binding explicitly permits a validated
  GitHub download host;
- request and response sizes are independently bounded; and
- raw upstream bodies and headers are never returned.

Use dedicated typed adapters when an operation needs field splitting, multiple
upstream calls, preconditions, secret handling, streaming, asynchronous
reconciliation, or domain-specific presentation. A generated REST binding is a
transport primitive, not authorization logic.

## GraphQL Boundary

GraphQL support consists only of reviewed persisted documents stored with an
exact digest, operation name, variable schema, response projection, cost bound,
credential kind, and catalog binding.

A persisted document is not agent-facing until it also has a reviewed target
binding for every owner, repository, node, and nested mutation-input identifier
that selects authority. Catalog coverage alone is not execution support. The
current pinned GraphQL roots remain operator-only because their generated
target classifications do not yet prove those bindings. This fail-closed
disposition prevents an allowed display target from authorizing variables that
access or mutate a different GitHub resource.

Use GraphQL when it provides a capability absent from REST, stronger immutable
preconditions, a safe atomic mutation, or a materially smaller bounded read.
Prefer REST when both APIs provide equivalent behavior and REST has a stable
typed endpoint.

At startup and in CI:

- validate every document against the pinned schema;
- reject introspection, multiple operations, dynamic directives, unbounded
  connections, caller-defined field selections, and unbounded recursion;
- require explicit `first`/`last` limits on every connection;
- calculate and cap expected query cost; and
- prove that response projection cannot expose credential or private fields not
  declared by the operation result schema.

The Agent API never accepts GraphQL text or a GraphQL operation ID directly.

## Immutable GitHub Plan V1

Replace GH plan V1 in place with the generic adapter envelope used by the HF
architecture. The plan binds:

- canonical operation name and operation revision;
- canonical target and immutable GitHub IDs;
- normalized public arguments;
- sealed payload references and digests, never plaintext;
- credential kind, installation/user selector, required permissions, and exact
  repository IDs;
- upstream REST binding or persisted GraphQL digest;
- observed ETag, node ID, object SHA, ref SHA, run attempt, state digest, or
  absence proof needed by the operation;
- policy decision context, requester, approval mode, use limit, and expiry;
- redacted operator presentation; and
- canonical plan digest.

Resolve mutable names before approval. Immediately before execution, verify all
preconditions. Use `If-Match` or equivalent GitHub conditional behavior when
available; otherwise perform a bounded preflight read and compare the canonical
state digest.

Critical examples:

- PR merge binds pull request ID, base ref, expected head SHA, merge method, and
  observed mergeability state;
- ref update/delete binds repository ID, full ref, and old object SHA;
- repository transfer/delete binds repository ID, owner/name, visibility, and a
  typed confirmation;
- workflow dispatch binds workflow ID, exact ref SHA, and canonical input
  digest;
- ruleset and branch protection updates bind the observed ruleset digest;
- membership/role changes bind actor ID, organization/team ID, and old role;
- secret writes bind secret name and plaintext digest while keeping the value
  sealed; and
- release uploads bind release ID, asset name, size, media type, and content
  digest.

Approval never authorizes arguments or a target supplied later.

## Secret Inputs and Credential Outputs

Use the existing sealed payload design for Actions, Dependabot, Codespaces,
webhook, environment, organization, and repository secrets; OAuth client
secrets; private keys; and any other write-only input. Plaintext exists only in
bounded memory during validation/encryption/execution and is deleted at every
terminal state.

Where GitHub requires libsodium sealed-box encryption, fetch and bind the exact
public-key ID, encrypt inside GH Broker, and never persist or display plaintext.
Unknown secret paths are rejected even if the upstream request schema accepts
additional properties.

Token-vending operations such as Actions runner registration tokens use the
credential-output channel. They are explicit-only, one-use, short-lived, and
delivered only into a predeclared encrypted credential slot. Installation
tokens, app JWTs, user access tokens, refresh tokens, and PATs are internal
credentials and are never vendable agent operations.

## Generic Agent Lifecycle

Register GH adapters with the extracted BrokerKit operation runtime. Use the
same lifecycle as HF for allow, request, deny, cancellation, approval,
execution, reconciliation, restart recovery, idempotency, outbox notification,
and audit. Delete `pullRequest*` submission, authorization, worker, and result
branches. GH HTTP handlers must not reimplement lifecycle decisions.

For ambiguous timeouts and GitHub `202 Accepted` workflows, do not retry a
mutation blindly. Reconcile using resource IDs, idempotency markers, head SHAs,
delivery/run IDs, or before/after state. Finish as succeeded only when remote
state proves the approved result. Otherwise use stable unknown or reconciliation
failure outcomes and require a new operation when safety cannot be proven.

## Protocol and Streaming Operations

Keep Git smart HTTP as a protocol surface, but classify it through the same
catalog and policy registry. Use shared `gitx` parsing and preserve GitHub's
native report behavior.

- Fetch uses a repo-scoped, read-only installation token.
- Append push covers branch creation and proven fast-forward updates.
- Force push, tag replacement, ref deletion, workflow-file changes, and pushes
  to protected/default refs remain separately classifiable.
- Multi-ref pushes authorize every command; one denied command rejects the
  whole pack before forwarding.
- Requestable push operations create an exact ref/SHA grant and require retry;
  the broker never stores and executes an arbitrary pack after approval.

Implement release assets, archives, Actions artifacts/logs, code-scanning
uploads, and other binary endpoints through named bounded stream adapters.
Every adapter declares media type, compressed and expanded limits, digest
requirements, redirect allowlist, timeout, and safe result metadata. Never load
unbounded artifacts into memory or expose an authenticated redirect URL.

## CLI, MCP, and Capability Discovery

Generate one CLI command and one typed MCP tool definition per agent-facing
descriptor, using the HF operation-surface generator pattern. Do not advertise
the entire GitHub catalog to every MCP client at once. Large catalogs must
remain discoverable without consuming the client's full tool context:

- `gh-broker operations list [--family ...] [--risk ...]`;
- `gh-broker operations describe <name>`;
- `gh-broker operation submit <name> --target ... --arguments ...`;
- `gh-broker operation get|wait|cancel <id>`;
- a paged MCP capability resource containing every catalog descriptor; and
- generated explicit MCP tools with closed schemas and concise summaries for
  the operations exposed to the current client and deployment.

MCP tool advertisement is a presentation filter, not authorization. Compute it
from the authenticated client, the loaded policy, the runtime credential and
GitHub-product capabilities, and an operator-managed MCP exposure profile.
Policy is still evaluated again when the operation is submitted. Default
profiles expose the common code/review operations; operators can enable exact
additional operations or bounded families. Explicit-only operations require an
exact exposure entry and cannot appear through a family glob.

Use MCP `tools/list_changed` when a session's advertised set changes. Keep tool
names stable and regenerate each tool's exact target and argument schema from
the descriptor. Tests must cover empty, default, family, exact administrative,
and complete exposure profiles, including a policy change during a live
session.

Do not generate one generic MCP tool that accepts arbitrary operation names and
JSON without schema-level tool validation. Capability discovery may return the
catalog, but advertised MCP execution surfaces remain typed. Agent V1 and the
CLI remain capable of submitting every enabled catalog operation after strict
server-side schema validation, even when an operation is not currently
advertised as an MCP tool.

Operator presentation must show the exact GitHub resource, operation, risk,
meaningful argument changes, immutable preconditions, credential attribution,
expiry, and one-use semantics. Secrets, raw request bodies, diffs beyond strict
bounds, tokens, and upstream headers remain hidden. Telegram and the BrokerKit
web inbox decide the same durable request.

## GitHub App Permission Profiles

Generate the minimum GitHub App permission manifest from enabled catalog
operations. Ship documented profiles rather than requiring every deployment to
grant every permission:

- `code`: metadata, contents, pull requests, issues, checks, and deployments;
- `automation`: Actions, workflows, environments, runners, artifacts, and
  deployments;
- `security`: code scanning, secret scanning, Dependabot, advisories, and
  security settings;
- `administration`: repositories, rulesets, collaborators, teams, webhooks,
  organization, and enterprise controls; and
- `complete`: every implemented GitHub App permission for exhaustive test and
  intentionally broad operator deployments.

Profiles are installation permission ceilings, not policy. Scope files still
decide client access operation by operation. `doctor github` must compare the
catalog operations referenced by policy with app/user credential capabilities,
report missing installation consent, detect stale user authorization, and warn
about permissions granted upstream but unused by policy.

## Implementation Sequence

Implement on one cutover branch with coherent conventional commits. The final
merge replaces the old system in one step; intermediate commits need not retain
runtime compatibility but must compile and pass their focused tests.

### 1. Extract and Prove the Shared Operation Runtime

- Move generic descriptors, registry validation, lifecycle orchestration,
  sealed payload primitives, generated surface support, and adapter contracts
  into provider-neutral root packages.
- Cut HF Broker over to the shared runtime and retain all 258 catalog entries,
  Agent/CLI/MCP schemas, restart behavior, Telegram/inbox decisions, and tests.
- Add architecture checks that prevent providers from importing each other and
  prevent a second provider-local lifecycle implementation.

### 2. Freeze and Classify the GitHub Inventory

- Check in pinned REST, GraphQL, permission, and webhook snapshots with
  provenance and digests.
- Generate the complete route and GraphQL-root coverage maps.
- Define canonical semantic names, split broad update endpoints, target kinds,
  schemas, risks, credential kinds, permissions, dispositions, and execution
  modes.
- Review every destructive, secret, permission, billing, organization, and
  enterprise operation manually.

### 3. Add Catalog, Bindings, and Generated Surfaces

- Add `opcatalog`, target registry, schema projections, REST bindings, persisted
  GraphQL manifest, and startup validation.
- Generate capabilities, CLI, MCP, policy registry, and documentation.
- Add drift tests proving all 1,196 pinned REST operations and all pinned
  GraphQL roots have exactly one disposition.

### 4. Replace Credential Handling

- Introduce app, narrowed installation, user, and development credential
  providers.
- Add encrypted user-token enrollment and rotation on a protected operator or
  local setup path with no readback endpoint.
- Process installation and authorization revocation webhooks.
- Adopt wrapped `ghinstallation/v2` and `google/go-github`, then delete replaced
  custom JWT/token/read code.

### 5. Cut Over Plans and Lifecycle

- Replace GH plan V1 in place with immutable adapter plans.
- Replace the PR-create-specific lifecycle and worker with generic registry
  dispatch, reconciliation, sealed payloads, and credential outputs.
- Preserve shared SQLite transactions, use budgets, outbox, operator inbox, and
  Telegram behavior.

### 6. Implement Repository Collaboration and Git

- Complete repos, contents, commits, refs, branches, tags, releases, issues,
  PRs, reviews, discussions, comments, checks, deployments, and Git smart HTTP.
- Make PR merge, force push, ref deletion, workflow-file mutation, repository
  transfer, and repository deletion exact requestable operations.
- Delete old JSON routes or reimplement them as thin clients of Agent V1; do not
  retain independent authorization paths.

### 7. Implement Automation, Security, and Binary Surfaces

- Complete Actions/workflows/runs/jobs/artifacts/caches/runners, environments,
  Pages, packages, codespaces, security alerts/settings, Dependabot, scanning,
  advisories, and bounded uploads/downloads.
- Enable sealed secret inputs and credential outputs only after their dedicated
  security gates pass.

### 8. Implement Organization, Enterprise, and User Surfaces

- Complete teams, membership, collaborators, projects, webhooks, installations,
  organization and enterprise administration, billing-visible operations,
  migrations, notifications, gists, user-attributed actions, Copilot, campaigns,
  and agent tasks.
- Implement reviewed persisted GraphQL operations where REST is incomplete.
- Leave only precise credential/product/version limitations as blocked entries.

### 9. Delete Legacy Code and Ship

- Remove old operation constants, registry switches, PR lifecycle, custom
  GitHub App implementation, narrow Reader, duplicate REST routes, manual CLI
  lists, and refusal documentation.
- Replace `scope.example.json` with deny-by-default read, feature-branch, PR,
  destructive approval, secret, and administrative examples.
- Regenerate docs and artifacts, run the complete gates, deploy a disposable
  GitHub test installation, and merge only after local and CI verification.

## Test Strategy

### Source and Coverage Tests

- Verify snapshot digests, API version, provenance, and schema parsing.
- Require one disposition for every REST operation and GraphQL root mutation.
- Reject duplicate bindings, missing operation IDs, stale generated artifacts,
  unreviewed new upstream endpoints, and route/catalog/schema drift.
- Compare catalog permission requirements with the pinned official permission
  matrix.

### Adapter Contract Tests

Run the same contract suite for every adapter:

- strict bounded JSON with duplicate-key, unknown-field, trailing-data,
  invalid-UTF-8, and oversized-input rejection;
- deterministic normalization, plan digest, and presentation;
- canonical target ownership and immutable ID resolution;
- exact credential selector and minimum permission set;
- stale precondition refusal;
- one expected upstream call or reviewed call sequence;
- bounded/redacted response projection;
- deterministic rate-limit, forbidden, conflict, validation, timeout, and
  ambiguous-outcome errors; and
- reconciliation that proves success without replaying mutations.

### Lifecycle and Security Tests

- allow, request, deny, no-match, cancel, expire, revoke, and one-use consume;
- concurrent workers and duplicate idempotency keys;
- restart before and after approval, authority consumption, upstream send,
  response receipt, and reconciliation;
- app permission changes, installation suspension/deletion, repository transfer,
  user authorization revocation, token refresh, and SSO/permission failures;
- sealed input deletion and credential-output single delivery;
- no secret in plans, SQLite, audit, logs, errors, events, Telegram, web UI,
  fixtures, or test output; and
- GraphQL cost, persisted digest, response projection, and arbitrary-document
  rejection.

### Git and Streaming Tests

- fast-forward proof, force push, branch create, tag replacement, ref deletion,
  multi-ref atomic refusal, default/protected branch behavior, SHA-1/SHA-256
  framing, malformed packs, size limits, and GitHub report passthrough;
- workflow-file permission distinction;
- upload/download limits, redirects, content-length mismatch, chunked bodies,
  compression bombs, digest mismatch, interrupted streams, and cleanup; and
- fuzzing for path/query projection, webhook parsing, GraphQL variables,
  receive-pack commands, and binary metadata.

### Real GitHub End-to-End Tests

Use a dedicated GitHub App, organization, user authorization, and disposable
repositories. Tests must be idempotent, uniquely named, cost-aware, and have
verified cleanup.

The live matrix must include:

1. unrestricted policy denial with no upstream mutation;
2. repository read and Git fetch through a narrowed read token;
3. feature-branch push and PR creation;
4. PR update/review/merge bound to the expected head SHA;
5. Actions workflow dispatch and run reconciliation;
6. secret set with sealed input and no value readback;
7. ruleset or branch-protection update after explicit approval;
8. collaborator/team or organization-role change after explicit approval;
9. user-attributed operation through an expiring user access token;
10. repository deletion requested by the agent, approved through Telegram or
    the operator inbox, executed once, and verified absent;
11. replay refusal after the destructive grant is consumed; and
12. installation/user revocation with immediate execution refusal.

Exercise both direct and delegated OpenClaw operator UI modes for representative
read, mutation, destructive, stale, secret-bearing, denied, expired, and
ambiguous requests.

### Required Gates

- `go fmt ./...`
- `go vet ./...`
- `go test ./...`
- focused race tests for catalog, lifecycle, credentials, webhooks, Git, and
  streaming adapters
- `golangci-lint run`
- `slophammer-go check .`
- aggregate and GH package coverage gates with no blanket exclusions
- OpenAPI/GraphQL snapshot, generated-artifact, architecture, SQL, secret, DRY,
  and complexity checks
- OpenClaw plugin check, unit tests, build, packed-install test, and Playwright
  suite
- branch CI and Codex review against the base branch until no P0/P1 findings
  remain

Mutation tooling remains checked in but disabled and non-blocking.

## Cutover Deletion List

Delete in the same implementation branch:

- handwritten `Operation*` constants and duplicated registry metadata;
- `pr.create`-specific request decoding, plans, authorization, execution,
  recovery, and worker branches;
- independent `/api/repos` and contents authorization/execution paths replaced
  by catalog operations;
- custom GitHub App JWT signing, broad installation-token minting, and manual
  installation pagination replaced by wrapped libraries and narrowed tokens;
- the narrow `internal/githubapi.Reader` where typed adapters replace it;
- hand-maintained CLI, MCP, policy, README, and approval operation lists;
- old GH plan fields, validators, fixtures, and pre-release state;
- broad text claiming administrative or destructive GitHub operations are
  unsupported; and
- any endpoint that accepts a raw GitHub method, path, URL, GraphQL document,
  header map, or untyped request body.

## Acceptance Criteria

The cutover is complete only when:

1. Every operation in the pinned 1,196-route REST snapshot and every pinned
   GraphQL root mutation has exactly one reviewed binding or disposition.
2. Every agent-facing capability has a catalog descriptor, closed schemas,
   target resolver, policy metadata, safe presentation, executor, reconciler,
   CLI command, generatable typed MCP definition, and documentation row. MCP
   advertises only the operations enabled for that client and deployment.
3. Repository deletion and all other supported destructive/admin actions can be
   requested, approved through Telegram or the operator inbox, executed once,
   and reconciled against GitHub.
4. No caller can supply raw REST paths, GraphQL documents, credentials,
   credential selectors, permission maps, or post-approval arguments.
5. Installation tokens are narrowed to the exact repository set and minimum
   GitHub permissions required by the approved operation.
6. User-attributed operations use expiring GitHub App user tokens with encrypted
   refresh storage and revocation handling.
7. Unknown operations/fields, stale plans, expired approvals, replay,
   insufficient GitHub permissions, and policy no-match fail closed.
8. Secret values and broker credentials are absent from every durable,
   operator-visible, and agent-visible surface.
9. GitHub-native rulesets and protections remain effective and are never
   implicitly weakened.
10. All old GH registry, PR special cases, custom credential code, duplicate
    routes, and refusal documentation are removed.
11. The disposable GitHub live matrix, including Telegram-approved repository
    deletion and user-token revocation, passes with verified cleanup.
12. HF Broker runs on the shared operation runtime with no behavior regression,
    and GH Broker contains no copied provider-neutral lifecycle implementation.
13. All required local and CI gates are green before merge.

## Implementation Result

The cutover shipped as one catalog-driven platform with 1,436 GitHub
capabilities, of which 1,129 are agent-facing. The reviewed catalog contains
1,121 agent-facing REST-backed operations, eight agent-facing protocol
operations, 281 persisted GraphQL operations held operator-only pending
reviewed target-variable bindings, 19 other operator-only operations, and seven
internal operations. The
credential split is 1,035 installation-token operations, 380 user-token
operations, 20 app-JWT operations, and one explicit development-token mode.

The implementation now provides:

- generated closed schemas, CLI commands, MCP tools, capability documents, and
  runtime bindings from one provider-owned catalog;
- the shared BrokerKit operation lifecycle for GH and HF, including SQLite
  durability, Telegram and operator-inbox decisions, use budgets, sealed
  inputs, credential outputs, streams, restart recovery, and reconciliation;
- narrowed `ghinstallation` transports and typed `go-github` operations with
  bounded nested projections, no raw REST or GraphQL caller surface, strict
  REST target binding, and authenticated-user identity checks;
- 110 absence-proof reconcilers, bounded upload and download handling, and
  generated pagination for 277 bindings; and
- architecture, generated-artifact, coverage, secret, DRY, and exact
  non-regression complexity gates in CI.

Live validation used the globally installed broker and Bob's client identity.
An in-scope repository metadata read succeeded with a bounded result, while an
out-of-scope read was denied before GitHub. A destructive repository request
was delivered through Telegram, approved for one use, consumed once, and
returned GitHub's permission denial without exposing the credential. Repeating
the same client idempotency key returned the original terminal operation and
did not create another grant or upstream call. Authenticated-user operations
also reject a target that does not match the selected credential's GitHub
identity before mutation.

The complete local Go, race, aggregate coverage, static analysis,
vulnerability, secret, Slophammer, OpenClaw unit, build, packed-install, and
cross-browser Playwright gates pass. Successful destructive-operation testing
still requires a deployment credential that GitHub has granted the
corresponding destructive permission; BrokerKit correctly treats that
upstream permission as a ceiling rather than bypassing it.
