# GitHub Broker Platform Adoption Plan

Date: 2026-07-11

Status: implemented; final monorepo review, merge, release, and live installed
verification pending

Required companion plans:

- `docs/2026-07-11-universal-broker-platform-plan.md`
- `docs/2026-07-11-monorepo-consolidation-plan.md`

Monorepo destination: `brokers/github`

## Outcome

`gh-broker` should expose the same stable Brokerkit operator protocol as
`hf-broker` while keeping GitHub authentication, request classification,
canonical plans, execution, and provider-native protections in its broker directory.
A trusted host registers one generic broker source; it does not need special
code for GitHub Apps, installation tokens, Git, pull requests, webhooks,
rulesets, branch protection, REST, or GraphQL.

## Current Baseline

The repository already:

- uses Brokerkit's canonical control-plane runtime;
- has separate agent and operator credentials/listeners;
- mounts the shared operator inbox and HF-independent presenter contract;
- runs Brokerkit control-plane conformance tests;
- owns GitHub operation/target/attr registration and classification;
- supports Git smart HTTP and narrow repository/contents/pull routes;
- supports GitHub App JWT signing, installation resolution, and short-lived
  installation tokens, with a development PAT fallback;
- verifies GitHub webhooks;
- uses Brokerkit grants, reservations, durable notification state, Telegram,
  audit, setup, installer, and doctor primitives;
- handles ambiguous upstream and commit results fail closed; and
- has no credential management or readback API.

The adoption should preserve these invariants and add a versioned common wire
contract plus explicit provider-plan binding.

## Hard Ownership Boundary

### Remains in gh-broker

- GitHub App id/private key loading and JWT signing;
- installation lookup and short-lived token minting;
- development PAT loading and restrictions;
- repository visibility and installation selection;
- Git smart HTTP parsing decisions that depend on GitHub behavior;
- REST/GraphQL route schemas and response filtering;
- pull request create/update/merge semantics;
- webhook signature/event/delivery validation;
- ruleset, branch-protection, default-branch, and bypass interpretation;
- GitHub operation/target/attr registry and policy vocabulary;
- canonical capability-window and single-execution plans;
- upstream API-version headers, pagination, rate limits, retries, and ambiguity;
- GitHub-specific risk, presentation, audit, and doctor behavior; and
- live provider tests.

### Consumed from Brokerkit

- Operator V1 schema and protected handler;
- lifecycle, revisions, decision idempotency, and narrowing;
- safe presentation validation;
- operator credential separation;
- durable queries/events and cursor rules;
- stable common errors;
- source/client/fake fixtures; and
- Operator V1 conformance.

Brokerkit must not learn GitHub installation, repository, PR, ref, webhook,
ruleset, branch-protection, permission, or API semantics.

## Provider Adapter Shape

Continue assembling one Brokerkit runtime with a GitHub-owned presenter and
plan validator:

```go
controlplane.New(controlplane.Options{
    Broker:          "gh-broker",
    Store:           grantStore,
    ClientSecrets:   clients,
    OperatorSecrets: operators,
    Presenter:       approval.Presenter{},
    ActivationValidator: ghplan.Validator{Store: planStore},
    Audit:           auditWriter,
})
```

The proposed `ActivationValidator` hook reports only valid/invalid to
Brokerkit. It never returns a private key, installation token, PAT, provider
plan, request body, or GitHub response. Brokerkit's one `DecisionService` must
invoke it for operator HTTP, Telegram, CLI, and future approval channels so a
transport cannot bypass GitHub plan checks.
The runtime's approval-channel `Decider` is an adapter over that service; this
broker must not install a second store decider beside it.

## Canonical GitHub Plan Model

GitHub operations also require two kinds of approval:

```text
capability_window
single_execution
```

Git push is normally a capability window: approval authorizes an exact repo,
ref class, constraints, time, and use budget, while the pack arrives at
execution and is reclassified/validated before forwarding.

A PR create/update/merge or narrow REST operation can be a single execution
when its decision-relevant payload is known and stored before approval.

### Internal plan resource

```json
{
  "schema_version": "gh-broker.io/plan/v1",
  "kind": "single_execution",
  "operation": "pr.merge",
  "target": {
    "owner": "osolmaz",
    "repository": "gh-broker",
    "pull_number": 42
  },
  "constraints": {
    "base_ref": "refs/heads/main",
    "merge_method": "squash",
    "required_head_sha": "abc123..."
  },
  "credential_mode": "github_app",
  "created_at": "2026-07-11T12:00:00Z"
}
```

Rules:

- the plan is a closed, versioned, immutable GH-owned resource;
- it contains no App private key, JWT, installation token, PAT, webhook secret,
  Authorization header, signed URL, raw pack, or raw provider response;
- `credential_mode` selects configured server behavior and cannot name a raw
  credential or client-chosen installation token;
- repository/installation resolution is repeated safely at execution when
  current provider state matters;
- canonical plan bytes are atomically written to a content-addressed private
  store before grant creation; bounded grant metadata records plan schema and
  digest, and grant creation is the visibility commit;
- unreferenced prewritten plans are inert and garbage-collected after a safety
  window, avoiding a cross-file atomic commit and circular grant ids;
- Brokerkit request idempotency includes the plan-reference metadata, so one
  client request id cannot silently select different plan content;
- any missing, corrupt, mismatched, or unsupported plan blocks activation and
  execution;
- approval narrows Brokerkit duration/uses but never edits owner, repo, ref,
  PR, SHA, method, request body, or operation;
- a changed GitHub action requires a new request rather than plan mutation;
- a canonical internal digest may bind grant, plan, execution, and audit but is
  not part of Brokerkit Operator V1; and
- retention follows lifecycle and prevents orphan executable authority.

## Operation Families

### Git smart HTTP

Plans and policy must distinguish fetch, receive-pack discovery, branch create,
existing branch update, proven fast-forward where possible, conservative
force-like update, ref delete, tag update, and unsupported refs. A capability
window binds exact owner/repo, permitted ref patterns or exact ref, update
class, pack-size limit, duration, and uses.

Approval does not waive malformed pack rejection, body limits, forbidden ref
classes, default-branch policy, GitHub rulesets, branch protection, or
execution-time provider denial. Where fast-forward cannot be proven before the
pack reaches GitHub, retain the existing conservative classification.

### Pull requests

Typed operations should cover create, update, review/approval if deliberately
supported, merge, close/reopen, and read. A single-execution plan stores only
normalized decision-relevant fields:

- exact owner/repository and PR number where applicable;
- head/base refs and expected head SHA;
- title/body digest or bounded safe metadata, not necessarily raw private text
  in the operator projection;
- merge method and auto-merge choice;
- draft/state transition;
- required current-state preconditions; and
- execution settlement behavior.

PR title/body may contain sensitive or hostile text. It is provider input, not
safe common presentation unless explicitly sanitized and bounded.

### Narrow REST/GraphQL

Keep a route registry with exact method, path template, query/body schema,
forwarded headers, response projection, operation, target, attrs, plan kind,
grantability, and audit mapping. Unknown routes/methods/fields fail closed.

Do not add a generic authenticated `/api/github/*` or GraphQL passthrough.
GraphQL operations, if supported, must use broker-owned persisted documents or
typed query constructors with bounded variables; never accept arbitrary agent
queries under the App credential.

### Webhooks

Webhooks are provider input and backstop signals, not operator commands.
Continue verifying signature, delivery id, event type, body bounds, and
installation/repository identity before use. If installation caches are added,
invalidate them from verified relevant events. Never let webhook payloads
directly approve a Brokerkit request.

## GitHub Credential Safety

Production remains GitHub App first:

```text
validated broker request
  -> policy/grant/plan authorization
  -> resolve exact repository installation
  -> mint short-lived minimal installation token
  -> build sanitized upstream request
  -> execute with timeout and response bounds
  -> discard token
  -> settle use and audit
```

Requirements:

- mint tokens only after policy and plan checks allow the operation;
- request only minimal App permissions and repository access;
- never write minted tokens to disk or expose them in logs, plans, grants,
  errors, audit, traces, tests, or operator/browser responses;
- disable credential forwarding across redirects;
- strip client Authorization, Cookie, proxy, and hop-by-hop headers;
- validate GitHub API and upload/archive origins before sending credentials;
- keep PAT fallback explicitly development-only unless a documented production
  exception uses a fine-grained, repo-scoped, rotated token;
- cache installation tokens only in bounded private memory with expiration and
  repository/installation binding; and
- treat auth/permission mismatch as an operational security diagnostic, not a
  reason to broaden App permissions automatically.

## Provider-Native Backstops

Broker authorization is necessary but not sufficient. At execution time:

- re-read default branch where relevant;
- evaluate applicable rulesets or classic branch protection;
- validate installation visibility and current permissions;
- verify expected PR head SHA/state before merge;
- avoid App bypass on protected branches;
- respect required reviews/checks and merge queue rules where applicable;
- reject stale plan preconditions rather than silently adapting the action; and
- let GitHub deny an operation even after operator approval.

Approval grants permission to attempt the stored action under current safety
checks. It does not promise provider acceptance and never freezes GitHub state.

## Operator Presentation

Evolve the existing presenter to:

- use an explicit operation-to-risk table instead of substring matching;
- present title, consequence-focused summary, and bounded facts;
- include owner/repository, ref, PR number, base/head refs, expected SHA prefix,
  merge method, update class, protected/default-branch status, duration, and
  uses when relevant;
- state when an update is conservatively classified as force-like; and
- keep all display values inert text.

Unknown registered operations use `unknown` risk and fail presenter-coverage
tests until classified.

Do not expose App ids when unnecessary, installation tokens, PAT metadata,
private keys, webhook secrets, raw PR bodies, arbitrary diffs, Git packs,
provider responses, arbitrary Markdown/HTML/URLs, or editable plans.

When ambiguous provider execution retains a reservation and makes an
apparently active grant unusable, the presenter adds a bounded `Needs
attention` fact such as `Execution result is ambiguous; authority is closed`.
Reservation counters and internal settlement event kinds remain off V1.

## V1 Mapping From Current Types

| Current field | V1 projection | V1 rule |
| --- | --- | --- |
| `Client` | `requester` | Bounded actor label only. |
| `Operation` | `operation` | Preserve GH-owned classification. |
| `Duration` | `requested_duration_seconds` | Positive integer seconds. |
| `MaxUses` | `requested_max_uses` | Preserve requested committed-use limit. |
| narrowed `MaxUses` | `granted_max_uses` | Store separately at approval; never overwrite the original requested count. |
| `ReservedCount` | omitted | Keep execution reservation private. |
| `Reason` | `request_reason` | Sanitize and bound. |
| `Presentation.Fields` | `presentation.facts` | Bounded inert label/value facts. |
| `Presentation.Target` | title/facts | Fold the current required target into explicit `Repository`, `Ref`, or `Pull request` facts; V1 has no separate target slot. |
| status-derived actions | `allowed_actions` | Compute per authoritative revision. |
| policy limits | `approval_bounds` | Compute per request/revision. |

The V1 projection wraps the same canonical grant/store and event log. There is
no second GH request state machine.

## Errors, Rate Limits, And Ambiguity

| GitHub condition | Common result |
| --- | --- |
| malformed typed request or plan | `invalid_request` |
| broker policy denial | `forbidden` |
| stale operator decision | `revision_conflict` |
| narrowing beyond bounds | `constraint_exceeded` |
| unknown narrow route | `not_found`; never proxy |
| installation/repository not visible | safe `not_found` or `forbidden` according to route contract |
| GitHub 401/403 for server credential | `temporarily_unavailable` plus private security diagnostic |
| GitHub 404 | safe `not_found` without leaking inaccessible repo existence across clients |
| primary/secondary rate limit | `rate_limited` with safe `Retry-After` derived from GitHub headers |
| timeout/5xx before dispatch | bounded safe retry/release when non-dispatch is proven |
| ambiguous write or lost response after dispatch | retain/close use fail closed; never replay a non-idempotent provider action blindly |
| missing/corrupt plan | `internal_error`, block action, security audit |

Keep GitHub request ids and rate-limit diagnostics in bounded provider audit,
not raw common errors. Never forward raw response bodies or sensitive headers.

## Decision Idempotency Versus Provider Idempotency

Brokerkit decision idempotency guarantees that retrying `approve` does not
approve twice. It does not make the later GitHub action idempotent.

Each operation family must document provider execution semantics:

- safe GET/list/read may retry within a bounded budget;
- Git pack forwarding is not blindly replayed after ambiguous dispatch;
- PR creation should use a broker-side execution id and reconcile by exact
  target/head/base before retry where possible;
- merge checks current PR/SHA state and treats already-merged as a reconciled
  result only when it matches the same canonical plan;
- webhook delivery ids deduplicate only webhook processing; and
- retained reservations close authority when the broker cannot prove whether a
  provider mutation occurred.

## Testing Strategy

### Common conformance

Run Brokerkit Operator V1 conformance on the real GH operator handler: strict
unknown input rejection, tolerant/drop-only unknown response handling, auth
separation, listener isolation, revision/idempotency behavior,
narrowing, live pagination plus the first-page event-cursor handoff, SSE
reconnect, presentation fallback, restarts, no-store,
errors, and secret leak fixtures.

### GH plan tests

- closed-schema round trips for every plan kind/operation;
- reject unknown versions, fields, operations, targets, and constraints;
- prevent grant-to-plan substitution and target mutation;
- prove approval cannot widen scope;
- missing/corrupt/mismatched plan blocks activation/execution;
- HTTP revision-bound and Telegram token-bound approval use the same Brokerkit
  decision service and activation validator;
- crash recovery before plan write, after plan write/before grant creation, and
  after grant creation, including safe orphan collection;
- stable internal digest fixtures;
- no credentials/raw sensitive payloads in plans; and
- fuzz decoding and canonicalization.

### Provider tests

- fake GitHub API, Git smart HTTP, installation-token minting, webhook, and
  protection endpoints by default;
- explicit route-registry coverage and catch-all rejection;
- Git ref/update classification and body bounds;
- PR validation and stale head/state checks;
- GitHub App permission, installation, and token isolation;
- redirect/header/origin/timeouts/rate-limit behavior;
- ruleset/classic protection/default-branch backstops;
- deny overriding active grants;
- ambiguous execution and grant settlement;
- complete risk/presenter coverage;
- presenter fallback preserves actions/bounds, and ambiguous settlement gets a
  safe `Needs attention` fact; and
- audit/error/trace leak corpus.

### Live milestone probes

Use a dedicated GitHub App installation and disposable private repository.
Verify list/read, feature-branch push, request/approval, PR create, protected
default-branch denial, expiry, revoke, restart, rate-limit observation, and
webhook processing. Avoid destructive organization actions. Clean up resources
and keep live probes outside default CI.

## Implementation Order For The Single Cutover

These are dependency-ordered commits in the one monorepo branch. None is a
supported deployment until the complete cutover passes:

1. inventory current Git/API routes, operation/target/attr vocabulary, auth
   modes, grants, presenter output, state, and every provider execution path;
2. define deterministic canonical GitHub plans and content-addressed plan
   storage, then bind every pending grant before visibility;
3. add the GitHub activation validator to BrokerKit's one decision service and
   make every HTTP/channel decision path use it;
4. mount only Operator V1 discovery/list/watch/decision routes and delete the
   unversioned operator handler and duplicate decision path;
5. harden GitHub App/PAT containment, installation selection, Git smart HTTP,
   pull requests, narrow REST/GraphQL, webhooks, provider-native rules, rate
   limits, and ambiguous outcomes;
6. add V1 conformance, plan mutation, ambiguity, restart, cursor, rate-limit,
   presenter, secret-canary, and provider behavior tests;
7. integrate the source with the OpenClaw plugin using only the common
   presentation and decision contract;
8. run disposable live GitHub probes for every shipped operation family, revoke
   or expire all old authority, initialize fresh state, and include GH only in
   the complete coordinated release.

If any check fails, the cutover does not expose the new GitHub listener. Do not
add an adapter, dual route, dual state, or old-format reader to continue.

## Clean Cutover Rules

- Read only the new V1 config, grant, plan, event, cursor, and idempotency
  shapes.
- Mount only the V1 operator contract.
- Do not import old state or preserve active grants across cutover.
- Do not run old/new GH binaries against each other's state.
- Archive old state and audit files for forensic retention only.
- Preserve no generic GitHub proxy, broad PAT escape hatch, or provider-rule
  bypass.
- The first supported GitHub deployment is the complete monorepo release.

## Acceptance Criteria

The GH adoption is complete when:

- it passes Brokerkit Operator V1 conformance;
- the trusted host registers it with the same interface as HF;
- common UI and host decision code contain no GitHub-specific branch;
- every requestable operation has a closed immutable provider plan/predicate;
- App/PAT authority is reachable only through registered typed routes,
  classification, policy, plan, grant, and live provider checks;
- approval cannot replace or widen a GitHub action;
- rulesets, branch protection, current PR/SHA state, and installation visibility
  remain execution-time backstops;
- credentials, packs, raw bodies, plans, and upstream responses never cross the
  common operator/browser boundary;
- retry, ambiguity, rate limiting, restart, cursor expiry, and cutover failures are
  deterministic and fail closed; and
- GitHub behavior can evolve independently without polluting Brokerkit.
