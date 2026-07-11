# Hugging Face Broker Platform Adoption Plan

Date: 2026-07-11

Status: proposed; depends on the Brokerkit Operator V1 contract

Required companion plans:

- `docs/2026-07-11-universal-broker-platform-plan.md`
- `docs/2026-07-11-monorepo-consolidation-plan.md`

Monorepo destination: `brokers/huggingface`

## Outcome

`hf-broker` should expose Brokerkit's stable operator protocol while continuing
to own every Hugging Face-specific security decision and upstream interaction.
A trusted host should be able to register this broker exactly like a GitHub or
future broker, but neither Brokerkit nor the common UI should learn Hugging
Face token, Hub, Router, Git, LFS, Xet, repository-type, mirror, or Storage
Bucket semantics.

This plan supports broad Hugging Face access tokens safely. The broad token
stays behind `hf-broker`; agent authority remains the intersection of the
broker's narrow routes, request classifier, policy, grant, canonical plan, and
live Hugging Face checks. The broker must never become a generic authenticated
proxy merely because the upstream token has broad scope.

## Current Baseline

The repository already:

- uses Brokerkit for shared control-plane assembly;
- separates agent credentials from operator credentials and listeners;
- mounts the shared canonical operator inbox;
- implements an HF-owned bounded presenter;
- runs Brokerkit control-plane conformance tests;
- stores canonical Brokerkit grants and durable lifecycle events;
- supports durable Telegram approval over the same state machine;
- classifies Git operations and enforces append-only/provider checks;
- implements a typed Hugging Face Router inference proxy;
- owns HF grant normalization through `internal/hfgrant`;
- owns credential isolation, mirrors, reservations, settlement, and audit; and
- has no upstream credential readback API.

The work is a versioned protocol adoption and provider-plan hardening project,
not a control-plane rewrite.

## Hard Ownership Boundary

### Remains in hf-broker

- token file loading, memory handling, rotation, and upstream authorization;
- selection among configured HF credentials, if multiple credentials are later
  supported;
- Hub and Router URL construction and redirect policy;
- model, dataset, Space, collection, and bucket resource normalization;
- Git smart HTTP, LFS, and Xet behavior;
- local mirror lifecycle and ancestry/append-only checks;
- inference request schemas, streaming, limits, and response filtering;
- Storage Bucket operation semantics and snapshot safety;
- HF route classification and operation registry;
- HF policy vocabulary and safe defaults;
- canonical capability-window or single-execution plans;
- provider risk mapping, approval wording, and display facts;
- upstream ambiguity and reservation settlement;
- Hugging Face-specific audit extensions; and
- live checks against Hugging Face behavior.

### Consumed from Brokerkit

- Operator V1 wire schema and handler;
- request/grant lifecycle and revision semantics;
- decision idempotency and narrowing;
- safe presentation validation;
- operator auth separation;
- durable list/event cursors;
- common errors and no-store behavior;
- Go source/client fixtures; and
- Operator V1 conformance tests.

Brokerkit must not import HF packages or define HF operations, target kinds,
attrs, repository types, transfer protocols, token scopes, route patterns, or
plan schemas.

## Provider Adapter Shape

The broker continues to assemble one Brokerkit runtime:

```go
controlplane.New(controlplane.Options{
    Broker:          "hf-broker",
    Store:           grantStore,
    ClientSecrets:   clients,
    OperatorSecrets: operators,
    Presenter:       approval.Presenter{},
    ActivationValidator: hfplan.Validator{Store: planStore},
    Audit:           auditWriter,
})
```

`ActivationValidator` is a proposed provider-neutral fail-closed hook. The
concrete validator and plan store stay in its broker directory. It returns only
success or a safe error, never a token, plan, or upstream request to Brokerkit.
Brokerkit's single `DecisionService` must invoke it for operator HTTP, Telegram,
CLI, and every future approval channel so no transport can bypass plan checks.
The runtime's approval-channel `Decider` is an adapter over that service; this
broker must not install a second store decider beside it.

## Canonical HF Plan Model

Approval can mean either authority for a bounded class of operations or consent
to one already-materialized operation. The broker should model that distinction
explicitly rather than pretending every approval contains an exact HTTP body.

### Plan kinds

```text
capability_window
single_execution
```

`capability_window` is a canonical predicate. It may authorize, for example,
one append-only push to one repository/ref during five minutes. The eventual
Git pack is validated against that predicate at execution time.

`single_execution` binds one normalized request whose decision-relevant
content is already known, such as a narrow Hub mutation or bucket operation.
Large or streaming bodies are stored by bounded reference and digest, never
embedded in the Brokerkit grant or operator response.

### Internal plan resource

This resource is private to `hf-broker` and is not part of Brokerkit Operator
V1:

```json
{
  "schema_version": "hf-broker.io/plan/v1",
  "kind": "capability_window",
  "operation": "git.push.append",
  "target": {
    "resource_type": "dataset",
    "name": "acme/demo",
    "ref": "refs/heads/main"
  },
  "constraints": {
    "append_only": true,
    "max_uses": 1,
    "max_pack_bytes": 104857600
  },
  "credential_selector": "primary",
  "created_at": "2026-07-11T12:00:00Z"
}
```

Rules:

- `schema_version`, `kind`, `operation`, `target`, `constraints`,
  credential selector, and creation time are required.
- Objects are closed and validated before the grant becomes operator-visible.
- The plan contains no token, authorization header, cookie, signed URL, raw
  secret, or provider response.
- A credential selector names configured server-side policy; it is not a file
  path or credential value and is never public.
- The plan is immutable. Narrowing approval changes the Brokerkit grant bounds,
  not the provider operation or target.
- Reclassification creates a new request/plan instead of editing an existing
  pending plan.
- Canonical plan bytes are written atomically to a content-addressed private
  store before the grant is created. Bounded opaque grant metadata records the
  plan schema and digest. Grant creation is the visibility commit; a plan that
  was never referenced is inert and garbage-collected after a safety window.
  This avoids a cross-file cross-file atomic commit and circular grant id in the plan.
- Brokerkit request idempotency includes the plan-reference metadata, so reuse
  of one client request id with different plan content conflicts.
- A missing, corrupt, mismatched, or unsupported plan fails closed before
  approval activation and again before execution.
- SHA-256 over canonical JSON identifies the plan in private storage and
  correlates plan, grant, execution, and audit. It is not a public security
  field in Operator V1.
- Retention and deletion follow the grant lifecycle and audit policy; plan
  deletion cannot make an active grant executable without validation.

## Operation Families

The first plan registry should explicitly cover existing and intended narrow
families rather than introduce a generic HF proxy.

### Git, LFS, and Xet

- resource type: model, dataset, or Space;
- exact repository name and optional revision/ref;
- fetch, advertise, branch create/update, force-like update, ref delete, tag
  update, LFS object transfer, and Xet transfer classifications;
- append-only requirement and ancestry evidence where applicable;
- receive-pack/body limits;
- grant mode and use budget; and
- mirror snapshot/version used for preflight, with a fresh execution-time check.

Approval never bypasses malformed Git parsing, body limits, append-only rules
that policy marks non-overridable, or fail-closed ambiguity settlement.

### Router inference

- exact typed route family;
- model/repository identity;
- allowed task or provider selector;
- input/output byte and token bounds;
- streaming permission;
- timeout and concurrency class; and
- optional cost/rate guardrails owned by hf-broker.

Prompts, completions, embeddings, media bodies, and tool arguments must not be
copied into the operator inbox or common audit fields. The presenter describes
the operation using bounded safe facts.

### Hub APIs

Add only typed endpoints with explicit request/response schemas and operation
names. Candidate families include repository metadata, branch/tag management,
files/commits, repository settings, and gated-resource operations. Each route
needs:

- exact allowed method and path template;
- strict path/query/body decoding;
- allowed forwarded headers;
- response filtering;
- policy operation/target/attrs;
- grantability decision;
- plan kind and execution settlement; and
- upstream error/audit mapping.

Unknown Hub paths, methods, query fields, and bodies fail closed. There is no
catch-all `/api/hf/*` authenticated proxy.

### Storage Buckets

Bucket support remains HF-specific. The operation registry should distinguish
list/read, create, write/upload, copy/move, delete object, delete bucket,
snapshot/restore, and destructive bulk operations. Plans bind exact bucket and
object prefixes, overwrite/destructive flags, object/total byte bounds, use
budgets, and snapshot preconditions. The common protocol only sees the safe
operation label, lifecycle, bounds, and presentation.

## Broad Token Safety

A broad upstream token is acceptable only when every request passes all of
these gates:

```text
narrow registered route
  -> strict request decoding and size limits
  -> authenticated named broker client
  -> HF operation/target/attrs classification
  -> Brokerkit policy decision
  -> exact active grant and private plan validation when required
  -> fresh provider-specific safety checks
  -> server-side credential selection
  -> sanitized outbound request
  -> bounded upstream execution and response filtering
  -> fail-closed settlement and audit
```

Additional requirements:

- default-deny policy for every new route and operation;
- no forwarding of client Authorization, Cookie, proxy, or hop-by-hop headers;
- redirects disabled or revalidated against an HF allowlist without credential
  forwarding across origins;
- DNS/connect protections against SSRF for any provider-returned URL;
- upstream token never written to plan, grant, lifecycle event, presentation,
  error, test fixture, trace, or audit;
- separate credentials may be selected by server configuration, but clients
  cannot name a raw token or arbitrary credential id;
- doctor checks verify token access without printing token metadata that could
  expand client authority; and
- policy remains narrower than token scope and is the primary broker gate.

## Operator Presentation

The existing presenter should evolve to the V1 safe fields:

- `title`: direct HF wording for the operation;
- `summary`: consequence and important invariant in plain text;
- `facts`: resource type, exact repository/bucket/model, ref or object prefix,
  approval mode, append-only/destructive status, requested duration, and use
  count when relevant; and
- `risk`: conservative common level derived by an explicit HF operation table,
  not substring matching.

Replace substring-based risk heuristics with a complete operation-to-risk map
registered beside the operation. Unknown registered operations use `unknown`
and fail a presenter coverage test until deliberately classified.

Presentation must never include:

- tokens or token-derived authorization metadata;
- raw prompts, completions, tool arguments, Git packs, LFS/Xet payloads, object
  contents, private file paths, or provider responses;
- arbitrary Markdown/HTML/URLs;
- a browser action; or
- a plan that the browser can edit and return.

Presenter failure returns the Brokerkit fallback while keeping the request
visible. Sensitive operations may additionally make presentation availability
an HF-owned approval precondition, but that must be explicit and tested rather
than inferred by Brokerkit.

When internal ambiguous execution retains a reservation and makes an apparently
active grant unusable, the presenter adds a bounded `Needs attention` fact such
as `Execution result is ambiguous; authority is closed`. Reservation counters
and internal settlement event kinds remain off the V1 wire.

## V1 Mapping From Current Types

| Current field | V1 projection | V1 rule |
| --- | --- | --- |
| `Client` | `requester` | Safe bounded label only. |
| `Operation` | `operation` | Preserve HF-owned opaque value. |
| `Duration` | `requested_duration_seconds` | Positive whole seconds on wire; keep HF whole-minute input rule where desired. |
| `MaxUses` | `requested_max_uses` | Preserve positive requested count. |
| narrowed `MaxUses` | `granted_max_uses` | Store separately at approval; never overwrite the original requested count. |
| `ReservedCount` | omitted | Keep private in execution settlement. |
| `Reason` | `request_reason` | Sanitize and bound before projection. |
| `Presentation.Fields` | `presentation.facts` | Keep bounded inert label/value entries. |
| `Presentation.Target` | title/facts | Fold the current required target into an explicit `Repository`, `Model`, `Bucket`, or other fact; V1 has no separate target slot. |
| `Presentation.PlanHash` | omitted | Retain internal canonical plan digest/audit correlation. |
| status-derived behavior | `allowed_actions` | Compute from authoritative grant revision and HF preconditions. |
| requested limits | `approval_bounds` | Compute the maximum operator may choose at this revision. |

The V1 projection is a wire adapter over the same durable grant. No duplicate
V1 store is introduced.

## Errors And Rate Limits

Map HF behavior into stable common categories without losing provider detail in
private audit:

| HF condition | Common result |
| --- | --- |
| malformed typed request | `invalid_request` |
| unknown/unregistered HF route | `not_found` or fail-closed agent denial; never proxy |
| policy denial | `forbidden` |
| stale operator decision | `revision_conflict` |
| invalid/narrowing overflow | `constraint_exceeded` |
| HF 401/403 from server credential | `temporarily_unavailable` to agent/operator plus urgent internal diagnostic; never expose token metadata |
| HF 404 | operation-specific safe `not_found` |
| HF 429 | `rate_limited` with bounded `Retry-After` |
| timeout/5xx | `temporarily_unavailable` when safe to retry |
| ambiguous write result | fail-closed retained settlement; safe common error |
| corrupt/missing canonical plan | `internal_error`, no execution, security audit event |

Do not relay raw HF response bodies or headers through common errors.

## Testing Strategy

### Common conformance

Run Brokerkit Operator V1 conformance against the real HF operator handler.
Include agent/operator credential separation, route isolation, strict unknown
input rejection plus tolerant/drop-only unknown response handling,
revision conflicts, decision idempotency, narrowing, live pagination plus the
first-page event-cursor handoff, SSE recovery,
presentation fallback, no-store headers, restarts, and leak fixtures.

### HF plan tests

- round-trip every plan kind and operation family;
- reject unknown fields, versions, operations, target types, and constraints;
- prove grants cannot reference another plan or change plan target;
- prove grant narrowing cannot widen plan scope;
- prove missing/corrupt plan blocks activation and execution;
- prove HTTP revision-bound and Telegram token-bound approval use the same
  Brokerkit decision service and activation validator;
- prove plans and digests contain no token or raw sensitive body;
- crash before plan write, after plan write/before grant creation, and after
  grant creation; recover or garbage-collect fail closed;
- verify internal digest stability with canonical fixtures;
- verify retention cannot leave executable orphan authority; and
- fuzz plan decoding and canonicalization.

### Provider behavior tests

- fake HF Hub/Router/Git/LFS/Xet/Bucket upstreams by default;
- header, redirect, DNS, timeout, retry, streaming, and body-limit tests;
- append-only, ancestry, ref, repo-type, overwrite, deletion, and snapshot
  invariants;
- policy deny overriding active grant;
- ambiguous upstream result retaining/closing approved use;
- exact audit redaction;
- explicit risk/presenter coverage for every operation;
- presenter fallback preserves actions/bounds, and ambiguous settlement gets a
  safe `Needs attention` fact; and
- broad-token tests proving an unregistered route remains unreachable.

### Live milestone probes

Use a dedicated test namespace and disposable resources. Verify read, request,
approval, execution, denial, expiry, revoke, restart, Router streaming, Git
write, and bucket flows as supported. Record only safe ids/timings. Clean up
resources and do not run live probes in default CI.

## Implementation Order For The Single Cutover

These are dependency-ordered commits in the one monorepo branch. None is a
supported deployment until the complete cutover passes:

1. inventory current HF routes, operation/target/attr vocabulary, grants,
   presenter output, state files, and every place an upstream request executes;
2. define deterministic canonical HF plans and content-addressed plan storage,
   then bind every pending grant to one immutable plan before visibility;
3. add the HF activation validator to BrokerKit's one decision service and make
   every HTTP/channel decision path use it;
4. mount only Operator V1 discovery/list/watch/decision routes and delete the
   unversioned operator handler and duplicate decision path;
5. harden broad-token containment across Git/LFS/Xet, Router, narrow Hub
   operations, and Storage Buckets without adding a generic proxy;
6. add V1 conformance, plan mutation, ambiguity, restart, rate-limit, cursor,
   presenter, secret-canary, and provider behavior tests;
7. integrate the source with the OpenClaw plugin using only the common
   presentation and decision contract;
8. run disposable live HF probes for every shipped operation family, revoke or
   expire all old authority, initialize fresh state, and include HF only in the
   complete coordinated release.

If any check fails, the cutover does not expose the new HF listener. Do not add
an adapter, dual route, dual state, or old-format reader to continue.

## Clean Cutover Rules

- Read only the new V1 config, grant, plan, event, cursor, and idempotency
  shapes.
- Mount only the V1 operator contract.
- Do not import old state or preserve active grants across cutover.
- Do not run old/new HF binaries against each other's state.
- Archive old state and audit files for forensic retention only.
- Preserve no generic proxy or broad-token escape hatch.
- The first supported HF deployment is the complete monorepo release.

## Acceptance Criteria

The HF adoption is complete when:

- the broker passes Brokerkit Operator V1 conformance;
- the trusted host registers it through the same interface as GH;
- the common UI has no HF-specific decision branch;
- every requestable HF action has a closed provider-owned plan or predicate;
- broad tokens remain unreachable outside registered, classified, policy-gated
  routes;
- approval never changes provider operation, target, or request content;
- provider safety checks still run at execution time;
- token, prompts, content, packs, plans, and raw responses never cross the
  common operator/browser boundary;
- retries, ambiguity, restart, cursor expiry, and cutover failure handling is fail closed; and
- HF-specific behavior can evolve without changing Brokerkit unless a proven
  provider-neutral concept is deliberately standardized.
