# Provider-Neutral MCP Execution Implementation Plan

Date: 2026-07-18

Status: implemented; release and live deployment validation pending

## Objective

Replace the separate Hugging Face and GitHub MCP implementations with one
provider-neutral BrokerKit MCP runtime. Every advertised operation tool must
either perform the declared operation through BrokerKit or return an explicit,
usable protocol-access result for an action that necessarily continues over a
native data plane such as Git.

This is one hard cutover. Do not retain the current HF window-tool behavior,
parallel MCP implementations, compatibility aliases, dual tool schemas,
fallback grant dispatch, old tool descriptions, or mixed old/new tests.

The official Hugging Face and GitHub MCP servers are not execution
dependencies. BrokerKit continues to own policy, approval, audit, durable
operations, credential isolation, and provider execution.

## Confirmed Defect

HF catalog tools with `authorization_mode: window` currently call the grant
endpoint directly. The default policy allows safe reads, discovery, and
inference without approval, so the grant endpoint correctly returns
`not_requestable`. The MCP tool then fails without performing the operation.

The defect affects the whole HF window-mode MCP class, not only repository
reads:

- 93 advertised operations default to `allow` and fail by requesting an
  unnecessary grant;
- 24 advertised operations default to `request` and can return a grant, but do
  not perform the operation their tool name claims to run; and
- the normal model-inference router works only because it bypasses the MCP
  dispatch path.

`hf_repo_list` has an additional semantic defect. Its HTTP implementation
derives rows from exact policy targets instead of querying Hugging Face. The
default wildcard policy therefore returns no repositories and cannot discover
private repositories that the broker credential and policy permit.

GitHub already sends MCP application tools through Agent Operations V1, but it
maintains a separate JSON-RPC server, tool dispatcher, submission preparation,
sealed-payload handling, stream handling, lifecycle utilities, and result
formatting. The duplicated paths can drift again unless the shared contract is
enforced in code and conformance tests.

## Superseded Contract

This plan supersedes the statements in `docs/OPERATIONS_RUNTIME.md` and
`docs/2026-07-14-agent-tool-compatibility-plan.md` that window-mode MCP
tools remain direct grant tools outside Agent Operations.

After the cutover:

- ordinary provider operation tools always enter Agent Operations V1;
- authorization mode controls policy and grant semantics only;
- authorization mode never selects the MCP dispatch mechanism;
- explicit grant lifecycle tools remain available for callers that
  intentionally request a capability without submitting an operation; and
- native-protocol access is represented explicitly instead of pretending that
  a grant response is the completed provider action.

Update the superseded long-term documentation as part of implementation. Do
not leave contradictory live documentation after merge.

## Design Principles

- Authorization and execution are separate concerns.
- MCP, CLI, and HTTP are projections over the same provider operation catalog.
- An advertised tool must have a registered runtime implementation.
- Safe bounded reads execute synchronously when policy allows them.
- Approval-required and mutating work remains durable and resumable.
- Approval resumes the original operation; it does not require the agent to
  reconstruct or resubmit the dangerous request.
- Native Git, LFS, inference, and object streams remain dedicated data planes.
- Provider credentials never enter MCP arguments, results, logs, plans, or
  conversation history.
- Shared packages contain no Hugging Face, GitHub, sudo, OpenClaw, or MLClaw
  branches.
- Provider packages retain provider schemas, target normalization, API calls,
  result projection, and approval presentation.
- Unsupported operations are not advertised.
- Request replay is idempotent, and approved execution occurs at most once.

## Target Architecture

```text
OpenClaw or another MCP host
        |
        v
brokerkit/mcpserver
        |
        v
brokerkit/agentmcp
        |
        v
Agent Operations V1
        |
        +-- allow ----------> provider executor ----------> result
        |
        +-- active grant ---> reserve use -> executor ----> result
        |
        +-- request --------> pending approval
        |                         |
        |                         v
        |                    approved -> executor --------> result
        |
        +-- deny -----------> refusal; no upstream call
```

The logical path is shared. The physical data plane remains appropriate to the
operation: bounded JSON, durable execution, stream references, or scoped
native-protocol access.

## Package Boundaries

### `mcpserver`

Add a small provider-neutral package that owns MCP protocol mechanics only:

- JSON-RPC 2.0 request and response envelopes;
- bounded line-oriented stdio transport;
- `initialize`, `ping`, `tools/list`, `tools/call`, `resources/list`, and
  `resources/read` dispatch;
- tool-list change notifications;
- strict request decoding and stable MCP errors;
- tool result and structured-content envelopes; and
- deterministic server metadata.

`mcpserver` must not import Agent V1, policy, grants, provider catalogs, sealed
stores, or provider packages. It receives registered tool and resource
handlers through concrete configuration and small function values. Avoid a
large provider interface or a generic dependency-injection framework.

### `agentmcp`

Add a provider-neutral Agent Operations bridge that composes `mcpserver` with
the existing `capability`, `agentclient`, `agentv1`, and `mcpoperation`
packages. It owns:

- catalog-to-MCP tool registration;
- selected-tool lookup and exposure filtering;
- closed input-envelope validation;
- transcript-safe `request_id` resolution;
- operation submission;
- get, wait, list, and cancel utility tools;
- structured request-ID conflict recovery;
- operation and page projection hooks; and
- stable handling of immediate, pending, and terminal operation results.

`agentmcp` submits every ordinary provider tool through Agent Operations V1.
It must not inspect authorization mode to choose a grant endpoint.

Provider configuration supplies only:

- provider and server names;
- the selected capability descriptors;
- provider-owned target and argument schemas;
- canonical input projection;
- transcript-safe output projection;
- optional MCP resources; and
- provider-specific tool descriptions.

### `agentclient`

Extend the existing provider-neutral client instead of retaining separate HF
and GitHub upload implementations. Add bounded methods for:

- sealed-payload upload;
- stream upload;
- stream download; and
- any shared request construction needed by those methods.

The client owns endpoint parsing, bearer authentication, response bounds,
strict response decoding, and secret-redacted errors. Providers own only the
decision to use a sealed payload or stream and the provider-specific public
argument shape.

### Provider packages

HF and GitHub retain:

- operation catalogs and generated bindings;
- target and argument schemas;
- canonical field projections;
- executor registries;
- provider API clients and native transports;
- policy classification details;
- result projection;
- approval presentation; and
- provider-specific resources.

Do not move Hugging Face or GitHub API behavior into shared MCP packages.

## Catalog And Runtime Contract

### Authorization is not dispatch

Keep authorization mode as policy data:

- `window` permits reusable, bounded grants where the operation supports them;
- `execution` permits one-use execution approval; and
- explicit-only, sealed, internal, and risk metadata retain their existing
  security meaning.

Remove every MCP branch that interprets `window` as "call `/api/grants` and
return". Agent Operations and the provider runtime decide whether an operation
is direct, uses an active grant, creates a pending approval, or is denied.

### Runtime implementation binding

Add an explicit, validated runtime binding for every advertised operation.
The binding identifies one of these execution shapes:

- `inline`: bounded request and bounded JSON result;
- `stream`: bounded public metadata plus a BrokerKit stream reference;
- `credential`: generated secret material written only to an approved
  credential slot; or
- `protocol_access`: a scoped connection result for a native data plane.

Do not infer execution shape from risk, authorization mode, operation name,
HTTP method, or disposition flags.

Catalog validation and startup validation must reject:

- an advertised operation without a runtime binding;
- a binding whose input or result schema is missing;
- credential output without a credential slot contract;
- sealed input without a sealed-payload contract;
- stream input or output without declared bounds; and
- protocol access without a scoped target, expiry, and use budget.

The MCP tool set is the intersection of:

1. agent-facing catalog operations;
2. client exposure configuration;
3. policy-recognized operations; and
4. registered runtime implementations.

No placeholder or protocol-only catalog entry may appear as a runnable tool.

## Operation Behavior

### Direct allow

When static policy allows an operation, Agent Operations executes it
immediately. The broker must not create a grant, send an approval notification,
or write a pending approval record.

### Approval required

When policy marks an operation requestable:

1. persist the canonical operation and immutable plan;
2. persist and notify one approval request;
3. return the pending operation immediately;
4. resume the same operation after approval;
5. reserve the approved grant use before upstream execution;
6. execute exactly once; and
7. commit the terminal result or bounded error.

An active matching window grant may authorize a later operation submission,
subject to expiry and atomic use reservation. The agent never needs to call a
grant tool before calling the actual operation tool.

### Deny

A denied operation returns a stable bounded refusal. It must not create a
grant, allocate a stream, upload a sealed payload, contact the provider, or
reveal whether an inaccessible private resource exists.

### Native protocol access

Git, LFS, and similar protocols cannot be represented honestly as one bounded
JSON response. Their provider runtime returns a closed protocol-access result
containing only:

- broker-owned endpoint information;
- the exact approved operation and target;
- expiry and remaining-use information;
- bounded non-secret client instructions; and
- an opaque access handle when needed.

The result must not contain the upstream credential. Tool names and
descriptions must say that they authorize or prepare protocol access; they
must not claim that a fetch, push, or transfer has already completed.

Protocol traffic remains policy-enforced at the broker data plane. Approval of
a control-plane operation does not create an unbounded generic proxy.

## Hugging Face Replacement

### MCP submission

- Route all HF catalog tools through `agentmcp`.
- Delete `callMCPWindowOperation`, window-only MCP input validation, and
  automatic grant requests from ordinary operation tools.
- Keep explicitly named HF grant lifecycle tools only for deliberate grant
  management.
- Use the shared Agent V1 lifecycle utilities and result envelopes.
- Use the shared sealed-payload and stream client.

### Runtime adapters

Provide real runtime bindings for every HF operation that remains advertised.
Group implementation by provider transport, not by MCP tool:

- Hub repositories, revisions, files, collections, discussions, webhooks, and
  user or organization metadata;
- Buckets and bounded object transfer;
- Jobs, scheduled jobs, and sandboxes;
- Spaces, endpoints, logs, metrics, variables, and secrets;
- inference router operations;
- Git, LFS, and repository snapshots; and
- credential-output operations.

Reuse shared bounded HTTP and stream primitives. Do not shell out to the
official HF MCP server and do not expose the upstream HF token to the local MCP
subprocess.

### Repository discovery

Replace policy-derived `repo.list` rows with an authenticated upstream listing
through the broker credential. Filter every result through policy before
returning it.

Rules:

- wildcard policy may disclose matching upstream repositories;
- exact policy discloses only exact matching repositories;
- private visibility is not returned unless requested by the result schema;
- pagination remains bounded and opaque;
- filtering occurs before result projection;
- denied repositories are indistinguishable from absent repositories; and
- repository content still requires its own operation authorization.

The private-repository regression fixture must prove that an allowed private
repo can be listed and read without an approval request.

## GitHub Replacement

- Replace the GitHub-local JSON-RPC loop with `mcpserver`.
- Replace GitHub-local submission and lifecycle dispatch with `agentmcp`.
- Move sealed-payload and stream transport into `agentclient`.
- Preserve GitHub exposure profiles and dynamic tool-change notifications
  through provider-neutral selectors and hooks.
- Preserve GitHub MCP resources as provider-owned resource registrations.
- Keep GitHub REST, GraphQL, Git, GitHub App authentication, and projections in
  the GitHub broker.
- Require the same executor-binding validation used by HF.
- Delete the superseded GitHub MCP transport and utility implementations after
  parity tests pass.

The GitHub migration must be behavior-preserving except where the shared
contract identifies an existing defect. Do not add the official GitHub MCP
server as an agent-visible bypass or as a required runtime dependency.

## Shared Conformance Suite

Add a provider-neutral suite that every MCP-enabled broker must pass.

### Protocol conformance

- malformed JSON and duplicate keys fail closed;
- notifications without IDs receive no response;
- unknown methods and tools return stable MCP errors;
- line, argument, result, and resource sizes are bounded;
- tool-list changes emit one correct notification;
- structured content and text content agree; and
- no panic or process exit follows malformed caller input.

### Authorization and execution matrix

For each execution shape, test:

| Policy result | Required behavior                                      |
| ------------- | ------------------------------------------------------ |
| allow         | execute once, return result, create no approval        |
| active grant  | reserve one use, execute once, return result           |
| request       | persist pending operation, execute once after approval |
| deny          | return refusal, make no upstream call                  |

Run the matrix for inline, stream, credential, and protocol-access adapters.

### Lifecycle conformance

- omitted request IDs are generated securely;
- identical retries return the same operation;
- conflicting retries return `request_id_conflict`;
- get, wait, list, and cancel are client-scoped;
- a restart between approval and execution resumes safely;
- canceled or denied operations never execute;
- execution reservation survives concurrent workers; and
- terminal results are immutable.

### Security conformance

- upstream credentials never appear in MCP traffic or audit records;
- sealed values appear only in the sealed store and trusted executor input;
- credential output appears only in its approved slot;
- provider errors are bounded and redacted;
- caller-controlled URLs cannot create an arbitrary HTTP proxy;
- caller-controlled paths cannot escape declared stream or workspace bounds;
- policy filtering happens before private-resource projection; and
- expired protocol access fails closed.

### Catalog conformance

Generate tests over every advertised operation:

- descriptor, schema, projection, and runtime binding exist;
- tool names are unique after provider prefixing;
- tool descriptions match actual behavior;
- authorization mode does not choose MCP dispatch;
- result shape matches execution shape; and
- internal or denied non-agent operations are not advertised.

## Provider End-To-End Tests

### Hugging Face

- list and read an allowed private repository through MCP without approval;
- verify a denied private repository is not disclosed;
- approve one requestable mutation and observe one upstream mutation;
- deny the same class and observe no upstream mutation;
- resume an approved operation after MCP and broker restart;
- read Space logs and bucket metadata through real executors;
- exercise one bounded stream result;
- exercise one scoped Git protocol-access result; and
- verify inference MCP and the existing `/v1` router use the same policy
  semantics without sharing transport code.

### GitHub

- read an allowed private repository through MCP without approval;
- create or update one approved resource and observe one upstream mutation;
- deny one mutation and observe no upstream call;
- resume after process restart;
- upload one sealed input without transcript exposure;
- upload and retrieve one bounded stream; and
- verify exposure-profile changes update the advertised tool set.

### OpenClaw and MLClaw

- run each broker as its packaged stdio MCP subprocess;
- confirm the advertised tool schemas survive OpenClaw redaction;
- invoke an HF private-repository read from a real agent session;
- approve one operation in the embedded BrokerKit popover;
- verify the original operation reaches its terminal result without agent
  reconstruction; and
- confirm no direct provider credential is present in agent configuration or
  session history.

Use disposable provider fixtures. Do not mutate personal repositories,
credentials, or long-lived conversations during automated tests.

## Implementation Sequence

1. Freeze cross-provider behavioral fixtures for the current GitHub operation
   path and the confirmed HF failure.
2. Add `mcpserver` with protocol conformance tests.
3. Add `agentmcp` by extracting the working GitHub submission and lifecycle
   behavior.
4. Extend `agentclient` with shared sealed-payload and stream transport.
5. Migrate GitHub to the shared packages and delete its duplicated MCP shell.
6. Add runtime-binding metadata and startup/catalog validation.
7. Migrate HF ordinary tools to `agentmcp` and delete direct window grant
   dispatch.
8. Implement or bind HF executors for every advertised tool family.
9. Replace HF policy-derived repository listing with upstream discovery plus
   policy filtering.
10. Make native protocol-access tools explicit and remove misleading tool
    names or descriptions.
11. Run generated catalog, provider, restart, concurrency, security, and live
    packaged-MCP tests.
12. Update all long-term architecture, runtime, provider README, and generated
    capability documentation.
13. Update MLClaw to the immutable BrokerKit commit, deploy the test agent, and
    run the OpenClaw approval and private-repository smoke tests.
14. Release and install only after BrokerKit and MLClaw CI are green.

Use coherent conventional commits. Because this is a hard cutover, do not
merge an intermediate state that advertises tools without executors or keeps
both dispatch paths active.

## Deletions Required

The implementation is incomplete until it removes:

- HF automatic MCP window-to-grant dispatch;
- HF window-only ordinary-tool input types and validators;
- duplicated HF and GitHub JSON-RPC envelopes and stdio loops;
- duplicated operation get, wait, list, cancel, and result formatting;
- duplicated sealed-payload and stream HTTP clients;
- policy-derived HF repository discovery;
- misleading "Run operation" descriptions for capability-only tools;
- runtime branches that infer execution from authorization mode; and
- superseded documentation and tests asserting the old behavior.

Do not retain dead helpers, compatibility wrappers, aliases, or fallback
readers after the new conformance suite passes.

## Documentation Deliverables

Update at least:

- `docs/ARCHITECTURE.md`;
- `docs/OPERATIONS_RUNTIME.md`;
- `docs/UNIFIED_BROKER_CONTRACT.md`;
- `docs/POLICY_CORE.md` where authorization semantics need clarification;
- `brokers/huggingface/README.md` and its policy/specification docs;
- `brokers/github/README.md` and operation docs;
- generated capability and MCP compatibility artifacts; and
- MLClaw's BrokerKit integration and operator-flow documentation.

Mark this plan complete only after the released packages and live MLClaw test
deployment satisfy the acceptance criteria.

## Acceptance Criteria

The cutover is complete only when:

1. HF and GitHub use the same `mcpserver` and `agentmcp` implementations.
2. No ordinary MCP operation tool calls a grant endpoint directly.
3. Every advertised operation has a validated runtime binding.
4. Allowed HF private-repository list and read operations return real upstream
   results without approval.
5. Approval-required tools execute the original operation exactly once after
   approval.
6. Denied operations make no provider request and disclose no private-resource
   existence.
7. Native protocol tools return honest scoped access results and enforce them
   at the broker data plane.
8. GitHub behavior remains green under the shared runtime.
9. Provider credentials never enter MCP traffic, operation results, logs, or
   conversation state.
10. Unit, race, integration, cross-provider conformance, packaged-install,
    OpenClaw, Slophammer, vulnerability, and secret-scanning gates pass.
11. BrokerKit and MLClaw CI are green on immutable commits.
12. A live MLClaw test deployment proves private HF read and approved mutation
    behavior end to end.
13. Old dispatch code, duplicated MCP infrastructure, and superseded live
    documentation are removed.
