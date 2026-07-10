# Credential Firewall And Operator Inbox Plan

Date: 2026-07-10

Status: operator inbox and Router inference implemented; typed Hub routes pending

## Motivation

An agent often needs broad day-to-day access to Hugging Face:

- call Inference Providers;
- discover and download public or private resources;
- clone, fetch, and update repositories;
- upload datasets and model artifacts;
- maintain buckets and automated pipelines.

Giving the agent a normal write-capable Hugging Face token also gives it the
ability to perform irreversible or account-wide operations. Prompt injection,
model mistakes, or compromised tools can then delete data, rewrite history,
change visibility, alter secrets, purchase hardware, or damage unrelated
resources.

The real security objective is not to restrict ordinary inference. It is to
keep the real Hugging Face credential outside the agent while enforcing what
that credential may do on every request.

`hf-broker` should become a general Hugging Face credential firewall that can
be embedded into agent distributions, local automation hosts, remote coding
environments, hosted applications, and other control planes. It must remain
useful without ML Claw, Telegram, or any particular frontend.

## Goal

An untrusted client receives only a revocable broker client secret. The broker
holds the real Hugging Face token and provides:

- unrestricted authenticated Router inference;
- explicitly classified read-only Hub access;
- append-only and otherwise reversible writes where policy allows;
- typed approval requests for exceptional operations;
- a durable operator inbox consumable by browser UIs, CLIs, or other trusted
  applications;
- complete secret-safe auditing;
- isolation checks for same-host deployment.

The broker must never expose a generic authenticated Hub proxy.

## Existing Refactor Baseline

This plan builds on pull request
[#19](https://github.com/osolmaz/hf-broker/pull/19). That change already cuts
Telegram transport and durable notification behavior over to Brokerkit commit
`5d682c4`, requires idempotent grant request IDs, and makes callback decisions
restart-safe. The operator inbox must reuse that exact grant store and
notification lifecycle.

Do not create another approval model, copy the Telegram state machine, or
replace the callback durability work from pull request #19. Merge or rebase
that work before implementing the inbox-facing changes.

## Intended Integrations

The design should support:

- OpenAI-compatible agent runtimes that can set a custom API base URL;
- Git clients using smart HTTP;
- Hugging Face CLI and libraries through explicitly supported broker routes or
  broker-aware adapters;
- browser-based operator consoles;
- terminal and desktop approval clients;
- same-host deployments with separate Unix users;
- separate-host deployments over a private network.

No integration should need to know or receive the upstream Hugging Face token.

## Architecture

```text
untrusted client
    |
    | broker client secret
    v
agent-facing listener
    |
    | authenticate -> classify -> policy -> grant -> execute -> audit
    v
hf-broker -------------------------------- real HF token ---> Hugging Face
    ^
    | operator-only transport
    |
trusted operator application
```

Use Brokerkit for provider-neutral auth, policy, grants, operator inbox,
decisions, events, audit primitives, HTTP safety, and durable storage. Keep all
Hugging Face request classification, upstream routing, token use, Git/LFS/Xet
behavior, mirrors, resource terminology, and operator presentation in
`hf-broker`.

## Credential Boundary

Production deployment should prefer:

```text
HF_BROKER_HF_TOKEN_FILE=/run/hf-broker/hf-token
```

Requirements:

- token file owned by the broker user, mode `0600`;
- broker process runs under a different UID from every untrusted client;
- broker process environment contains the token-file path, not the token;
- client receives only its named broker secret;
- operator credential is separate from all client secrets;
- binaries, configuration, policy, state, and runtime files have verified ownership
  and modes;
- diagnostics never report token values or token metadata;
- `hf-broker doctor` fails closed when the isolation boundary is unsafe or
  inconclusive.

Raw token environment variables may remain for development, but setup and
embedding documentation should use token files.

## Agent-Facing Surfaces

Every route except health requires named-client authentication. Unknown paths,
methods, operations, targets, and attributes fail closed.

### Router Inference

Add OpenAI-compatible routes:

```text
GET  /v1/models
POST /v1/chat/completions
```

Inference is allowed without human approval. The broker should:

- validate method and content type;
- enforce small metadata and bounded request-body limits;
- require a syntactically valid model ID;
- support streaming and non-streaming responses;
- preserve standard OpenAI-compatible status and event semantics where safe;
- replace downstream authorization with the upstream HF token;
- strip hop-by-hop, credential, cookie, internal routing, and unsafe response
  headers;
- apply explicit connect, header, idle, and total timeouts;
- cancel the upstream request when the client disconnects;
- audit model, provider suffix, status, duration, and safe usage totals;
- never audit prompts, tool arguments, generated content, images, or token
  material by default.

The first implementation may support only chat completions and model listing.
Other inference endpoints require explicit typed additions later.

### Read-Only Hub Access

Add explicitly classified read operations required by common Hugging Face
workflows. Candidate categories include:

- model, dataset, and Space metadata reads;
- file trees, file metadata, and download resolution;
- discussion and pull-request reads;
- bucket listing, object metadata, and object download;
- authenticated private-resource discovery.

Do not implement this as `GET anything on huggingface.co`. Each route family
must define:

- accepted path shape;
- allowed query fields;
- target extraction;
- response and body limits;
- redirect policy;
- credential and cookie stripping;
- audit-safe metadata.

Private reads remain an exfiltration risk. Scope policy should be able to
restrict readable resources by owner, resource kind, and ID even when a host
application chooses broad read access.

### Git, LFS, And Xet

Keep the existing Git smart-HTTP behavior and cut its generic control-plane
logic over to Brokerkit.

- fetch and clone are read operations;
- fast-forward branch updates are allowed in append-only mode;
- new branches and tags are allowed when policy permits;
- force-push, ref deletion, and tag movement are refused or approval-gated;
- ancestry remains verified against the commits-only mirror;
- LFS/Xet transfers remain scoped and additive;
- request and pack contents never enter logs or approval projections.

### Typed Hub Writes

Add write capabilities only as typed operations with explicit reversible or
approval behavior. Candidate operations include:

- create a commit or pull request;
- upload a new file or object;
- update an existing file through a recoverable commit;
- append a new bucket object;
- overwrite a bucket object only after broker-controlled snapshot.

Never expose an arbitrary method/path/body forwarding endpoint.

Standing policy must continue to deny:

- repository, dataset, model, Space, or bucket deletion;
- force-push and history replacement;
- branch or tag deletion and tag movement;
- credential, secret, webhook, member, permission, or role changes;
- visibility, repository settings, and resource administration changes;
- namespace transfer or ownership changes;
- billing, paid hardware, quota, and storage-tier changes;
- arbitrary Space variables that may contain credentials;
- any operation the broker cannot classify completely.

Selected denied operations may become typed approval requests when the scope
file explicitly enables their grant policy. Permanently forbidden operations
remain ungrantable.

## Operator Inbox

Consume Brokerkit's provider-neutral operator-inbox implementation and expose
it only on a trusted operator transport.

Use the established grant routes rather than an HF-specific protocol:

```text
GET  /api/grants
GET  /api/grants/{id}
GET  /api/grants/events
POST /api/grants/{id}/approve
POST /api/grants/{id}/deny
POST /api/grants/{id}/cancel
POST /api/grants/{id}/revoke
```

The current agent-facing create/list/get routes remain client-scoped. The
operator transport uses separate authentication and may list requests across
clients and perform decisions.

Required capabilities:

```text
list pending requests
list request history
read one request
stream lifecycle events
approve
deny
cancel
revoke
```

`hf-broker` supplies the Hugging Face presentation for each request:

- action name;
- resource type and ID;
- exact branch, tag, file, object, or prefix;
- before and after values;
- risk label;
- requested duration and use budget;
- provider-specific policy explanation;
- canonical plan hash for execution grants.

Approval always applies to the canonical durable request. An operator client
cannot replace the action, resource, attrs, or execution plan.

The operator transport uses an independently authenticated HTTP listener bound
to loopback by default. A separate-host deployment may expose it only through a
private network boundary. The agent-facing client secret must never
authenticate to the operator inbox.

Telegram becomes an optional notification adapter, not a requirement for
creating or deciding requests. A broker can run entirely through its operator
inbox.

## Client Experience

Do not require a custom client where an existing protocol already works.

### Inference Clients

OpenAI-compatible clients set:

```text
base URL = http://broker-host:port/v1
API key  = broker client secret
```

No inference SDK specific to `hf-broker` is needed.

### Git Clients

Git uses the broker URL as its remote and the broker client secret as the
password. Existing smart-HTTP behavior remains compatible.

### Hub Tools

For route families that can preserve Hugging Face API semantics, document the
supported endpoint override for `hf` CLI and libraries. Where upstream clients
cannot target only the supported broker surface safely, provide a small
broker-aware adapter or command rather than pretending the generic Hub API is
available.

### Operator Applications

Operator applications consume the Brokerkit operator-inbox HTTP surface.
Provide JSON/SSE examples and conformance fixtures. Do not publish a dedicated
multi-language SDK; host applications can maintain thin internal clients.

### Setup Output

Extend client setup to generate a secret-safe config file containing only:

```text
HF_BROKER_URL
HF_BROKER_SHARED_SECRET
```

Optional helper output may show standard base-URL and Git remote configuration.
It must never copy the upstream token into a client file.

## Policy Vocabulary

Register Hugging Face operations and targets in Brokerkit. The exact names are
owned here and should be action-oriented.

Candidate operations:

```text
inference.models.list
inference.chat.complete
repo.metadata.read
repo.contents.read
repo.git.fetch
repo.git.push.fast_forward
repo.git.push.force
repo.ref.create
repo.ref.delete
repo.tag.move
repo.commit.create
repo.pull_request.create
bucket.objects.list
bucket.object.read
bucket.object.create
bucket.object.overwrite
bucket.object.delete
```

Candidate targets:

```text
account
organization
model
dataset
space
bucket
repo_ref
repo_path
bucket_object
inference_model
```

Request classifiers extract canonical targets and attrs before policy
evaluation. Policy never receives arbitrary URLs as targets.

## Execution Plans

Operations that can be executed exactly by the broker use execution grants.
The broker reads current upstream state and builds a canonical plan containing:

- operation;
- target;
- safe before state;
- exact after state;
- provider preconditions;
- expiry;
- plan hash.

After approval, the broker re-reads upstream state. If preconditions differ,
execution is refused and a new request is required. Plans are single-use.

Git history changes that cannot be represented as a broker-executed body may
continue to use narrowly scoped window grants with exact refs, short duration,
and bounded uses.

## Process And Transport Isolation

Same-host deployment is supported only when the broker runs under a distinct
non-root user and `hf-broker doctor` proves the boundary.

The doctor must check:

- agent and broker UID separation;
- root-equivalent agent groups;
- token, policy, state, binary, directory, and credential ownership and modes;
- agent ability to read or modify the token file;
- agent ability to read broker process environment;
- agent ability to authenticate to the operator listener;
- accidental exposure of operator routes on the agent listener;
- client/operator secret reuse;
- broker health and upstream reachability without printing token metadata.

Separate-host deployment remains supported and stronger, but it is not
required by this plan.

## Configuration

Retain file-first secret configuration and add explicit listener settings:

```text
HF_BROKER_HF_TOKEN_FILE
HF_BROKER_SECRETS_FILE
HF_BROKER_SCOPE_FILE
HF_BROKER_STATE_DIR
HF_BROKER_BIND_ADDR
HF_BROKER_PORT
HF_BROKER_OPERATOR_SECRETS_FILE
HF_BROKER_OPERATOR_BIND_ADDR
HF_BROKER_OPERATOR_PORT
HF_BROKER_UPSTREAM_HUB_URL
HF_BROKER_UPSTREAM_ROUTER_URL
```

Unknown configuration fields and invalid combinations fail startup. Operator
and client secrets must be distinct. Configuration errors name fields, never
values.

The implemented operator transport is a dedicated HTTP listener so local and
private-network trusted hosts can use the same contract. Setup binds it to
`127.0.0.1:8081` by default. It is never multiplexed onto the agent listener.

## Audit And Observability

Audit every classified request and operator transition with safe metadata:

- time;
- client or approver;
- operation;
- canonical target;
- policy decision and matched rule IDs;
- grant ID;
- status and duration;
- upstream status class;
- safe inference usage totals when available;
- error code.

Never log or audit:

- upstream or broker credentials;
- token metadata;
- prompts, completions, tool arguments, images, or embeddings;
- private resource contents;
- HTTP request bodies or raw upstream responses;
- Git packs or uploaded file contents;
- approval or decision tokens.

Add health status for agent listener, operator listener, grant store, mirror
store, and upstream connectivity. Health output remains credential-blind.

## Brokerkit Cutover

Replace broker-local shared implementations with Brokerkit in the same change
that adopts each shared package:

- auth;
- policy;
- grants;
- operator inbox and lifecycle events;
- audit;
- notification interfaces and optional Telegram adapter;
- HTTP safety helpers;
- atomic storage;
- generic Git parsing helpers where ownership is already proven.

Delete local duplicates after cutover. Keep only Hugging Face classifiers,
presenters, executors, mirrors, routing, token handling, and setup/doctor
integration in this repository.

## Implementation Work

- register the Hugging Face policy vocabulary in Brokerkit;
- cut existing auth, grants, notification, audit, storage, and generic Git
  behavior over to Brokerkit;
- implement OpenAI-compatible Router inference forwarding;
- implement explicit read-only Hub route families;
- retain and adapt append-only Git/LFS/Xet enforcement;
- implement typed reversible Hub writes required by real consumers;
- implement Hugging Face operator-inbox presentation;
- mount Brokerkit operator handlers on the independently authenticated operator listener;
- make request creation independent of Telegram configuration;
- add client setup output for inference and Git;
- expand doctor for dual listeners, operator isolation, and credential files;
- update `docs/SPECIFICATION.md`, `README.md`, and `scope.example.json` after
  implementation;
- retain direct cutover semantics with no protocol compatibility layer.

## Test Plan

### Inference

- models and chat-completions happy paths;
- streaming and non-streaming responses;
- tool-call and structured-output payloads;
- provider-pinned model IDs;
- upstream 4xx, 5xx, timeout, disconnect, and malformed stream behavior;
- body, header, idle, and total limits;
- authorization replacement and response-header stripping;
- prompts and generated content absent from audit and errors.

### Hub Reads And Writes

- every supported path and query shape;
- private resource reads within scope;
- cross-scope and malformed target refusal;
- redirect and alternate-host refusal;
- fast-forward, new ref, force-push, deletion, and tag movement;
- LFS/Xet scope and signed-transfer behavior;
- reversible typed writes;
- snapshots before bucket overwrite;
- generic API forwarding remains impossible;
- permanently forbidden administration operations remain ungrantable.

### Operator Inbox

- pending and history queries;
- safe Hugging Face presentation;
- SSE replay, live updates, and reconnect;
- approve, deny, cancel, revoke, expire, reserve, consume, and ambiguous
  execution;
- canonical plan cannot be replaced by operator input;
- agent secret cannot access operator routes;
- optional Telegram delivery and no-Telegram operation produce identical
  durable grant states.

### Isolation And Secrets

- token-file ownership and mode checks;
- agent cannot read token file or broker environment;
- agent cannot authenticate to the operator listener;
- client and operator secret reuse rejected;
- no credential in API responses, logs, errors, audits, fixtures, test names,
  process arguments, or diagnostics;
- doctor fails unsafe and inconclusive deployments.

### Live Validation

- run inference through a broker secret;
- read a private in-scope resource;
- perform a fast-forward push;
- request and deny a force-push;
- request and approve a second exact operation;
- restart and verify pending/history durability;
- exercise the operator inbox from an independent host application;
- prove the untrusted client cannot recover the HF token;
- run doctor and require a clean result.

### Quality Gates

```sh
gofmt -l .
go vet ./...
go test -race ./...
go build ./cmd/hf-broker
golangci-lint run
slophammer-go dry .
slophammer-go crap .
slophammer-go check .
```

## Acceptance Criteria

- An agent can use Router inference without receiving a Hugging Face token.
- Supported private reads and reversible writes work through a broker secret.
- Destructive and administrative actions fail closed or become exact pending
  requests only when policy permits.
- A trusted application can render pending requests, history, and live events
  and can approve, deny, cancel, or revoke through the operator surface.
- Telegram is optional and no longer owns approval state.
- Standard OpenAI and Git clients work without an `hf-broker` SDK.
- Other applications can integrate through the documented operator HTTP/SSE
  surface and thin internal clients.
- Same-host isolation is verifiable and the real token remains inaccessible to
  the client user.
- No generic authenticated Hugging Face proxy exists.

## Non-Goals

- Do not build an application-specific notification drawer in `hf-broker`.
- Do not publish a custom inference SDK.
- Do not require Telegram or another messaging transport.
- Do not expose arbitrary Hugging Face methods, paths, headers, or bodies.
- Do not put provider-neutral grant and inbox machinery back into
  `hf-broker` after Brokerkit owns it.
- Do not add protocol negotiation, compatibility layers, or versioned routes.
