# Native Git Client Integration Plan

Date: 2026-07-19

Status: planned

## Objective

Make Git-speaking brokers work through ordinary Git commands after one
user-level setup:

```sh
gh-broker git install
hf-broker git install

git clone https://github.com/example/project.git
git pull
git push
```

The integration must apply to existing repositories and future clones without
editing each repository. BrokerKit must remain the only holder of provider
credentials. Git clients receive only their existing broker client credential,
and every fetch, push, LFS request, and supported Xet request remains subject to
the owning broker's policy, approval, audit, and bounded transport controls.

This is one coordinated replacement. Do not retain manual broker URLs,
provider-specific Git setup implementations, direct-provider credential
fallbacks, fixed default ports, or per-repository installation as supported
parallel paths.

## Current State

The provider servers already implement most of the data plane:

- GitHub Broker exposes smart-HTTP upload-pack and receive-pack routes;
- Hugging Face Broker exposes smart HTTP, LFS batch and object routes, and
  bounded forwarding for signed LFS actions;
- both brokers authenticate clients independently of provider credentials;
- receive-pack commands are classified into branch creation, fast-forward,
  force update, deletion, and tag operations;
- policy, grants, plans, notification, and audit infrastructure already exists;
  and
- shared endpoint code supports Unix sockets, explicit loopback TCP, socket
  activation, and inherited descriptors.

What is missing is the native client experience. A normal Git remote still
points directly at GitHub or Hugging Face. Git does not automatically route it
through a local Unix-socket broker, and the generated client configuration does
not install a Git credential helper or URL mappings.

## Architectural Decision

Use Git's standard smart-HTTP client, URL rewriting, and credential-helper
protocol. Do not implement packfiles, pkt-line exchange, object negotiation, or
a replacement Git client.

The native path is:

```text
git / git-lfs / supported Xet client
        |
        | ordinary HTTP smart-Git URL selected by Git configuration
        v
explicit loopback Git listener owned by the provider broker
        |
        | authenticated with the broker client credential
        v
provider broker policy and authorization
        |
        | provider credential remains inside the broker
        v
GitHub or Hugging Face
```

Git supports `url.<base>.insteadOf` and `url.<base>.pushInsteadOf` for applying
transport mappings to repositories that have never been configured locally.
Git also defines a credential-helper protocol for retrieving credentials
without storing them in remote URLs or Git configuration.

Reference standards:

- <https://git-scm.com/docs/git-config#Documentation/git-config.txt-urlbaseinsteadOf>
- <https://git-scm.com/docs/gitcredentials>
- <https://git-scm.com/docs/git-credential>
- <https://github.com/git-lfs/git-lfs/blob/main/docs/man/git-lfs-config.adoc>

### Why not make a custom URL scheme the primary transport?

A `git-remote-gh-broker` helper was the initial candidate. It would solve
ordinary Git over a Unix socket, but it would not provide a complete native
data plane. Git LFS derives an HTTP endpoint from the remote URL. A custom URL
such as `hf-broker://huggingface.co/...` is not a usable LFS HTTP origin and is
currently interpreted incorrectly by Git LFS. Xet and other provider-owned
side channels have the same class of problem.

The production contract therefore keeps the rewritten remote as ordinary HTTP
on an explicit loopback listener. Git, Git LFS, and provider side channels can
all derive valid URLs and use their mature clients. A remote-helper executable
may be added later for environments that cannot expose loopback TCP, but it is
not the canonical installation and cannot be used to claim LFS/Xet support.

### Why an explicit loopback listener is acceptable

There is no BrokerKit default port. The deployment allocates and persists the
listener during broker service setup, following the existing listener endpoint
architecture. Linux may use systemd socket activation, macOS may use launchd,
and containers or orchestrators may provide their own listener.

The endpoint is stable for that installation but is not globally prescribed.
Setup must never probe for a new port on each process start. A conflict causes a
clear setup or startup failure instead of silently moving Git traffic.

## User Experience

### System setup

The administrator configures a separate Git listener for each Git-speaking
broker:

```sh
gh-broker setup systemd \
  --agent-endpoint activation://agent \
  --git-endpoint tcp://127.0.0.1:52147 \
  ...

hf-broker setup systemd \
  --agent-endpoint activation://agent \
  --git-endpoint tcp://127.0.0.1:52148 \
  ...
```

The numbers above are examples chosen by a deployment, not defaults. Setup
persists a nonsecret descriptor containing the provider name, canonical remote
hosts, listener origin, and supported data-plane features.

The Git listener is separate from the operator listener. It exposes only the
provider's Git data-plane routes. It must not expose Operator V1, browser
sessions, setup, credential lifecycle, or administrative endpoints.

### User setup

One command configures one user:

```sh
gh-broker git install
hf-broker git install
```

The command:

1. locates and validates the broker client configuration;
2. verifies the configured Git listener is loopback or explicitly approved for
   network use;
3. verifies the listener belongs to the expected broker;
4. verifies the required `git` and optional `git-lfs` versions;
5. installs or exposes the shared `git-credential-brokerkit` executable;
6. writes only BrokerKit-owned user-level Git configuration;
7. runs a non-mutating authenticated discovery check; and
8. prints the exact providers and URL forms now routed through the broker.

It does not modify any repository, remote, hook, `.lfsconfig`, `.gitconfig`
inside a repository, or provider credential.

### Daily use

After setup:

- `git clone`, `git fetch`, and `git pull` use the broker;
- `git push` uses the broker;
- Git LFS batch, download, upload, verify, and locking routes use the broker
  where supported;
- public repositories follow the same policy path as private repositories;
- direct allows proceed normally;
- request decisions wait for operator approval and continue when approved;
- denies fail with a concise provider, operation, target, and rule result; and
- a missing or unhealthy broker fails closed without retrying the provider
  directly.

### Optional push-only mode

Support an explicit installation mode for users who intentionally retain
direct read credentials:

```sh
gh-broker git install --mode push-only
```

This uses `pushInsteadOf` instead of `insteadOf`. It is not the default. The
default is `all`, because a broker-only client must also be able to clone and
fetch private repositories without a provider token.

## Shared Package Boundaries

### `gitclient`

Add a provider-neutral root package that owns Git client integration:

- canonical Git URL mapping values;
- safe invocation of `git config --global`;
- exact-value install, update, and uninstall behavior;
- Git credential-helper input parsing and output rendering;
- strict client configuration loading without shell evaluation;
- endpoint descriptor loading and validation;
- host, path, and provider matching;
- doctor checks and machine-readable diagnostics; and
- command-runner injection for tests.

It must not import provider packages or contain `github.com`,
`huggingface.co`, repository-type path rules, or provider environment names.

The package receives a concrete descriptor:

```go
type Provider struct {
    Name             string
    BrokerName       string
    CredentialID     string
    CanonicalOrigins []Origin
    GitOrigin        url.URL
    ClientConfigPath string
    Features         Features
}
```

Keep this descriptor small. Do not create a generic plugin framework or a
provider registry that duplicates broker process ownership.

### `gitserver`

Add a provider-neutral server package for the separate Git listener:

- listener startup and coordinated shutdown;
- authentication middleware reuse;
- request body limits and secure request spooling;
- approval wait and cancellation behavior;
- idempotency derivation for retried Git requests;
- response and error projection suitable for Git clients;
- common Git content types and cache controls;
- safe route registration primitives; and
- transport metrics.

`gitserver` does not classify provider operations, construct provider URLs,
hold provider credentials, or parse provider-specific repository paths.

### Provider adapters

GitHub owns:

- `github.com` URL forms, including HTTPS, SSH URL, and SCP-like syntax;
- `OWNER/REPOSITORY` path normalization;
- smart-HTTP route registration;
- GitHub credential selection;
- GitHub receive-pack classification and upstream verification; and
- GitHub-specific approval presentation.

Hugging Face owns:

- `huggingface.co` URL forms;
- model, dataset, and Space repository path normalization;
- smart HTTP, LFS, and supported Xet route registration;
- Hugging Face credential selection;
- LFS action rewriting and bounded forwarding; and
- Hugging Face-specific approval presentation.

Shared packages must not import either adapter.

## Git Configuration Contract

### URL rewriting

For an installation whose Git listener is
`http://127.0.0.1:52147`, GitHub's default `all` mode writes exact user-level
mappings equivalent to:

```ini
[url "http://127.0.0.1:52147/"]
    insteadOf = https://github.com/
    insteadOf = ssh://git@github.com/
    insteadOf = git@github.com:
```

Hugging Face writes its own listener and canonical URL forms. Preserve the full
repository suffix after replacement. Reject rewrites that could collapse
provider, owner, repository type, or repository name boundaries.

Use `git config --global --add` and `--fixed-value` operations rather than
editing text. Installation is idempotent. Uninstall removes only exact values
owned by the matching provider installation.

### Credential configuration

Configure the helper only for the exact loopback origin:

```ini
[credential "http://127.0.0.1:52147"]
    helper = brokerkit --provider github
    useHttpPath = true
```

The helper:

- supports `get`, `store`, `erase`, and capability negotiation;
- returns a broker username and the broker client credential only for `get`;
- treats `store` and `erase` as successful no-ops because the protected client
  file is authoritative;
- refuses unknown hosts, ports, paths, or providers;
- sets `quit=true` on a recognized broker origin when its credential is absent
  or invalid, preventing an interactive provider-password fallback;
- never emits the provider credential;
- never logs credential-helper stdin or stdout; and
- emits bounded, plain diagnostics on stderr.

The helper reads `~/.config/<broker>/client.env` using a strict parser for the
two generated exports. It must never source the file or invoke a shell. Keep the
file owner-only. Long term, client configuration may move to a structured file,
but this feature must not introduce dual readers; change the shared client
format once if that is required.

### Existing configuration conflicts

`git install` and `git doctor` detect:

- an explicit `remote.<name>.pushurl`, which overrides `pushInsteadOf`;
- a longer matching `insteadOf` rule;
- another credential helper scoped to the broker origin;
- a provider URL already routed through another local gateway;
- repository-local LFS URL overrides;
- a global hooks path or LFS configuration that changes transport behavior;
- missing `git-lfs` when LFS pointers are present; and
- stale BrokerKit values for an endpoint that no longer exists.

Do not silently delete user configuration. Fail with the exact conflicting key
and provide an explicit repair command. `git install --replace` may replace only
values previously marked and recognized as BrokerKit-owned.

## Git Listener Contract

Each provider process receives a second listener dedicated to Git traffic:

```text
agent listener     Unix socket or deployment endpoint; Agent V1 and grants
operator listener  protected Unix socket or deployment endpoint; Operator V1
Git listener       explicit loopback or deployment endpoint; Git data plane
```

The Git listener:

- defaults to absent, never to a fixed port;
- accepts loopback TCP without a network-exposure override;
- requires the existing explicit acknowledgement for non-loopback TCP;
- uses the same per-client authentication database as the agent listener;
- registers only provider-approved Git, LFS, and Xet routes;
- rejects Agent V1, Operator V1, health detail, setup, webhook, and browser
  paths unless a minimal unauthenticated liveness route is deliberately added;
- applies no CORS behavior;
- disables caching for authenticated discovery and decision responses;
- enforces strict path normalization before provider classification; and
- never follows an upstream redirect with a provider authorization header to a
  different origin.

Use shared concurrent serving and graceful-shutdown code. Do not merge
listeners into one broad router and try to hide routes with middleware.

## Approval And Execution Flow

### Fetch

Fetch remains a direct smart-HTTP operation:

1. Git asks for upload-pack discovery.
2. The broker authenticates the client and canonicalizes the repository.
3. Policy evaluates `git.fetch`.
4. An allow proxies discovery and upload-pack with the provider credential.
5. A deny returns a stable Git-readable error without an upstream call.

Fetch is not requestable by default. A deployment may define stricter policy,
but the client integration must not invent a bypass or provider fallback.

### Push advertisement

Receive-pack discovery is non-mutating but credential-bearing. Policy evaluates
`git.push.advertise` independently. Normal writable repositories should allow
advertisement so Git can calculate the intended update before sending a pack.

### Receive-pack authorization

The broker remains authoritative. Do not trust a client-supplied declaration
that an update is a fast-forward.

1. Receive the bounded request into a secure spool under the broker state
   directory.
2. Hash bytes while spooling and reject excess size immediately.
3. Parse and normalize every receive-pack command using the existing bounded
   Git implementation.
4. Resolve current upstream refs and classify every update.
5. Build one immutable push plan containing the exact repository, refs, old and
   new object IDs, object format, force markers, atomic mode, push options,
   command order, pack digest, and expiry.
6. Evaluate policy for every classified update.
7. Deny the entire push if any update is denied.
8. If all updates are allowed, reserve authorization and forward the exact
   spooled bytes.
9. If any update requires approval, create one grouped approval bound to the
   complete plan and wait on the existing lifecycle mechanism.
10. On approval, reserve one use, revalidate upstream refs, and forward the same
    spooled bytes.
11. Commit grant use only after the upstream outcome is known. Reconcile an
    ambiguous transport failure before permitting a retry.

The approval is bound to the actual request body, not an advisory preflight
from a helper. This removes the gap between an approved ref list and the pack
eventually sent by Git.

### Waiting behavior

The HTTP request remains open while approval is pending. Git therefore waits
inside the original `git push` and continues after an operator approves it.

Requirements:

- configurable bounded wait, with five minutes as policy data rather than a
  hard-coded transport timeout;
- heartbeat or progress text only where the Git protocol permits it;
- cancellation when the Git client disconnects, without corrupting grant
  state;
- a stable request ID printed when the wait ends before a decision;
- idempotent retry derived from client, repository, operation set, and plan
  digest;
- reuse of an already approved unconsumed plan on an exact retry; and
- no second Telegram or inbox request for the same pending plan.

If a reverse proxy or remote deployment cannot hold the request for the policy
window, the command fails with the request ID and a later identical `git push`
resumes it. Local loopback installations must support the seamless wait path.

### Multi-ref and atomic pushes

Treat one receive-pack request as one transaction:

- evaluate every ref before forwarding;
- present every ref in one bounded approval view;
- require all decisions before forwarding any bytes upstream;
- preserve Git's atomic option when requested and supported;
- reject mixed allowed and denied batches rather than partially forwarding;
  and
- bind one-use authorization to the full ordered command set.

## Git LFS And Xet

### Git LFS

Standard HTTP URL rewriting is required so Git LFS derives a valid broker URL.
The HF adapter must preserve its existing secure action rewriting:

1. Git LFS sends the batch request to the HF Broker Git listener.
2. Policy classifies read, upload, verify, lock, or unlock behavior.
3. Requestable behavior waits before returning an upload action.
4. Upstream signed action URLs are replaced with bounded broker-local URLs.
5. The client never receives the HF provider token or upstream action headers.
6. Object transfer, range requests, retries, and verification remain bounded
   and audited.

Set `lfs.transfer.enablehrefrewrite` only if conformance tests prove it is
required and scoped correctly. Do not write repository-local `.lfsconfig`.

Add corresponding GitHub LFS routes before claiming complete GitHub LFS
support. If the configured GitHub credential type cannot perform an LFS action,
return a precise capability error rather than bypassing the broker.

### Xet

Treat Xet as a provider side channel, not as ordinary Git pack traffic. Before
enabling HF native Git installation by default:

- inventory the current official Xet client's endpoint and credential
  discovery behavior;
- register only the required HF Broker routes;
- ensure reconstructed or signed URLs remain broker-local;
- preserve range, multipart, retry, and integrity behavior;
- classify upload and mutation separately from reads; and
- pass a real model or dataset clone and push corpus using the official client.

If the official Xet client cannot be routed without provider credential
exposure, fail closed and document that exact unsupported path. Do not silently
export the HF token as an interim solution.

## Security Requirements

- Provider credentials remain readable only by the provider broker process.
- Broker client credentials never appear in Git remotes, Git config values,
  process arguments, logs, audit records, error bodies, or importable files.
- The credential helper responds only to the exact installed loopback origin.
- `credential.useHttpPath` prevents one provider route from receiving another
  provider's client credential when an ingress host is shared.
- Git listeners bind only to literal loopback addresses unless network exposure
  is explicitly approved.
- Non-loopback plaintext HTTP is rejected.
- URL userinfo, fragments, ambiguous escaping, dot segments, encoded path
  separators, and unexpected query parameters are rejected.
- Authorization headers are replaced, not appended, before upstream calls.
- Cross-origin redirects strip authorization and are rejected by default.
- Secure spools use owner-only files under the broker state directory, have
  bounded size and lifetime, survive only when required for an idempotent
  pending request, and are deleted after terminal reconciliation.
- Approval decisions bind to immutable plans and one-use reservations.
- A helper or Git configuration failure never falls back to direct GitHub or
  Hugging Face credentials.
- Existing explicit repository `pushurl` values are reported because they can
  bypass global rewriting.
- Uninstall removes routing before removing credential-helper configuration so
  an interrupted uninstall cannot expose a secret to a provider host.

Update the threat model with local port scanning, malicious repositories,
credential-helper confusion, URL rewrite precedence, hostile Git hooks,
cross-user process inspection, request-spool exhaustion, approval races,
multi-ref ambiguity, and redirect leakage.

## Failure Semantics

The client must receive concise errors that preserve Git's normal exit status:

- broker unavailable;
- broker authentication failed;
- repository denied by policy;
- approval requested with request ID;
- approval denied or expired;
- Git listener misconfigured;
- conflicting Git URL rewrite;
- explicit push URL bypass;
- provider credential unavailable or under-scoped;
- upstream rejected the update;
- request exceeded a configured byte or time limit; and
- outcome ambiguous and under reconciliation.

Errors must not include provider response bodies that may contain credentials,
signed URLs, private paths beyond the authorized target, or raw pack content.

## Observability And Audit

Add bounded metrics for:

- Git discovery, upload-pack, receive-pack, LFS, and Xet requests;
- bytes spooled and forwarded by direction;
- policy allow, request, and deny outcomes;
- approval wait duration and client disconnects;
- exact-plan retries and deduplicated notifications;
- upstream duration and status classes;
- ambiguous outcomes and reconciliation; and
- credential-helper success, refusal, and configuration errors without host
  credentials or repository secrets.

Audit records retain provider, client, canonical operation, target, safe ref
attributes, matched rule IDs, grant ID, plan digest, byte counts, and upstream
status. They never contain pack bytes, object contents, secrets, signed URLs, or
authorization headers.

## Commands

Provider binaries expose the same command shape:

```text
<broker> git install [--mode all|push-only] [--home-dir PATH]
<broker> git uninstall [--home-dir PATH]
<broker> git doctor [--home-dir PATH] [--repository PATH]
<broker> git status [--home-dir PATH]
```

Shared parsing and behavior live in BrokerKit. Provider binaries supply their
descriptor and presentation names only.

`status` is machine-readable with `--json`. `doctor` performs no mutations and
checks:

- binary and Git version;
- client file ownership and mode;
- Git listener reachability and identity;
- URL rewrite precedence;
- credential-helper resolution;
- exact authenticated read against a caller-selected repository;
- LFS availability when requested; and
- direct-provider credential helpers that could bypass the broker.

## Implementation Work

### 1. Define conformance fixtures

- Add provider-neutral URL rewrite and credential-helper fixtures.
- Record expected Git behavior for HTTPS, SSH URL, and SCP-like remotes.
- Add temporary Git repositories for SHA-1 and SHA-256 object formats.
- Add regular, branch-create, fast-forward, force, delete, tag, multi-ref,
  atomic, shallow, LFS, and interrupted-push cases.
- Freeze expected security and failure outcomes before implementation.

### 2. Add the shared Git client package

- Implement strict descriptors, URL mappings, config ownership, install,
  uninstall, status, and doctor.
- Implement `git-credential-brokerkit` with bounded protocol parsing.
- Add exact-value conflict detection and idempotency tests.
- Add Linux and macOS path and ownership tests.

### 3. Add the shared Git listener runtime

- Extend setup models with an optional explicit Git endpoint.
- Add separate route registration and concurrent serving.
- Reuse authentication without exposing Agent or Operator routes.
- Add secure spooling, cancellation, and cleanup.
- Add Git-readable stable errors and metrics.

### 4. Add plan-bound waiting

- Build canonical multi-ref push plans from actual receive-pack requests.
- Bind policy decisions and grants to the complete plan digest.
- Add grouped approval presentation.
- Wait on durable lifecycle events and resume the same request.
- Revalidate refs immediately before forwarding.
- Add exact retry, use reservation, ambiguous outcome, and reconciliation
  behavior.

### 5. Integrate GitHub

- Register the GitHub Git listener routes.
- Reuse the existing smart-HTTP and receive-pack implementation.
- Add GitHub URL forms and setup commands.
- Add GitHub LFS support or an explicit capability refusal.
- Test installation credentials and repository policy independently.

### 6. Integrate Hugging Face

- Register smart HTTP and all existing LFS routes on the Git listener.
- Add model, dataset, and Space URL forms.
- Prove Git LFS endpoint derivation through global URL rewriting.
- Validate LFS action rewriting against real client behavior.
- Complete the Xet inventory and route only proven safe operations.
- Test private and gated repositories without an HF CLI token in the client
  account.

### 7. Replace manual workflows

- Remove documentation that requires users to set broker remote URLs manually.
- Remove provider-local Git client setup code if any appears during
  implementation.
- Remove direct provider credential helper setup from broker-only installation
  paths.
- Keep only the native install, status, doctor, and uninstall workflow.

### 8. Install and release

- Include the credential helper in Linux and macOS artifacts.
- Update systemd and launchd setup for explicit Git listeners.
- Update package manifests, checksums, and installer ownership records.
- Run install, upgrade, uninstall, and reinstall tests from packed artifacts.
- Release all affected broker binaries from one coherent BrokerKit revision.

## Test Strategy

### Unit tests

- URL canonicalization and rewrite generation;
- exact Git config ownership and conflict handling;
- credential protocol capability, get, store, erase, and malformed input;
- client file parsing and permission checks;
- endpoint and listener exposure validation;
- secure spool bounds and cleanup;
- push-plan canonicalization and digest stability;
- receive-pack operation classification;
- multi-ref policy aggregation;
- approval wait, cancellation, retry, and expiry; and
- secret redaction in every error path.

### Integration tests

Run real Git binaries against local fake upstreams through both Unix-backed
broker internals and explicit loopback Git listeners:

- clone, fetch, pull, and push;
- existing branch fast-forward;
- new branch creation;
- rejected force push and deletion;
- approved request that continues in the original command;
- denied and expired approval;
- multiple refs with mixed policy outcomes;
- atomic push;
- push options;
- SHA-1 and SHA-256 repositories;
- shallow and partial operations supported by the provider;
- client disconnect during approval;
- broker restart with a pending request;
- stale and conflicting Git configuration; and
- no direct-provider credential available to the test user.

Use the system Git installation and include a version matrix in CI. Do not use
go-git as a substitute for client conformance.

### LFS and Xet tests

- official `git-lfs` against the HF Broker listener;
- LFS pointer checkout, batch download, range retry, upload, verify, and lock
  behavior;
- large-object limits and spool exhaustion;
- rewritten action URLs contain no provider credential;
- official supported Xet client clone and push;
- interrupted and resumed object transfers; and
- provider credential under-scope failures.

### Packed-install tests

On clean Linux and macOS user homes:

1. install BrokerKit artifacts;
2. configure provider services and explicit Git listeners;
3. run `<broker> setup client`;
4. run `<broker> git install`;
5. clone without provider credentials;
6. fetch and make an allowed push;
7. trigger and approve a gated push;
8. verify force and delete denials;
9. run doctor;
10. uninstall Git integration; and
11. prove the exact Git config values were removed without touching unrelated
    user configuration.

### Live acceptance

Before reporting completion, verify with an isolated real GitHub repository and
an isolated real Hugging Face repository:

- the client account has no direct GitHub or Hugging Face token;
- clone and fetch work through the broker;
- a normal fast-forward push succeeds;
- a requestable push waits, appears in Telegram and the operator inbox, and
  continues after approval;
- denial is visible in Git and audit output;
- force push and ref deletion remain denied;
- HF LFS upload and download work; and
- all temporary repositories, refs, LFS objects, grants, and credentials are
  cleaned up through authorized operator paths.

Mocks, health checks, and successful advertisements are not substitutes for an
actual receive-pack push in this acceptance test.

## Documentation Updates

Update these maintained documents in the same implementation:

- `docs/ARCHITECTURE.md` for the Git listener and client path;
- `docs/UNIFIED_BROKER_CONTRACT.md` for native Git setup and plan-bound waits;
- `docs/POLICY_CORE.md` for multi-ref authorization;
- `docs/OBSERVABILITY.md` for Git transport metrics and audit;
- `docs/security/THREAT_MODEL.md` for local Git client threats;
- `docs/SYSTEMD_INSTALL_RUNTIME.md` for explicit Git socket activation;
- GitHub and Hugging Face broker READMEs;
- installer and release documentation; and
- generated capability documentation where Git, LFS, or Xet support changes.

Delete superseded manual remote examples rather than retaining two documented
ways to install the feature.

## Acceptance Criteria

The implementation is complete only when all of the following are true:

- one command installs Git integration for a user;
- no repository-local setup is required;
- existing and newly cloned provider URLs route correctly;
- default installation brokers clone, fetch, pull, and push;
- no fixed BrokerKit Git port exists;
- no provider or broker credential appears in Git configuration or remotes;
- direct allows finish without prompts;
- request decisions continue after approval in the same local Git command;
- exact retry works after disconnect or timeout;
- force pushes and deletions remain separately enforceable;
- multi-ref pushes are authorized as one immutable transaction;
- Git LFS works end to end for every provider claiming LFS support;
- HF Xet either works end to end or is explicitly refused without credential
  leakage;
- install, doctor, status, uninstall, and reinstall are idempotent;
- Linux and macOS packed-install tests pass;
- all required Go, Slophammer, protocol-generation, and package checks pass;
  and
- live isolated GitHub and Hugging Face pushes have been completed and cleaned
  up.

## Explicit Non-Goals

- Reimplementing Git pack or wire protocols.
- Replacing Git, Git LFS, or the official supported Xet client.
- Installing hooks or configuration into each repository.
- Defining a universal BrokerKit TCP port.
- Exposing operator APIs on the Git listener.
- Acting as a general-purpose HTTP proxy.
- Supplying provider tokens through Git credential helpers.
- Silently bypassing BrokerKit when it is unavailable.
- Supporting arbitrary third-party Git hosts without a broker-owned provider
  adapter and conformance suite.
