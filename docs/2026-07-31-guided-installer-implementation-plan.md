# Guided installer implementation plan

Date: 2026-07-31

Status: reviewed and ready for implementation

## Objective

Replace the fixed Linux host wizard with one goal-first installer that can:

- install the unYOLO command only
- install credential services without an agent connection
- connect an agent to existing credential services
- install credential services and connect an agent in one run
- use the current account, an existing account, or a new restricted account
- connect an agent running in Docker or on another machine
- install native services on Linux and macOS
- install credential services in Docker when that backend is selected

The normal flow uses the plain terms and screen copy in
[`GUIDED_INSTALLATION.md`](GUIDED_INSTALLATION.md). Internal deployment formats, plan digests, and
release provenance stay available under **Show technical details**.

A setup path is unavailable until apply and rollback work, removal is safe, and real workflow tests
pass on the target platform.

## Scope

This plan covers the installer, its persisted nonsecret state, native host deployment, client
connections, Docker integration, secure remote pairing, reconfiguration, repair, and removal. It
also covers the release and its documentation together with end-to-end verification.

The work replaces pre-release V1 contracts in place. It does not add old-state readers, aliases,
dual writes, a second setup command, or a second wizard framework.

## Current implementation

The repository already has these useful boundaries:

- `install/bootstrap.sh` verifies and stages one exact release.
- `internal/userinstall` activates one immutable user-level release.
- `deployment/session` stores resumable nonsecret setup state.
- `deployment/flow` defines renderer-neutral setup steps.
- `internal/terminal/setup` renders Huh fields with Lip Gloss styling.
- `deployment/profile` loads a locked host configuration.
- `deployment/component` validates provider-owned resources and applies them with rollback.
- `internal/host/deployment` binds a reviewed plan to observed host state.
- `internal/host/privilege` runs the verified root worker through one framed exchange.
- `internal/host/bundle` activates signed runtime artifacts and manages systemd or launchd.
- the broker client configuration and named-secret formats already support owner-only files.
- Linux account inspection and service activation already exist with rollback and real client
  probes.
- launchd rendering and broker-specific launchd installation code provide tested macOS primitives.

The current flow has these blocking limits:

- `cmd/unyolo/setup.go` assumes one complete host deployment.
- the provider menu appears before the user chooses a goal.
- Huh field height includes the title and description, so the current height calculation hides
  options.
- Back and Edit are represented in types but are not wired to interactive navigation.
- setup sessions store a loose answer map instead of one validated intent.
- release templates hardcode client `agent`, Unix account `unyolo-agent`, and one approver.
- Custom mode records a value but does not change the generated configuration.
- release generation prebuilds every provider combination instead of compiling one selected setup.
- root provenance checks expect one exact prebuilt template and cannot verify dynamic identities.
- the host profile requires at least one agent, so credential-services-only setup is impossible.
- the GitHub broker accepts only one configured client per process.
- client secret files cannot represent an intentionally empty server or declaratively add and
  remove several managed clients.
- local client files are generated inside provider component apply, which couples server deployment
  to one local Unix account.
- managed agent creation and component account creation are Linux-only.
- the root bootstrap rejects macOS and hardcodes Linux root paths in several commands.
- release deployment files contain systemd units but no generated launchd profiles.
- direct network TCP is plaintext HTTP and the client transport rejects non-loopback TCP.
- no pairing protocol or pairing service exists.
- no Docker deployment backend or official per-broker image release exists.
- the host engine has transaction rollback but no durable ownership receipt for safe later removal.

## Product decisions

### One installer

The public command continues to stage and run `unyolo setup`. No second CLI or Cobra command tree is
added. `cmd/unyolo/setup.go` becomes a thin entrypoint around the new setup coordinator.

### One setup intent

The wizard produces one closed `unyolo.io/setup-intent/v1` object. The intent contains only
nonsecret user choices. It drives server configuration, client configuration, or both.

### One durable installation record

A successful server-side setup stores one nonsecret `unyolo.io/installation/v1` record below the
user configuration root:

```text
unyolo/installations/default/
├── installation.json
└── generated/
    ├── deployment.json
    ├── components/
    └── runtime/
```

`installation.json` is the source for later guided reconfiguration. `generated/` is a deterministic,
locked build output. A generated deployment records the installation digest that produced it. The
compiler rejects edits to generated files. Advanced users may continue to pass an independently
maintained locked profile with `unyolo setup --profile`; that path has no installation record and
remains explicitly advanced.

The name is `default` unless another installation already exists or the user opens advanced naming.
The normal first run never asks for a hostname or deployment name.

### Separate server and connection plans

The compiler produces independent outputs:

```text
Setup intent
├── Credential-service plan, when local services were selected
├── Agent-connection plan, when an agent was selected
└── Integration plan, when OpenClaw or another integration was selected
```

A complete local setup composes these plans into one review and one transaction. A client-only setup
never starts the host deployment worker unless it must change a different local account.

### Server setup with no clients

A credential service can start with zero agent clients. Its agent endpoint returns an ordinary
authentication failure until a client is added. The person approving requests remains separately
authenticated.

This requires all three brokers to accept an empty named-client store. It also requires the GitHub
broker to use the same multi-client authentication model already used by the Hugging Face and sudo
brokers.

### Client connections remain desired state

A server installation records every managed client connection in `installation.json`. Adding,
rotating, or removing a connection recompiles and reapplies the same installation. The root host
state stores only a receipt and the applied digests; it does not become another editable source.

A remote pairing invitation can be created only by a person with local approval authority on the
server. The reviewed connection remains pending while the invitation is claimed. The client secret
is not installed in a broker until the client confirms that it stored the bundle and the server-side
wizard performs the final activation plan.

### Account choices

The account modes are:

- `current`: connect the account running setup
- `existing`: connect another account that already exists
- `managed`: create a restricted, non-login account
- `container`: connect a Docker Compose service
- `remote`: create an invitation for another machine

A managed account is intended for a managed agent service and has no interactive login. A user who
needs an interactive shell creates or selects a normal operating-system account and uses
`existing`.

Using the current account provides connection control but may provide weak operating-system
isolation. The result reports connection health and isolation assurance separately. It must never
claim that provider credentials are protected from an agent running with administrator-equivalent
access.

### Internal terminology

The implementation can retain package and type names such as deployment profile and root worker.
The normal renderer uses only the user terms from the contract. Technical details expose internal
names only after defining them.

## Persisted models

### Setup intent V1

Create `setup/intent` and `protocol/setup-intent.schema.json`. The Go model uses strict JSON,
collection bounds, exact enums, and cross-field validation.

```json
{
  "api_version": "unyolo.io/setup-intent/v1",
  "goal": "complete_local",
  "credential_service": {
    "location": "native",
    "providers": ["github", "huggingface"]
  },
  "agent": {
    "location": "local_account",
    "connection_name": "bob",
    "account": {
      "mode": "existing",
      "name": "bob"
    }
  },
  "connection": {
    "transport": "local_socket"
  },
  "integrations": ["openclaw"]
}
```

Validation rules:

- `goal` is `command_only`, `credential_service`, `agent_connection`, or `complete_local`.
- `credential_service` is required only for goals that install services.
- service `location` is `native` or `docker`.
- provider IDs are unique and must exist in the verified release catalog.
- `agent` and `connection` are required only for goals that connect an agent.
- account mode and fields must match the selected agent location.
- `connection_name` is a safe 1-to-64-character client identity accepted by the shared named-secret
  format.
- remote endpoints are absolute HTTPS URLs with no user information, query, or fragment.
- integration IDs are unique and must exist in the verified release catalog.
- unknown fields are errors.
- secrets, tokens, private keys, pairing invitations, and observed host state are forbidden.

### Installation V1

Create `setup/installation`. This is the durable server-side source used after setup completes.

```json
{
  "api_version": "unyolo.io/installation/v1",
  "name": "default",
  "credential_service": {
    "location": "native",
    "providers": ["github", "huggingface"]
  },
  "approvers": [
    {"account": "onur"}
  ],
  "connections": [
    {
      "id": "bob",
      "client_id": "bob",
      "target": {
        "kind": "local_account",
        "account_mode": "existing",
        "account": "bob"
      },
      "providers": ["github", "huggingface"],
      "integrations": ["openclaw"]
    }
  ]
}
```

The record contains zero or more connections. Connection IDs and client IDs are unique. A
connection selects only providers installed by the same record. Account and integration fields are
validated by the matching platform and release capabilities.

### Setup session V1

Replace the current loose `Answers` and mandatory `Deployment` fields in
`deployment/session.Session`. The new V1 session contains:

- one partially completed setup intent
- the current step ID and ordered completed step IDs
- a capability snapshot digest
- generated nonsecret file digests
- the last committed phase
- secret-slot names with `Supplied` reset to false on reload
- timestamps and a safe bounded error

Old session files are rejected. The release notes tell pre-release users to discard them. No old
session reader is retained.

### Host deployment V1

Change `deployment/profile.Deployment` in place:

- allow zero agents for a server-only installation
- replace the local-only `Agent` fields with a target union for local account, container, or remote
- add an explicit isolation class used by verification and review
- keep approvers separate from clients
- bind the generated deployment to its installation digest
- retain selected components and integrations

A local account target contains the Unix account and its host paths together with the account mode.
Container and remote targets contain no fake Unix account. `api.AgentBinding` receives the same target kind and carries a
local config destination only when one exists.

### Client configuration V1

Change `unyolo.io/client/v1` in place so a client can use:

- `unix://` or loopback `tcp://` for local connections
- `tls://host:port` for encrypted network connections
- an inline shared secret for owner-only native files
- `shared_secret_file` for Docker and other mounted-secret environments
- an optional pinned CA file for TLS

Exactly one secret source is allowed. TLS requires a pinned CA and hostname or IP verification.
Plain non-loopback TCP remains invalid.

### Ownership receipt V1

Add a root-owned, nonsecret receipt under the host state directory. It records:

- installation and deployment digests
- resources created by unYOLO
- resources that existed before unYOLO
- current expected metadata and nonsecret digests
- enabled services and runtime release
- managed account and group identities
- connection IDs, without secret values

Removal deletes only resources marked as created and still matching their expected identity.
Preexisting or changed resources are retained and reported. Provider credentials and broker state
are retained unless the user separately confirms **Remove credentials and data**.

## Wizard architecture

### Coordinator

Add `setup/wizard` with an explicit state machine. The coordinator owns the ordered shared steps:

```text
goal
→ platform capability check
→ credential-service location, when needed
→ providers, when needed
→ agent location, when needed
→ account or container details, when needed
→ connection name
→ approvers, when needed
→ integrations
→ nonsecret provider configuration questions
→ editable review
→ CLI confirmation
→ administrator plan and confirmation, when needed
→ provider credential collection, when needed
→ apply
→ real workflow verification
```

Every transition is a pure function of the current intent and capability set. Going back or editing
an earlier answer clears all dependent answers and derived state.

`cmd/unyolo/setup.go` parses flags, loads the verified release context, creates the coordinator, and
maps cancellation to exit status. It no longer contains product decisions or one long procedural
flow.

### Terminal renderer

Continue using Huh and Lip Gloss. Add a small Bubble Tea wizard model in
`internal/terminal/setup` that hosts Huh fields and owns page navigation. Do not add another TUI
framework.

Interactive controls:

- Enter performs the displayed primary action.
- Shift+Tab moves back when Back is available.
- Ctrl+C cancels.
- The footer always shows the available controls.
- Review shows Install or Connect as the primary action and also offers Edit, Show technical
  details, or Cancel.
- accessible mode presents the same actions as numbered or named line prompts.

Text fields must support every tier-one terminal editing key. These are Ctrl+A, Ctrl+E, Ctrl+W,
Ctrl+K, Ctrl+U, and Backspace/Ctrl+H. Tests also cover arrow-key synonyms and ensure unsupported modified keys do
nothing. If the pinned Huh text input does not meet these checks, add a bounded keymap adapter rather
than a second text widget.

### Menu height

Add terminal height to renderer options. When all options fit, do not set a Huh height and let the
field render every option. When a list is longer than the available viewport, reserve lines for the
title and explanation as well as errors and the footer. Cap only the option viewport. Show
`3 more options below` or the matching count. Tests inspect the rendered PTY before submission so a final selected-value
line cannot hide clipping.

### Plain copy

Keep all normal copy in one catalog under `setup/copy`. Shared screens use typed copy IDs. Provider
steps carry signed labels and help text through setup-flow V1. Tests reject the forbidden user-facing
terms from the normal transcript and snapshot the complete flow at 80 columns.

Each screen has one question, one reason, outcome-based options, and a marked recommendation when the
platform supplies one. Confirmations use action labels such as Install, Connect, Apply system
changes, and Cancel instead of Yes and No.

### Provider question protocol

Use the existing `unyolo.io/setup-flow/v1` step model for provider-owned questions. Add the missing
file prompt to `SetupPrompter` and wire `NavigationError` into the wizard state machine.

Extend setup-component V1 with an unprivileged deterministic render exchange:

1. The coordinator sends selected providers, target platform, agent targets, approvers, endpoints,
   and the complete set of nonsecret answers.
2. The adapter returns the next bounded setup-flow step or a final rendered component result.
3. The final result contains the provider profile, referenced nonsecret files, plain review items,
   secret prompt metadata, and runtime requirements.
4. The coordinator runs rendering twice and rejects nondeterministic output.

The adapter is stateless across questions. Moving Back or resuming sends the remaining answers again
and reproduces the same next step. Secret prompt metadata is rendered before review, but secret bytes
and credential source paths are collected only after the user accepts the administrator plan. They
remain in memory or one-use descriptors and must be entered again after resume.

Rendering does not inspect live host state, fetch mutable network data, or depend on secret bytes.
Enrollment and credential checks happen after the deterministic configuration is reviewed.

## Capability model

Add signed setup capabilities to the release manifest and provider descriptors. A capability is
available only when both conditions hold:

- the verified release declares the path complete for the current OS and architecture
- a live probe finds the required native tools and environment

The release declaration includes:

- native service backend: systemd or launchd
- local account inspection and managed-account creation
- local Unix sockets
- TLS network listeners
- remote pairing
- Docker client integration
- Docker credential-service deployment
- supported integrations

Live probes are read-only. They check commands, versions, service-manager availability, Docker
Compose availability, current identity, and required filesystem roots. The installer never installs
Docker, changes a firewall, or substitutes an unsupported backend.

Capability snapshots are digest-bound to the setup session. Resume reruns the live probes. A changed
capability invalidates dependent answers and plans.

## Dynamic compilation and release trust

### Release source set

Replace the generated template for every provider subset with one verified platform source set:

```text
deployment-kits/
├── artifacts/
├── providers/
│   ├── github/
│   ├── huggingface/
│   └── sudo/
├── integrations/
├── platform/
│   ├── linux/
│   └── darwin/
└── runtime/
```

Provider runtime binaries remain under `deployment-kits/artifacts/`. The source set contains signed
ownership envelopes, renderer entrypoints, static files, platform service templates, and capability
metadata. Release creation validates every source and includes only the current platform directory
in a platform archive.

### Deterministic compiler

Add `setup/compiler`. It accepts an installation record, the verified release source set, and the
platform capability snapshot. It emits one locked host deployment plus client and integration plans.
It performs no network calls and reads no credential values.

For the same inputs it must produce byte-identical files and digest. Provider-specific rendering is
performed only by the release-attested provider adapter. Shared code validates output shape,
ownership, identities, path confinement, and references.

### Root verification

Change the root bootstrap to store the exact release source set used to produce generated profiles. Before
planning, the root-owned release CLI recompiles the submitted installation record and compares every
generated byte and digest. A user-owned generated deployment that does not match root recompilation
is rejected.

The root worker request states whether its input is an installer-generated installation or an
advanced locked profile. For an installation, root recompiles and compares all generated bytes. An
advanced profile has no generated-source claim; root verifies its runtime against the attested
release and relies on strict schemas, signed adapter ownership envelopes, locked references, and
provider validation. The two input kinds never fall back into each other.

The root worker still verifies the release tag, source commit, archive checksum, GitHub attestation,
and platform. Attested renderer code produces dynamic identities, and ownership envelopes bound the resulting
resources.

The bootstrap and root staging paths come from `bundle.DefaultPaths()` and a platform-specific
bootstrap path helper. Remove `/opt` and `/var/lib` literals from shared privilege code.

## Multi-client broker support

### Named client stores

Replace the single-client and single-approver GitHub configuration with the shared named-secret
model. GitHub, Hugging Face, and sudo then use one bounded client map and one separate bounded
approver map. Admission and audit receive the authenticated identity for every request.

All brokers accept an empty client store in production. An empty store authenticates nobody. A
server installation still requires at least one approver. Client and approver credentials must
never share a value or file.

### Declarative client entries

Replace the component profile's one-client credential encoding with a named client-store resource.
For each desired connection, the plan computes `add`, `retain`, `rotate`, or `remove`. Apply reads the
existing store, changes only the reviewed entries, writes the complete file atomically, and restarts
the affected broker before verification.

Generated client secrets use 32 random bytes encoded without padding. The installer generates them;
the user is never asked to invent a client secret. Secret values travel through one-use pipes and do
not enter plans, sessions, logs, or receipts.

The server store is authoritative for clients managed by the installation. Unknown entries in an
installation-owned store are drift and block apply until the person chooses Import or Remove. There
is no silent preservation of untracked clients.

### Local client files

Move client-file publication out of the provider's general resource loop into a connection step.
The connection step writes all selected broker configs for one local account as one rollback unit.
It verifies the home path without symlinks, writes owner-only files, and restores previous files on
failure.

A current-account client-only setup writes user files without root. An existing or managed different
account uses the reviewed root connection step. Server-only setup writes no client files.

## Native account backends

Add `internal/host/account` with platform files and an injected command runner. The backend provides separate bounded operations for listing, inspection, create planning, apply,
rollback, and verification.

### Linux

- List NSS users with `getent` and `os/user`.
- Exclude root and system service accounts from the normal existing-account list.
- Show administrator-equivalent groups found by the existing doctor checks.
- Create a managed account with fixed `useradd` arguments, an explicit home, and a nologin shell.
- Recheck account and home absence under the host lock.
- Roll back only an account created by the transaction whose complete identity still matches.
- Remove the home only after a no-follow walk confirms that every remaining path is installation
  owned; otherwise retain it and report the path.

### macOS

- Inspect local records with `dscl` and group membership with `dsmemberutil` or `dseditgroup`.
- List normal local accounts with UID 501 or greater and exclude root, disabled system accounts, and
  the current set of administrator-equivalent groups.
- Create a managed account as a hidden, password-disabled local record. Allocate an unused UID and
  primary GID at 501 or greater while holding the host lock, then recheck before each create.
- Set `NFSHomeDirectory`, `UserShell` to `/usr/bin/false`, `RealName`, `IsHidden` to `1`, and a
  disabled authentication authority. Do not grant a Secure Token or add the account to `admin`.
- Create the home with descriptor-relative operations and exact ownership.
- Record every created directory-service attribute in the transaction handle.
- Roll back with `dscl -delete` only when the record still matches the complete created snapshot.
- Use `/private/var/run/unyolo` for sockets, `/Library/Application Support/unyolo` for host data, and
  `/Library/LaunchDaemons` for system service definitions.

Existing normal macOS accounts are never rewritten to match a desired shell or home. A mismatch is a
blocking review item.

## Native service backends

### Linux systemd

Keep the existing systemd manager, socket units, enablement tracking, restart ordering, and real
process checks. Generate units from provider render output instead of copying fixed client names.

### macOS launchd

Reuse `RenderLaunchd`, `LaunchdInstallPlan`, launchd transaction snapshots, and the native bundle
manager. Add platform profiles for every provider and OpenClaw integration:

- reverse-DNS labels such as `io.unyolo.github`
- root-owned plists under `/Library/LaunchDaemons`
- `ProgramArguments` with no shell interpolation
- explicit service account and group
- launchd-owned Unix sockets with mode `0660`
- socket parents under `/private/var/run/unyolo` with traversal-only access where needed
- state and config under `/Library/Application Support/unyolo`
- `RunAtLoad` or socket activation according to the real broker behavior

Complete the missing macOS account creation in the shared account backend. Provider service accounts
use fixed signed names and hidden password-disabled records; managed agent accounts use the reviewed
name and their own home. Change component apply and rollback to call platform account and group
primitives instead of Linux commands directly.

The launchd service manager must implement real registration. `Enable` runs `launchctl bootstrap`
with the exact root-owned plist, `Disable` runs `launchctl bootout`, and rollback restores the prior
registration. Replace bare service strings in the runtime manifest with bounded native service
descriptors when the manager needs a definition path. Status continues to verify the running
executable against the active release.

Change root bootstrap verification, source-set storage, worker paths, and attestation checks to run on
macOS. The macOS release is unsupported until a real host test applies, restarts, reboots, repairs,
and removes every selected service combination.

## Current-account isolation

A current-account connection is supported because users may want unYOLO policy without a separate
Unix account. The review and verification distinguish:

- `separate`: the agent account is not the approver and is not administrator-equivalent
- `container`: the agent runs in a container without host administration or Docker control
- `remote`: the agent is on another machine
- `reduced`: the agent shares the current account or another administrator-equivalent identity

`reduced` can report a working connection but cannot report operating-system credential isolation.
The installer requires a dedicated warning confirmation. It is never the recommended choice for a
complete local setup.

## Encrypted network transport

Remote machines and Docker Desktop require an encrypted network transport. Add `tls://host:port` to
`transport/endpoint`.

### TLS rules

- TLS 1.3 is required.
- Plain non-loopback TCP remains invalid.
- Each installation has a root-owned local CA.
- Each broker has its own server key and certificate with the reviewed DNS or IP subject names.
- Broker keys are readable only by that broker's service account.
- Clients pin the installation CA and still authenticate with a distinct broker client secret.
- Client configuration contains the CA path and expected server name.
- Git integration writes origin-scoped CA settings and never changes global TLS verification.
- Certificates are checked during doctor and setup verification.
- Repair renews server certificates before expiry without changing the CA.
- Changing the reachable name or CA creates a reviewed connection update.

Add `internal/host/pki` to plan and apply certificate resources. Root generates the CA key and server
keys with `crypto/rand`; key bytes never enter the unprivileged plan. The plan binds subject names,
key algorithms, file ownership, and renewal policy. Apply backs up existing certificate files,
generates or renews as reviewed, and restores them on transaction failure. The public CA certificate
is included in client bundles; private keys remain in their owning service directories.

Add TLS listener wrapping in the shared transport package and use it from every broker. TLS settings
remain provider-neutral; each broker keeps its own listener, key, process, and audit stream.

## Remote pairing V1

Add the canonical wire schema under `protocol/pairing/` and a separately released
`unyolo-pairing` process. The pairing process has a separate key and process identity. It has its own listener and state
directory plus a release component and audit events. It cannot read provider credentials or broker state.

### Invitation

The server-side command creates a single-line invitation:

```text
unyolo-pair-v1.<base64url payload>
```

The payload contains:

- pairing endpoint URL
- pairing ID
- 256-bit random bearer token
- the public installation CA certificate and its SHA-256 fingerprint
- expected server name
- expiry

The root state stores only the token hash. Invitations expire after 10 minutes by default, can be
shortened, are accepted once, and are revoked when the setup session is cancelled. The connection
bundle is stored in a separate pairing-service directory with mode `0600`; it contains generated
client secrets but no provider or approver credential.

### Claim and activation

Remote and Docker pairing use a durable two-phase exchange:

1. The server wizard reviews the connection and creates a pending bundle. Broker client stores are
   unchanged.
2. The client opens TLS without sending the token and verifies the server certificate with the CA
   carried in the invitation, its fingerprint, and the expected name.
3. The client submits the token to `POST /v1/pairings/{id}/claim` and receives one bounded bundle.
4. The client validates every broker identity and TLS setting, including the CA, and writes its files
   atomically.
5. The client sends `ready` and waits. The pairing service records readiness but has no privilege to
   edit broker stores.
6. The local server wizard, or a resumed server session, observes readiness and starts a fresh root
   plan that installs the reviewed client entries and restarts affected brokers.
7. The server records `active`; the client performs authenticated discovery plus one allowed and one
   denied operation and then sends `verified`.
8. Both sides record completion and the pairing service erases the bundle.

A server wizard may remain attached while the client claims, but correctness cannot depend on that
process staying alive. `unyolo setup --resume` continues a ready pairing from durable state. A claim
that is ready but not activated expires after one hour by default and is removed without changing a
broker. Cancellation before activation removes the pending bundle. Cancellation after activation
uses a reviewed connection-removal plan.

The pairing service hashes high-entropy tokens with SHA-256, compares in constant time, never logs
headers or bodies, and returns `410 Gone` after claim, expiry, or revocation. It exposes a protected
local status interface to the server wizard and cannot execute root commands.

The connection bundle contains client credentials and CA certificates only. It contains no provider
credential, executable, policy authority, or approver credential. Provider policy and admission are
compiled for the pending client during review but become active in the same root plan that installs
the broker client entry.

## Docker agent connections

Docker support depends on encrypted network transport unless the selected engine and platform pass a
real Unix-socket mount test. The default cross-platform path uses TLS and pairing.

### Compose-managed agent

Add `deployment/container` with a Docker CLI runner. It uses an existing `docker compose`; the
installer never installs Docker or starts the daemon.

For a Compose project, the installer:

- runs `docker compose config --format json` and identifies one exact service
- generates an override in the installation directory
- adds a one-shot verified `unyolo-client-init` service that claims the invitation
- stores client config in a named volume
- stores each secret as a mounted secret file, never inline environment text
- makes the agent service depend on successful client initialization
- adds no Docker socket mount
- pins every unYOLO helper image by digest
- shows the exact project and service that will be recreated

Apply writes the override and runs the init service through the pending pairing flow. After the init
service reports ready, the server activates the broker entries and recreates only the selected agent
service. Failure before activation restores the previous override. Failure after activation also
runs the reviewed server-side connection-removal plan before restoring the previous service.

For an arbitrary standalone container, setup generates exact mounts and arguments and waits for the
user to recreate the container. It does not mutate or replace an untracked running container. The
path is complete only after the recreated container passes the same real request checks.

### Docker security checks

Verification fails when:

- the agent receives the Docker socket
- provider credential or broker state paths are mounted
- client secret files are writable by another service
- the container runs privileged or with host PID, user, or network namespaces without an explicit
  unsupported-path stop
- an unpinned helper image is used
- authentication succeeds from a service other than the selected agent service

## Docker credential services

Publish one official, multi-architecture image per broker and one image for the pairing service.
Each image contains one process and runs as its own fixed nonroot identity. Images are built by the
release workflow, pinned by digest in generated Compose, and carry SBOM and build attestations.

The generated Compose project gives each broker:

- its own state volume
- its own provider credential secrets
- its own client and approver secret stores
- its own listener and health check
- no Docker socket
- no mount from another broker's state or credentials

The Docker deployment backend plans `config`, `pull`, `up`, restart, rollback, and `down` as explicit
actions. Removal keeps state and credential volumes by default. **Remove credentials and data** is a
separate destructive confirmation that names every volume.

Docker credential-service support is released separately from Docker agent support. Neither choice
appears until its own real Compose lifecycle tests pass on Linux and macOS Docker hosts.

## Provider enrollment

Provider setup adapters own their questions and secret metadata. The shared wizard renders the
questions and keeps the copy rules.

### GitHub

Production setup offers GitHub App credentials. It asks for the App ID, private key file, webhook
secret, and optional OAuth client credentials needed for user enrollment. Development token fallback
stays under advanced development options and cannot enter a production plan.

The adapter parses the private key, validates nonsecret IDs, and performs a bounded authenticated App
probe after service start. It labels every file in plain language and links to the GitHub App setup
instructions.

### Hugging Face

Setup asks for a purpose-scoped Hugging Face token through a hidden prompt or an explicit file path.
It never copies a token from another local credential store without a separate named choice and
confirmation. The adapter identifies the target account, validates the token with one bounded Hub
request, and states the selected policy preset in plain language. A future device flow may replace
manual token entry only after Hugging Face provides and the repository tests that exact flow.

### Approved local commands

Setup explains that this service runs only root-owned catalog entries. It shows the exact command
catalog and policy summary. It never offers arbitrary shell execution.

### Client and approver secrets

unYOLO generates client and approver secrets. The user supplies only upstream provider credentials
and optional third-party integration credentials. Friendly labels replace raw slot names in the
normal flow; technical details retain the exact slot IDs.

## Reconfigure, repair, and remove

### Reconfigure

`unyolo setup` detects the default installation and offers Review or change this installation. It
loads `installation.json`, applies edits, recompiles to a fresh staging directory, and shows the
diff.

Publication and host apply form one recoverable user-level transaction. Setup writes a marker,
atomically moves the previous installation directory to a backup, publishes the staged directory,
and then starts root apply. A failed or cancelled apply rolls back the host transaction and restores
the previous directory. A successful apply syncs the new directory and removes the backup. Resume
reads the marker and finishes or restores the interrupted side before accepting more edits.

Adding or removing a provider, connection, approver, or integration uses this path. A changed answer
invalidates all downstream plans and secret requirements.

### Repair

Repair recompiles the same installation record, plans and applies the result, then runs real
verification. It does
not widen policy, rotate retained credentials, or replace state unless the reviewed plan names that
action.

### Remove

Removal has two confirmations:

1. remove services, generated client files, group memberships, and installation-owned accounts
2. optionally remove provider credentials, broker state, audit data, Docker volumes, and the local CA

The first action uses the ownership receipt and retains changed or preexisting resources. The second
lists every destructive path and volume. Existing agent accounts are never deleted. Managed accounts
are deleted only when their identity and remaining home contents match the receipt.

The installed user CLI remains unless the user separately chooses **Remove the unYOLO command**.

## Implementation slices

Each slice is a coherent pull request or a small series of pull requests. Main must stay buildable and
tested after every merge. New setup choices remain hidden until their complete vertical slice passes.

### Slice A: intent and session foundation

Files:

- add `setup/intent/`
- add `setup/installation/`
- add `protocol/setup-intent.schema.json`
- replace `deployment/session/session.go` V1 fields and tests
- add strict examples and schema agreement tests

Acceptance:

- every valid goal round-trips
- every invalid cross-field combination is rejected
- persisted state contains no secret-like keys or values
- old session fixtures are rejected
- `default` is selected without a prompt when no installation exists

### Slice B: wizard and copy

Files:

- add `setup/wizard/`
- add `setup/copy/`
- refactor `deployment/flow/`
- refactor `internal/terminal/setup/`
- reduce `cmd/unyolo/setup.go` to orchestration

Acceptance:

- complete menu content is visible for the current provider list
- long menus show hidden-item counts
- Back and Edit navigation plus Cancel, resume, or discard work in visual and accessible modes
- text inputs pass tier-one keybinding tests
- normal transcripts contain none of the forbidden internal terms
- command-only setup activates the checked CLI and performs no administrator work

### Slice C: signed capabilities

Files:

- extend `internal/host/bundle/manifest.go` V1
- extend `deployment/provider/` V1 and schemas
- add `setup/capability/`
- update release descriptors and `internal/tooling/release/`
- update bootstrap output and setup release context

Acceptance:

- offered choices equal the intersection of signed and live capabilities
- resume invalidates a changed capability snapshot
- macOS never enters a Linux plan
- temporary PATH instructions disappear from normal output

### Slice D: deterministic compilation

Files:

- add `setup/compiler/`
- extend setup-component V1 render exchange in `deployment/api/` and `deployment/component/`
- replace `deployment/profile/template.go` string substitution
- replace provider-combination generation in `internal/tooling/release/deployment_kits.go`
- change root verified-release storage and recompilation checks

Acceptance:

- repeated compilation is byte-identical
- root recompilation rejects every changed generated byte
- selected providers and identities appear in all component resources
- static ownership envelopes still bound paths and services as well as every account and group
- runtime artifacts remain under `deployment-kits/artifacts/`

### Slice E: server-only and multi-client brokers

Files:

- change client authentication in all broker config and HTTP server packages
- change `internal/config/secretfile` to allow an explicitly configured empty managed store
- add named client-store resources to component V1
- update policy and admission compilation for zero or many clients
- update provider renderers and tests

Acceptance:

- each broker starts with zero clients and rejects agent authentication
- GitHub, Hugging Face, and sudo authenticate two distinct clients and two distinct approvers
- audit and policy use the authenticated client ID
- adding or retaining entries and rotating or removing them preserves only reviewed entries
- changed stores restart and pass real authentication checks

### Slice F: Linux native vertical paths

Files:

- add `internal/host/account` Linux backend
- update profile V1 agent targets and identity checks
- add connection transaction steps
- update provider Linux renderers
- update OpenClaw integration rendering
- replace the current `runSetupFlow`

Acceptance:

- command-only and server-only setup plus client-only and complete local setup pass on clean Linux
- current and existing account modes plus managed-account mode behave as specified
- managed rollback removes only unchanged installation-owned resources
- current-account output reports reduced isolation
- GitHub-only, Hugging-Face-only, approved-command-only, and combined selections pass
- an allowed operation succeeds and a denied operation is refused from the real selected account

This slice is the first point where the old fixed wizard is removed from runtime behavior.

### Slice G: lifecycle and ownership receipts

Files:

- add receipt model under `internal/host/deployment`
- add reconfigure and remove commands plus session discard to the existing CLI parser
- add remove planning to component and bundle managers
- update installation compiler and status output

Acceptance:

- add and remove a provider or client without replacing retained credentials
- interrupted reconfiguration recovers or rolls back
- removal preserves changed and preexisting resources
- managed account deletion fails closed when the account or home changed
- optional data removal names and removes only confirmed paths
- the CLI can remain installed after host removal

### Slice H: macOS native backend

Files:

- add macOS account implementation under `internal/host/account`
- remove Linux-only account and group commands from component apply
- add Darwin provider and integration render inputs
- add launchd source files and ownership envelopes to deployment descriptors
- make root bootstrap and privilege paths platform-aware
- add macOS clean-host scripts and reboot verification

Acceptance:

- server-only and client-only flows plus complete local setup pass on real macOS amd64 and arm64
  targets
- existing and managed account flows pass
- launchd services survive reboot
- socket access matches selected account groups
- repair is idempotent
- rollback and removal restore service registration and preserve changed resources

### Slice I: TLS transport

Files:

- extend `transport/endpoint` V1 with `tls`
- add shared TLS listener and client configuration
- change client config V1 and every broker client loader
- add certificate resources and renewal checks to provider profiles
- update Git helpers for origin-scoped CA trust

Acceptance:

- TLS 1.3 succeeds with the pinned installation CA
- wrong CA, name, expired certificate, plaintext downgrade, and missing client secret fail
- every broker and Git data path works over TLS
- local Unix paths remain unchanged
- certificate repair does not rotate client credentials

### Slice J: remote pairing

Files:

- add `protocol/pairing/`
- add `cmd/unyolo-pairing/` and its state package
- add pairing as a release component with a separate account and audit stream
- add server invitation and client claim flows to the wizard
- add pairing cleanup and removal actions

Acceptance:

- one invitation claims once
- expiry, replay, wrong CA, wrong server name, cancellation, and interrupted claim fail safely
- no provider or approver credential enters a bundle
- client publication is atomic
- the remote client performs real allowed and denied requests
- claimed and expired bundles are erased

### Slice K: Docker agent

Files:

- add `deployment/container/`
- add official `unyolo-client-init` image release
- add Compose project inspection, override generation, apply, rollback, and verification
- add Docker client targets to intent and installation compilation

Acceptance:

- a Compose agent claims its connection and persists configs in the intended volume
- no Docker socket or provider credential is mounted
- service recreation is limited to the reviewed service
- failure restores the previous override and service
- Linux and macOS Docker hosts pass the real agent request tests

### Slice L: Docker credential services

Files:

- add official per-broker Dockerfiles and release workflows
- add Docker credential-service compiler and lifecycle backend
- add provider Compose fragments and secret declarations
- add Docker removal and volume-retention receipts

Acceptance:

- every broker runs in a separate image, process, state volume, and credential domain
- image digests, SBOMs, and build attestations are recorded
- server-only and complete Compose setups pass
- restart, upgrade, rollback, repair, and removal pass
- destructive volume removal requires the separate confirmation

### Slice M: release and documentation

Files:

- update CLI help, website instructions, host documentation, and release notes
- update public screenshots and terminal transcripts
- remove current-release limitation notices only for paths that shipped
- publish the next immutable release

Acceptance:

- the public command exercises every displayed choice on its real target
- Linux and macOS native release assets pass
- Docker image manifests include amd64 and arm64
- public client-only remote pairing passes from a separate machine
- the live website describes exactly the released behavior

## Test matrix

Every displayed path requires the following evidence:

| Path | Unit | PTY | Clean apply | Real client | Rollback | Remove | Reboot or restart |
| --- | --- | --- | --- | --- | --- | --- | --- |
| Command only | Yes | Yes | Yes | Not applicable | Yes | Yes | Not applicable |
| Linux native server only | Yes | Yes | Yes | Auth rejection with zero clients | Yes | Yes | Yes |
| Linux current account | Yes | Yes | Yes | Yes | Yes | Yes | Yes |
| Linux existing account | Yes | Yes | Yes | Yes | Yes | Yes | Yes |
| Linux managed account | Yes | Yes | Yes | Yes | Yes | Yes | Yes |
| macOS native server only | Yes | Yes | Yes | Auth rejection with zero clients | Yes | Yes | Yes |
| macOS current account | Yes | Yes | Yes | Yes | Yes | Yes | Yes |
| macOS existing account | Yes | Yes | Yes | Yes | Yes | Yes | Yes |
| macOS managed account | Yes | Yes | Yes | Yes | Yes | Yes | Yes |
| Remote pairing | Yes | Yes | Server and client | Yes | Yes | Yes | Service restart |
| Docker agent | Yes | Yes | Compose apply | From container | Yes | Yes | Container restart |
| Docker services | Yes | Yes | Compose apply | Yes | Yes | Yes | Container restart |

Native tests cover amd64 and arm64 release assets. PTY tests cover 60, 80, and 120 columns, visual and
accessible modes, color and no-color output, terminal EOF, Ctrl+C, and every Back/Edit transition.

A complete provider path includes real startup, upstream credential validation, client
authentication, one allowed request, one denied request, audit evidence, restart, repair, and removal.
Mocks, builds, and health endpoints support this evidence but cannot replace it.

## Local quality gates

Every code slice runs with `GOWORK=off`:

```sh
go fmt ./...
go vet ./...
go test ./...
go test -race -timeout 20m ./...
./scripts/check-go-coverage.sh
golangci-lint run
govulncheck ./...
gitleaks git --no-banner --redact .
slophammer-go check .
```

Relevant slices also run:

```sh
./scripts/check-architecture.sh
./scripts/check-github-generated.sh
./scripts/check-sql.sh
pnpm check
pnpm test
pnpm build
pnpm --filter openclaw-unyolo test:browser
pnpm --filter openclaw-unyolo test:package
```

Shell changes run syntax checks and ShellCheck when available. macOS and Docker slices add their real
platform scripts. No mutation testing runs unless explicitly requested.

## Plan review record

The plan was reviewed in four passes against the current code and the guided installation contract.

**Architecture pass.** The first draft did not fully separate durable installation state from
generated deployment files. It also lacked a path for a server with zero clients, GitHub
multi-client authentication, and independent root verification of dynamic output. The revised plan
adds one installation record, deterministic compilation, named client stores, and two explicit root
input kinds.

**Platform and security pass.** The next pass found that the existing launchd manager did not
register new plists, macOS account creation was still undefined, TLS key generation had no
transaction owner, and a CA fingerprint alone was insufficient bootstrap material. The revised plan
adds real launchd bootstrap and bootout behavior, exact hidden-account rules, a root PKI planner, and
the public CA certificate in pairing invitations.

**Lifecycle and UX pass.** The third pass found that provider secrets were collected too early,
reconfiguration could leave host state without a published source after a crash, remote and Docker
claims could leave active orphan credentials, and approver credentials were still modeled as a
single value. The revised plan moves secret collection after plan approval, adds a recoverable
user-level publication transaction, uses pending two-phase pairing, and gives every broker separate
multi-client and multi-approver stores.

**Traceability pass.** The final pass checked every user choice, platform path, failure boundary,
removal rule, test row, and completion claim against `GUIDED_INSTALLATION.md`. No material design gap
remains. Implementation may still stop at one of the explicit blocked conditions below. A blocked
path stays hidden, and no weaker fallback is added.

## Review checklist

Before implementation begins, the plan must answer yes to each item:

- Does every user choice map to one validated intent state?
- Can every displayed choice be derived from signed and live capabilities?
- Is there one durable nonsecret source for server reconfiguration?
- Can server-only setup run with zero clients?
- Can several clients be added, rotated, and removed without sharing secrets?
- Can current-account success avoid claiming operating-system isolation?
- Can root independently reproduce every dynamic generated file?
- Can macOS account, launchd, path, and rollback behavior run without Linux commands?
- Can Docker complete without a Docker socket or provider credential mount?
- Can remote pairing resist plaintext downgrade, replay, wrong-server, and token-log failures?
- Can every apply step roll back or stop with a named manual recovery action?
- Can removal distinguish created, preexisting, and changed resources?
- Does every completion claim include a real request from the selected account, container, or remote
  machine?
- Does the normal transcript avoid internal deployment terms?
- Are unsupported choices absent?

## Blocked stop conditions

Stop a slice and report the evidence when:

- the target platform cannot provide a native primitive needed by its advertised path
- safe rollback cannot distinguish installation-owned resources from preexisting resources
- a remote path would require plaintext network exposure or unpinned server identity
- Docker integration would require mounting the Docker socket into an agent or broker
- root cannot independently reproduce dynamic configuration from release-attested inputs
- a provider cannot support zero or multiple clients without weakening authentication
- a real end-to-end test cannot run in the target environment

Do not expose the blocked choice, add a compatibility fallback, or mark the path supported from
mocked evidence.

## Completion

The implementation is complete when the public installer shows only supported choices and every
shown path passes its row in the test matrix. The released website and command help must match the
observed behavior. Current limitation notices stay in place for every path that has not passed.
