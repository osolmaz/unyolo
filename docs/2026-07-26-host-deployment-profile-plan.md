# Host deployment profile implementation plan

Date: 2026-07-26

Status: accepted

## Objective

BrokerKit needs one supported workflow that can turn a new host into a working
agent host and keep that host aligned with reviewed configuration. Today the
safe pieces exist, but an operator has to join them manually. Installing a host
like Isengard requires a runtime bundle activation, three provider setup
commands, three client setup commands, Unix group changes, two Git helper
installations, shell startup edits, policy application, an OpenClaw package
installation, service restarts, and several doctor commands.

The normal user experience must begin with one installation command run from a
trusted user's account. BrokerKit then explains the security model, gathers one
choice at a time, creates the deployment profile, shows the exact plan, performs
one narrow privilege transition, and verifies the finished agent workflow.

Add a strict host deployment profile and make `brokerkit system` reconcile it.
A single plan must cover the signed runtime, agent and operator identities,
provider setup, policies, client credentials, Git routing, optional client
integrations, service activation, and end-to-end verification. Reapplying the
same profile must be safe and must either repair drift or explain exactly why it
cannot proceed.

The implementation must preserve BrokerKit's existing process and credential
boundaries. GitHub and Hugging Face keep separate executables, configuration,
credentials, state, listeners, release artifacts, and audit streams. The same
is true for sudo and Telegram as well as client integrations. The host command
coordinates those components through a shared setup protocol. It does not
absorb provider behavior.

BrokerKit is pre-release. Changed V1 formats are replaced in place through a
coordinated fresh configuration deployment. Do not add compatibility readers,
aliases, parallel profile versions, migration commands, or fallback loading.

## Guided setup flow

The primary installation path is one command run from the trusted operator's
normal user account:

```sh
curl -fsSL \
  "https://raw.githubusercontent.com/osolmaz/brokerkit/<verified-commit>/install/bootstrap.sh" \
  | sh -s -- --release brokerkit/v<reviewed-version> setup
```

The URL pins an immutable reviewed commit. The bootstrap script downloads the
matching `brokerkit` release, verifies its checksum and GitHub attestation,
installs it below the current user's home directory, reopens `/dev/tty`, and
executes `brokerkit setup`. The shell script does not collect configuration,
read credentials, invoke `sudo`, or perform host setup. The user-owned binary is
never executed as root.

`brokerkit setup` is an unprivileged guided frontend over the deployment pack,
planner, and transaction described in this document. It asks questions, runs
provider enrollment, writes a nonsecret deployment pack, and renders the final
plan. It never mutates a broker service directly. The final apply uses the same
planner and transaction as an unattended deployment.

Before enrollment, the wizard resolves the exact signed runtime bundle selected
by the pinned bootstrap release. It downloads and verifies the component setup
adapters into a private user cache without activating them. Guided questions
therefore come from the same component builds that the final plan will install.
The generated pack includes that exact manifest and signature plus its public
key.
There is no floating release-channel lookup after setup starts.

### Initiating user

The initiating user is the trusted human operator. The wizard runs with that
user's real UID, home directory, terminal, browser session, and configuration
directory. It refuses to run interactively as root because doing so would
create root-owned user files and lose the identity that should own the setup
session.

The normal secure layout uses a separate Unix account for the agent. The
initiating operator may be an administrator, while the agent account must not
be root or root-equivalent. The wizard defaults to creating a locked
`brokerkit-agent` account and lets the operator choose another name or bind an
existing safe account such as `bob`.

The guided production flow requires the initiating user and agent to resolve to
different UIDs. The wizard also rejects an agent account with `sudo`, `wheel`,
`docker`, `lxd`, `incus`, or equivalent authority. A user with that authority
could inspect or replace broker credentials later, so BrokerKit could not
enforce its stated isolation boundary. Advanced unattended deployments may bind
an existing nonprivileged account, but provider enrollment still runs through a
distinct trusted operator.

The initiating user is trusted to handle provider enrollment during setup. Its
UID is outside the agent process boundary, so a running agent cannot inspect the
wizard's terminal or memory. Secret input uses `/dev/tty` with echo disabled,
bounded locked memory where the platform supports it, immediate zeroing after
transfer, and anonymous read-only file descriptors. Secret bytes never enter
command arguments, environment variables, setup session files, deployment
packs, terminal transcripts, or temporary files.

### Setup screens

The first choice mirrors OpenClaw's QuickStart and Advanced split. `Recommended`
uses a separate managed agent account, local Unix sockets, approval-gated write
policies, and OpenClaw `skills-only`. `Custom` exposes account mode, endpoints,
component selection, and integration trust modes. An existing deployment pack
opens a review-and-repair flow. Recommended mode still asks which providers and
exact resources the user wants; it never turns safe defaults into broad access.

The default flow then uses one guided sequence with safe defaults and progressive
detail:

1. **Preflight.** Show the BrokerKit release, exact runtime bundle, platform,
   current user, network requirements, and security boundary. Authenticate and
   cache the signed setup adapters. Check that the user can perform the later
   privilege step without invoking it yet.
2. **Agent identity.** Create a separate locked agent account or select an
   existing safe account. Show the exact home and shell that BrokerKit will
   manage.
3. **Components.** Select GitHub, Hugging Face, sudo, Telegram approvals, and an
   optional client integration. The recommended local-agent profile selects
   GitHub and Hugging Face providers plus sudo and OpenClaw skills.
4. **Provider enrollment.** Run each selected provider's signed enrollment
   adapter. Browser-based provider flows open from the initiating user's
   session. Manual credentials use hidden input or an operator-selected
   protected file.
5. **Access policy.** Start from each provider's reviewed safe preset. Ask for
   exact repositories, namespaces, branches, command catalog entries, and
   approval behavior. Show separate operation counts for direct access,
   approval gates, and denials.
6. **Approvals.** Configure the protected operator path. Telegram is optional.
   OpenClaw `direct` mode is offered only after its operator trust boundary is
   explained; `skills-only` remains the default.
7. **Agent integration.** Detect a supported OpenClaw installation or offer the
   exact pinned package. Show which user files and processes the adapter will
   own.
8. **Review.** Generate and lock the deployment pack, inspect the host through a
   narrow privileged worker, and show the canonical plan. Policy changes,
   credential actions, account and group changes, services, restarts, and real
   verification targets are visible before confirmation.
9. **Apply.** Ask for one explicit confirmation bound to the plan digest. The
   privileged worker applies that exact plan and streams bounded progress back
   to the user process.
10. **Verification.** Run the complete host and agent checks. Finish with the
    deployment path, active bundle, configured components, and commands for
    later verification or reconfiguration.

Every screen supports help and cancellation. The operator may go back until the
privileged worker starts. Going back after plan generation cancels that worker
and invalidates the plan. There is no host mutation before the final
confirmation. A provider enrollment action that creates or changes an upstream
credential requires its own explicit confirmation and must define cancellation
cleanup. When automatic cleanup cannot be proved, the wizard shows the exact
remaining provider resource and blocks completion until the operator resolves
it.

### Terminal presentation

Use OpenClaw's onboarding as the interaction model. The default renderer is a
colored, Clack-like inline UI. BrokerKit should feel like the same family of
guided terminal flow while keeping its own copy, colors, security warnings, and
implementation.

The visible behavior follows these OpenClaw patterns:

- an `intro` starts one connected guide rail and an `outro` closes it.
- focused questions use the BrokerKit accent color; completed answers collapse
  into dim text so the terminal keeps a readable setup history.
- notes present security explanations, existing configuration, policy previews,
  and repair instructions without pretending they are questions.
- selects show a label and muted hint. Long provider or repository lists are
  searchable across every token in the label, hint, and stable value.
  Multiselects show selected and unselected states clearly.
- text fields show placeholders and validation beside the active field. Secret
  fields use a fixed mask while editing and collapse to `configured` after
  submission, so neither content nor length remains in scrollback.
- confirms use an explicit vertical Yes/No choice for high-risk actions. The
  safe option receives focus by default.
- progress work uses an inline spinner with a changing bounded label. The label
  is width-aware and cannot leak extra lines when the terminal shrinks. Terminals
  that support OSC progress receive the same safe label. Success and failure
  have stable symbols, as do warnings, and each uses a semantic color.
- navigation help stays visible below the current question. Left and right move
  between completed steps when safe. Arrow keys move within options, and space
  selects items. Enter confirms. Ctrl-C cancels.

Keep flow logic behind a BrokerKit-owned `SetupPrompter` interface modeled on
OpenClaw's `WizardPrompter`. The interface owns `intro`, `outro`, `note`,
`select`, `multiselect`, `text`, `secret`, `confirm`, `deviceCode`, `openURL`,
and `progress`. Setup and provider code depend only on this interface. Terminal
rendering, remote setup sessions, deterministic tests, and future graphical
clients can implement the same contract without changing setup decisions.

Use `charm.land/huh/v2` for the default Go renderer. Huh provides form groups,
selects, multiselects, validated input, confirms, themes, a spinner package,
and a first-class accessible mode. It removes the raw-mode, resize, key handling,
cursor cleanup, and screen-reader work that a custom prompt implementation
would otherwise own. BrokerKit supplies a small Huh adapter and theme instead of
forking Huh or exposing Huh types in domain packages.

The Huh renderer runs inline and must not use the alternate screen. Use a
BrokerKit palette with named accent, success, warning, error, muted, and heading
styles. Honor `NO_COLOR` and `FORCE_COLOR`. `--accessible` and
`BROKERKIT_ACCESSIBLE=1` enable Huh's simplified screen-reader mode. A dumb
terminal falls back to the accessible renderer after confirmation.

Do not use a Go Clack clone solely to copy Clack's appearance. Huh has broader
maintenance, testing, accessibility, and terminal support. Pin one reviewed Huh
V2 release and inspect its module graph, license, supported Go version,
cross-platform behavior, binary-size cost, and vulnerability report before
landing it. First build a focused renderer spike covering option hints,
tokenized search, multiselect, horizontal step navigation, fixed secret
submission text, dynamic width-aware progress, cancellation, and accessible
mode. If a requirement cannot be implemented through Huh's public API, use a
small BrokerKit-owned Bubble Tea component behind `SetupPrompter`; never import
Huh internals or maintain a fork. The currently reviewed Huh V2 source requires Go 1.25.8, while
BrokerKit declares Go 1.25.7 and builds with Go 1.26.5. The implementation must
align the declared Go patch level or select a maintained compatible Huh release
explicitly.

The review screen groups the plan under Identity, Providers, Access, Services,
and Verification. It shows safe summaries and the exact plan digest instead of
printing raw JSON. The user can save the canonical JSON plan separately. The
final outro reports each verified component, the deployment profile path, and
one command for status or repair.

Cancellation is a terminal outcome with exit code `1`, never successful setup.
Every exit path restores cursor visibility, echo, raw mode, input state, and any
running spinner. EOF follows the same cancellation path. A plain log renderer
remains available for golden tests, but automation continues to use the
declarative profile commands instead of answering interactive prompts.

### Provider-owned enrollment

The root wizard owns the sequence and rendering. Each provider owns its own
questions, validation, browser enrollment, safe policy choices, and resulting
component profile.

Add `brokerkit.io/setup-flow/v1` as a closed conversation protocol between the
wizard and signed setup adapters. It supports a small fixed set of steps:

```text
note
select
multiselect
text
secret
file
confirm
device_code
progress
open_url
review
```

A step has a stable ID, bounded title and help text, required status, safe
default, and type-specific validation. The wizard returns nonsecret answers as
closed JSON. `file` selects a nonsecret profile input. A credential file is a
`secret` source and returns only a one-use descriptor, so its path is not an
answer. Secret answers are represented in session state only as an incomplete
or supplied slot. A `device_code` step shows one temporary provider code and
expiry through structured UI; the code is never persisted or included in a
terminal transcript fixture.

The protocol does not accept HTML, scripts, shell commands, arbitrary
executables, environment fragments, or provider request bodies. `open_url`
accepts an HTTPS URL from the owning signed adapter and may bind one loopback
callback managed by that adapter. Provider OAuth, GitHub App enrollment,
Hugging Face token inspection, and Telegram checks remain provider code.

Adapters are deterministic over completed nonsecret answers and installed safe
metadata. They return a complete provider profile and policy file for the
deployment pack. They perform no host service or policy mutation during the
guided phase. Provider enrollment side effects follow the explicit confirmation
and cleanup rule above. The later host plan validates adapter output again
through setup-component V1.

### Setup session

The wizard stores resumable nonsecret progress at:

```text
~/.local/state/brokerkit/setup/<session-id>.json
```

The file is mode `0600` and uses a closed `brokerkit.io/setup-session/v1`
schema. It records the BrokerKit build, selected deployment name, completed
step IDs, nonsecret answers, generated file digests, current phase, and last
safe error. It contains no credential value, secret source path, OAuth code,
provider response, operator credential, or privileged plan body.

`brokerkit setup` resumes the newest compatible incomplete session after
confirmation. `brokerkit setup --resume <session-id>` selects one explicitly,
and `--new` starts over. An interrupted credential step must be repeated.
Successful provider credentials already installed by a committed privileged
transaction are discovered through safe status checks and are never read back.

The generated deployment pack is stored by default at:

```text
~/.config/brokerkit/deployments/<deployment-name>/
```

That directory is the local desired-state source and contains no secrets. The
final screen explains how to move it into a private control-plane repository.
BrokerKit stores only the applied pack digest and recovery state under the host
state directory, so it does not silently create a second desired-state copy.

### Privilege boundary

The wizard stays unprivileged through enrollment and profile generation. It
asks for `sudo` only after the nonsecret profile is complete and the operator is
ready to inspect protected host state.

The privileged phase must execute a root-owned verified worker. It never runs
the user-local `brokerkit` binary with `sudo`. On a fresh host, the wizard asks
`sudo` to run the immutable bootstrap script from the same pinned commit. That
root bootstrap independently downloads and verifies the matching host command,
installs it under a root-owned immutable directory, and execs:

```text
/opt/brokerkit/bootstrap/<build-id>/brokerkit \
  system setup-worker --protocol-stdio
```

The bootstrap and worker run in one `sudo` process, so the normal flow still has
one operating-system authentication prompt. On later runs, the wizard invokes
the matching root-owned worker directly after verifying its recorded build and
file identity.

The user-facing wizard starts `sudo` with anonymous stdin and stdout pipes.
`sudo` obtains authorization from the controlling terminal, then the worker
uses a bounded framed protocol on those pipes. This avoids relying on
platform-specific file-descriptor preservation through `sudo`. The wizard sends
the immutable deployment snapshot and one-use credential-slot frames. The
worker verifies its root-owned executable path, the `sudo` invoking UID,
protocol bounds, profile, signatures, credential input, and current host state.
It computes the canonical plan and returns the redacted plan to the user
process.

The worker may remain alive for a short fixed review deadline. During that time
it accepts only `apply <exact-plan-digest>` or `cancel`. Before mutation it
rechecks every observed-state fingerprint. It cannot execute a profile-supplied
command, reopen a user-selected secret path, change the plan, or extend its own
deadline. This design normally requires one operating-system authentication
prompt without keeping a privileged daemon installed.

If privilege is unavailable, the wizard still writes and locks the deployment
pack. It stops with a command that a trusted administrator can run against the
same pack. The setup session remains resumable and does not report the host as
installed.

### Guided and unattended parity

The wizard is a profile authoring client. All mutation goes through
setup-component V1, the canonical host planner, and the durable host
transaction. Tests must prove that a profile generated interactively produces
the same plan as that profile passed directly to `system plan`.

Automation uses the declarative commands below. There is no `--non-interactive`
branch inside the wizard that implements setup again. A CI system generates or
checks a deployment pack and calls `system plan`, `system apply`, and `system
verify` directly.

## Declarative workflow

A deployment is a directory with one entry file and referenced nonsecret
configuration:

```text
isengard/
├── deployment.json
├── runtime/
│   ├── manifest.json
│   ├── manifest.sig
│   └── release.pub
├── components/
│   ├── github.json
│   ├── huggingface.json
│   ├── sudo.json
│   └── telegram.json
├── policies/
│   ├── github.json
│   ├── huggingface.json
│   └── sudo.json
├── catalogs/
│   └── sudo.json
└── integrations/
    └── openclaw.json
```

The normal workflow is:

```sh
brokerkit system profile lock --profile ./isengard
brokerkit system validate --profile ./isengard
sudo brokerkit system plan \
  --profile ./isengard \
  --output /tmp/isengard-plan.json
sudo brokerkit system apply \
  --profile ./isengard \
  --expect-plan sha256:<reviewed-plan-digest> \
  --secret-file github-app-key=/run/brokerkit-secrets/github-app-key.pem \
  --secret-file github-webhook-secret=/run/brokerkit-secrets/github-webhook-secret \
  --secret-file huggingface-token=/run/brokerkit-secrets/huggingface-token \
  --secret-file telegram-token=/run/brokerkit-secrets/telegram-token
sudo brokerkit system verify --profile ./isengard
```

`profile lock` updates referenced-file digests after an operator edits the
pack. `validate` checks the locked pack without inspecting the host. `plan`
resolves the pack and compares it with the running host. `apply` accepts only
the exact plan the operator reviewed. `verify` runs host checks and real client
checks under the configured agent identity.

An unchanged apply verifies the current installation and reports a no-op. It
does not rewrite credentials, restart healthy services, regenerate policy, or
change timestamps merely because the command ran again.

## Current implementation

BrokerKit already has most of the required primitives:

- `brokerkit system install`, `upgrade`, `status`, `doctor`, and `rollback`
  activate signed immutable runtime bundles.
- Provider setup commands create service users, config directories, state
  directories, access groups, credentials, and policies. They also create
  sockets and systemd or launchd definitions.
- `setup client` writes one private client file into an agent home.
- GitHub and Hugging Face install scoped Git URL rewrites and credential
  helpers.
- The shared service package validates trusted paths and renders hardened
  systemd units.
- Provider doctors verify policy, credentials, upstream access, and isolation.
- The control-plane repository stores reviewed nonsecret policy and a redacted
  snapshot of Isengard.
- The OpenClaw package carries BrokerKit skills and the optional approval UI.

The missing piece is a durable desired-state contract above these commands.
Each current setup command plans and mutates one component. Nothing binds all
component inputs into one reviewed digest, establishes the agent account before
services start, guarantees that the live agent process received new Unix group
membership, or verifies the complete client workflow after activation.

Client discovery is also too dependent on shell startup files. The current
`client.env` files must be sourced into every process. A long-running OpenClaw
process can therefore have correct files and current account membership while
still lacking the environment or supplementary groups needed to reach an Agent
V1 socket. The recent GitHub pull-request socket failure on Isengard is an
example of that gap.

## Design decisions

### One deployment pack

Use one local deployment pack as the host's desired state. The pack contains
strict JSON and referenced files. It has no inheritance, remote includes,
templates, variable substitution, arbitrary extension maps, executable hooks,
or merge semantics.

JSON matches BrokerKit's existing closed-schema tooling and avoids another
configuration dependency. Every object rejects unknown fields. Every referenced
file is opened relative to the pack root, checked for path escape and symlinks,
read into an immutable snapshot, and verified against its declared SHA-256
digest before planning starts.

The runtime receives the resolved snapshot. It does not reopen profile files
during apply or verification. This prevents a plan from being reviewed against
one set of bytes and applied against another.

### Desired state and observed state

The deployment pack is the only desired-state input. Installed files, service
units, account databases, activation records, and running processes are
observed state. A redacted export may record observed state for review, but an
export never becomes policy input and never contains credentials.

Policy files in the pack are complete provider policies. Provider setup does
not merge them with a live policy, retain unknown local rules, or regenerate a
broader preset during an upgrade. An operator may use a provider command to
render a preset into the pack before review. The reviewed file remains the
complete source applied to the host.

This removes the rule-ownership ambiguity that currently requires the private
`control` script to separate managed rules from local overlays.

### Component ownership

The root deployment loader understands host identity, runtime bundle
references, component identities, agent bindings, operator bindings, file
references, and ordering. It treats provider and integration profiles as
opaque digest-bound documents.

Each component owns its setup profile and validates it through its own code:

- GitHub owns GitHub App, user-enrollment, or development credential slots. It
  also owns Git endpoints, webhook settings, and `scope.json`.
- Hugging Face owns token slots, Xet settings, Git endpoints, and `scope.json`.
- sudo owns its exact command catalog, execution settings, and `policy.json`.
- Telegram owns bot configuration and Operator V1 routes.
- The OpenClaw package owns plugin installation and plugin configuration.

Shared root packages must not import provider packages. `brokerkit` invokes the
exact setup adapter declared by the signed runtime manifest. The adapter is
loaded from the staged bundle by absolute path, receives a closed setup request
on a private file descriptor, and returns a closed redacted response. The host
never executes a command name, path, argument, or environment value supplied by
a profile.

### Shared setup protocol

Add `brokerkit.io/setup-component/v1` as the common protocol between the host
command and a bundled component. It supports four fixed actions:

```text
plan
apply
verify
rollback
```

A plan response identifies managed files, directories, accounts, groups,
services, sockets, client artifacts, credential slots, restart requirements,
and safe before-and-after digests. The shared schema bounds every collection
and string. Provider-specific facts stay in a provider-owned closed section
that the root stores for diagnostics without interpreting.

The host validates declared resources against the component's registered
ownership envelope. A GitHub adapter may manage `/etc/gh-broker`,
`/var/lib/gh-broker`, its service units, its access groups, and its client files.
It cannot claim `/etc/hf-broker`, another service, an arbitrary home path, or an
executable outside the staged bundle.

Setup adapters run with a minimal environment. Credential slots arrive as
already-open read-only file descriptors. Adapter output cannot contain secret
bytes, raw environment values, upstream responses, or copied credential
metadata.

A descriptor binding uses `--secret-fd name=3`. The host duplicates the supplied
descriptor into its private child descriptor range and closes it after the
owning adapter finishes. Apply rejects duplicate slots, shared descriptors,
terminal descriptors, writable descriptors, and unbounded streams.

### Credential slots

The deployment pack names logical credential slots and contains no secret
values or secret source paths. The apply invocation binds a slot to a protected
file or an inherited read-only descriptor:

```sh
--secret-file github-app-key=/run/brokerkit-secrets/github-app-key.pem
```

The host opens each source without following symlinks, verifies ownership and
mode, and passes an inherited descriptor to the owning component. The source
path does not enter the plan, transaction journal, audit log, or component
diagnostics.

On a fresh host, every required slot must be supplied. On an existing host, an
omitted slot preserves the installed credential after the component verifies
that it is present and usable. Supplying a new value for an installed slot is
rejected unless the operator also selects that slot with an explicit rotation
flag. A normal reconcile must never rotate a credential accidentally.

Generated broker client and operator credentials remain provider-owned. The
provider writes them directly to protected server files and the host installs
only the selected client credential into the bound agent home. Operator
credentials are never installed for an agent or client integration unless that
integration profile explicitly declares an operator trust mode.

### Agent and operator identities

An agent entry binds one BrokerKit client ID to one Unix account and a list of
components. Its account mode is either `managed` or `existing`.

`managed` creates a locked local account when it is absent. The profile supplies
an absolute home directory and shell. Account provisioning does not configure a
password, SSH key, login token, workspace, or application data. Reconciliation
never deletes an account or home directory.

`existing` requires the account plus its home and shell to match the profile.
This is the default for an established personal account.

Every operator account must already exist. The agent UID and every service UID
must be distinct. Agent accounts may not be root or belong to a root-equivalent
group such as `sudo`, `wheel`, `docker`, `lxd`, or `incus`. Operator and agent
identities may not resolve to the same UID.

The host creates component access groups before starting any agent runtime. It
adds agents only to Agent V1 groups and operators only to Operator V1 groups.
After a membership change, verification checks the effective groups of the
actual managed agent process. An integration adapter must restart its managed
process or return a blocked result that names the stale process and required
operator action. Reading `/etc/group` alone is insufficient.

### Client configuration discovery

Replace shell-sourced `client.env` with one closed private client document per
broker:

```text
~/.config/gh-broker/client.json
~/.config/hf-broker/client.json
~/.config/sudo-broker/client.json
```

The document keeps the existing V1 client contract and contains the client ID,
Agent V1 endpoint, optional Git endpoint, and broker client credential. It is
owned by the agent and has mode `0600`. Parent directories are real,
agent-owned, and not writable by another user.

Broker CLIs, MCP adapters, and Git credential helpers load this file directly.
Production clients do not depend on inherited shell variables. An explicit
`--client-config` flag selects another file for tests or advanced local use.
Development mode may accept environment configuration, but production startup
must choose one source and reject conflicting sources.

The coordinated deployment removes the old `client.env` files and shell startup
snippets after every installed client has switched to `client.json`. There is no
fallback reader for the old format.

### Git client setup

GitHub and Hugging Face keep ownership of their URL rewrites and credential
helper configuration. Their setup adapters calculate the intended per-user Git
configuration, compare it with the selected agent's global config, and apply
only provider-owned keys.

The host runs this work under the target UID with a minimal environment and a
verified home directory. Removal or replacement touches only exact keys owned
by BrokerKit. Verification uses ordinary upstream repository URLs and confirms
that the request reached the local broker.

### OpenClaw integration

The OpenClaw package supplies a setup adapter under `plugins/openclaw`. Its
profile pins the package artifact, package digest, supported OpenClaw range,
plugin mode, and managed configuration file. The signed host bundle carries the
adapter and the exact packed npm artifact so installation does not depend on a
mutable registry response.

The adapter runs as the agent account. In `skills-only` mode it installs the
package and verifies that all eligible packaged skills are visible. It receives
no operator credential. `direct` mode declares its operator credential slots
and service restart behavior in the integration profile. `delegated-web` keeps
its current trusted-backend contract.

OpenClaw behavior stays under `plugins/openclaw`. The root host package knows
only that a signed client integration adapter owns a bounded set of user files
and processes.

### Transaction boundary

`system apply` uses one host lock and one durable transaction journal under
`/var/lib/brokerkit-host`. The journal binds:

- the deployment pack digest.
- the canonical plan digest.
- the current and candidate runtime bundle IDs.
- every component setup-plan digest.
- ordered actions and completion markers.
- protected backup locations.
- service state before mutation.
- the active phase and recovery decision.

The host snapshots every managed nonsecret configuration file. A component
that rotates a credential creates its own protected rollback file and returns
an opaque backup handle to the transaction. The credential bytes never enter
host journal JSON, logs, status output, or redacted exports. Every rollback
file retains the original ownership and mode.

Host-wide rollback covers the runtime pointer, component configuration, client
configuration, owned Git keys, service definitions, service enablement, and
service ordering. State replacement continues using the runtime bundle's
existing archive and restore contract.

Some operating-system changes are intentionally persistent. A newly created
agent account, its home directory, and generated provider credentials are not
deleted automatically after a later failure. Group memberships added by the
failed transaction may be removed only when no earlier installation used them
and no running process depends on them. Recovery reports retained resources
plainly instead of claiming that the entire operating system was reverted.

### Service ordering

Planning computes one dependency graph from the runtime manifest and setup
adapters. The apply order is:

1. validate identities, profiles, policies, credential slots, and the current
   installation.
2. stage and authenticate the candidate runtime.
3. create service accounts, access groups, and agent accounts.
4. write provider configuration and credentials without starting services.
5. write agent client configuration and Git settings.
6. install client integrations without starting their managed processes.
7. activate provider sockets and services in dependency order.
8. start Telegram and other consumers after every provider is ready.
9. start or restart agent integrations after their group membership is current.
10. run component and host verification, followed by real-agent verification.
11. commit the activation and transaction records.

Stopping and rollback use the reverse dependency order. A provider must be
ready before a consumer or agent integration is allowed to start.

### Plan review

A production apply requires `--expect-plan`. The plan is canonical JSON with a
SHA-256 digest over the exact resolved pack, observed-state fingerprints, and
ordered actions. It contains no secret value and no secret source path.

Each action records a stable resource identity, owning component, action type,
risk class, current safe digest, desired safe digest, and restart effect. Policy
changes include operation and rule counts plus full-file digests. Credential
actions report only `install`, `retain`, `rotate`, or `remove` for a named slot.

If observed state changes after planning, apply fails with `plan_stale` before
mutation. The operator runs `plan` again and reviews the new digest.

## Deployment profile format

The required entry point is `deployment.json`. A minimal profile for one agent
and one broker is:

```json
{
  "api_version": "brokerkit.io/host-deployment/v1",
  "name": "isengard",
  "runtime": {
    "manifest": {
      "path": "runtime/manifest.json",
      "sha256": "sha256:<64 lowercase hex characters>"
    },
    "signature": {
      "path": "runtime/manifest.sig",
      "sha256": "sha256:<64 lowercase hex characters>"
    },
    "public_key": {
      "path": "runtime/release.pub",
      "sha256": "sha256:<64 lowercase hex characters>"
    }
  },
  "agents": [
    {
      "id": "bob",
      "client_id": "bob",
      "unix_user": "bob",
      "account_mode": "existing",
      "home": "/home/bob",
      "shell": "/usr/bin/zsh",
      "component_ids": ["github"]
    }
  ],
  "operators": [
    {
      "id": "onur",
      "unix_user": "onur"
    }
  ],
  "components": [
    {
      "id": "github",
      "profile": {
        "path": "components/github.json",
        "sha256": "sha256:<64 lowercase hex characters>"
      }
    }
  ]
}
```

The full main-object fields are:

| Field | Required | Meaning |
| --- | --- | --- |
| `api_version` | Yes | Exact deployment profile schema identifier. |
| `name` | Yes | Stable name for this host deployment. |
| `runtime` | Yes | References to the signed runtime manifest and its initial trust key. |
| `agents` | Yes | Nonempty agent identity and client bindings. |
| `operators` | Yes | Nonempty existing operator identity bindings. |
| `components` | Yes | Nonempty component setup profiles. |
| `integrations` | No | Client integration profiles. Omission means no managed integration. |

Names use lowercase ASCII letters and digits, with hyphens allowed between
them. Names are 1 to 64 characters and unique within their collection.
`client_id` follows the shared named-client validation. Unix names follow
platform account rules. Collection order
has no semantic meaning; the loader canonicalizes entries by ID before hashing
and planning.

`api_version` keeps BrokerKit's established API-version vocabulary. Components
also keep the established runtime-manifest term because the deployment includes
provider brokers plus Telegram and client adapters. Provider profiles use
their own closed V1 identifiers.

### File references

Every reference has exactly two fields:

```json
{
  "path": "policies/github.json",
  "sha256": "sha256:0123456789abcdef..."
}
```

Paths use forward slashes and are relative to the directory containing
`deployment.json`. Absolute paths, empty components, `.` components, `..`, NUL,
backslashes, and symlinks are invalid. Referenced regular files must remain
inside the pack and must not be writable by group or other users during a
privileged apply.

The digest covers exact file bytes. There is no newline normalization. A digest
mismatch is fatal. Files are loaded once into a bounded immutable snapshot.

### Agent entries

An agent entry contains:

| Field | Required | Meaning |
| --- | --- | --- |
| `id` | Yes | Stable profile-local identity used by integrations. |
| `client_id` | Yes | Named BrokerKit client written into provider secret files. |
| `unix_user` | Yes | Local account that runs the agent. |
| `account_mode` | Yes | `managed` or `existing`. |
| `home` | Yes | Absolute verified home directory. |
| `shell` | Yes | Absolute root-owned login shell. |
| `component_ids` | Yes | Nonempty set of components available to this agent. |

The host resolves the account and records UID and primary GID as observed state.
UIDs and GIDs do not belong in the portable profile. A deployment may bind
several agent accounts to different component subsets.

### Operator entries

An operator entry contains `id` and `unix_user`. The account must exist before
apply. Provider profiles select operator IDs when a component needs Operator V1
socket access. The main loader rejects an unreferenced duplicate, an agent and
operator UID collision, or an operator binding to a service account.

### Component entries

A component entry contains an ID and one profile reference. Its ID must exist in
the signed runtime manifest and the component must declare a setup adapter.
There is no inline provider configuration in `deployment.json`.

A component profile names referenced policy or catalog files and logical
credential slots. The profile uses provider vocabulary and is validated by the
component adapter during `validate` and `plan`. Provider profile references
follow the same path and digest rules as main-file references.

### Integration entries

An integration entry contains:

| Field | Required | Meaning |
| --- | --- | --- |
| `id` | Yes | Stable integration identity. |
| `kind` | Yes | Setup adapter kind declared by a signed component. |
| `agent_id` | Yes | Agent account that owns the integration. |
| `profile` | Yes | Digest-bound integration profile. |

The first implementation supports `openclaw-brokerkit`. Unknown kinds are
fatal. Future integrations require a signed setup adapter and a reviewed
ownership envelope. A profile cannot introduce an executable path or generic
command hook.

### Format boundaries

The pack must not contain:

- provider credentials or derived credentials.
- broker client or operator secrets.
- Telegram bot tokens.
- passwords, SSH keys, API headers, cookies, or environment dumps.
- runtime state, audit logs, operation records, or database backups.
- remote URLs used as includes.
- executable scripts or arbitrary setup commands.

The pack may contain public signing keys, detached signatures, complete policy,
exact sudo catalogs, public endpoint choices, package metadata, and nonsecret
service settings.

## Command contract

### `brokerkit setup`

`brokerkit setup` launches or resumes the unprivileged guided flow. It requires
an interactive terminal and a non-root initiating user. The command may open a
browser only after showing the exact provider and URL purpose. `--no-open`
prints URLs for remote or headless terminals.

The setup command writes only its private nonsecret session and deployment pack
before final apply. It invokes the fixed privileged worker for protected host
inspection and mutation. `--profile <directory>` starts from an existing pack
and asks only for missing guided choices or credential slots. `--accessible`
selects the screen-reader renderer for the complete session.

`brokerkit setup status` reports incomplete and completed local sessions without
reading host secrets. `brokerkit setup cancel <session-id>` removes an
uncommitted local session after confirming that no host transaction is active.
It never cancels or rolls back a committed host deployment.

### `system profile lock`

`profile lock` resolves every declared file and updates only its SHA-256 field.
It obtains provider-owned reference locations through the staged component
adapter, so root packages do not parse provider profiles. The command performs
no remote fetch, credential lookup, host inspection, or service mutation.

`profile lock --check` is the CI form. It fails when any stored digest differs
from the exact file bytes or when locking would change a profile. Locking writes
files atomically and leaves a normal reviewable Git diff.

### `system validate`

`validate` parses every closed schema, resolves and hashes every file,
validates cross-references, checks the runtime signature, and asks each staged
component adapter to validate its opaque profile. It performs no host mutation
and does not require provider credentials.

Validation output names only the deployment, pack digest, runtime bundle ID,
component IDs, agent IDs, operator IDs, and errors. JSON output uses a closed
schema.

### `system plan`

`plan` requires sufficient privilege to inspect protected installed state. It
loads the same immutable pack snapshot, discovers current BrokerKit resources,
asks every component for a plan, builds the dependency graph, and writes one
canonical plan.

A plan may be `noop`, `install`, `reconcile`, `upgrade`, or `blocked`. A blocked
plan includes evidence and operator action. Missing credentials, unsafe agent
membership, unknown managed files, stale running groups, unsupported runtime
contracts, invalid policy, and state-format mismatch are blocking conditions.

### `system apply`

`apply` reruns planning and compares the result with `--expect-plan`. It refuses
mutation when the digest differs. It then executes the durable transaction and
prints bounded progress records.

Human-readable and JSON output never includes secrets. A terminal error reports
the failed phase, completed rollback actions, retained resources, transaction
ID, and the command needed to inspect recovery status.

### `system verify`

`verify` combines:

- runtime bundle status and digest checks.
- provider service and socket readiness.
- provider policy and credential doctors.
- account and group checks plus path and secret isolation.
- client configuration and Git helper checks under each agent UID.
- effective-group checks for managed agent processes.
- integration-specific checks such as OpenClaw plugin and skill discovery.
- real safe provider reads through the same client path the agent uses.

A provider profile selects the exact harmless verification target. GitHub may
use `git ls-remote` and a typed repository read. Hugging Face may list one
allowed repository. sudo uses a cataloged no-op diagnostic command only when
its policy explicitly allows one. Verification does not create external
resources or send approval notifications.

The command returns `0` only when the configured user-visible workflow passes.
Supporting service health without a successful agent request is incomplete.

### `system export`

`export` writes a deterministic redacted observed-state report. It contains
bundle IDs, component build IDs, contract digests, service states, policy
digests, client IDs, account IDs, owned Git-key digests, integration versions,
and doctor results.

It omits credential contents, credential metadata that could aid misuse,
operation inputs and results, notification destinations, and private state.
The report is evidence for a control-plane repository. It is never accepted as
a deployment profile.

## Interruption and recovery

Every mutation records intent before execution and completion afterward. On
startup, all `system` mutation commands reconcile an unfinished transaction
under the host lock before accepting new work.

Recovery follows the existing bundle rule. A committed and verified candidate
is retained. An uncommitted candidate restores the previous runtime pointer,
configuration snapshots, service definitions, client files, owned Git keys,
and service state. Component adapters receive rollback only for actions they
reported as completed.

Power-loss tests must interrupt every action boundary, including account and
group creation, credential installation, policy replacement, service-unit
write, daemon reload, socket start, provider readiness, client config write,
Git config write, OpenClaw install, and final verification.

A recovery that cannot prove either the candidate or prior deployment healthy
stops all affected consumers and reports `recovery_required`. It does not keep
retrying mutations or select a profile based on partial state.

## Drift and idempotency

BrokerKit owns only resources declared by setup adapters. Drift in an owned
resource appears in the plan. Drift outside ownership is ignored unless it
breaks a security invariant such as a writable parent directory or a
root-equivalent agent group.

File comparison uses content digests and path identity together with ownership
and mode. Service comparison uses normalized unit content, enablement, active
state, and running executable identity. Account comparison uses the resolved UID and GID
along with home, shell, supplementary groups, and active-process groups.

A successful apply stores the deployment pack digest and canonical component
state digests in the activation record. Reapplying the same deployment skips
writes and restarts, then verifies. A new profile digest always produces a new
plan even when its observable result happens to match.

Manual edits to a complete provider policy are drift. Applying the reviewed
profile replaces them atomically after plan approval. There is no dual policy
source or local-rule preservation path.

## Package ownership

Add shared deployment code under root packages that remain provider-neutral:

```text
deployment/
├── api/                 # Closed setup-component V1 request and response types
├── flow/                # Setup-flow V1 steps, answers, and renderer contract
├── profile/             # Pack loader, strict schemas, references, snapshots
├── plan/                # Canonical actions, digest, dependency graph
├── runtime/             # Setup adapter subprocess and descriptor handling
├── session/             # Nonsecret guided setup state and resume behavior
└── transaction/         # Journal, backups, recovery, rollback coordination

internal/host/
├── identity/            # Linux and macOS account/group inspection and setup
├── privilege/           # Narrow setup worker and framed transport
└── deployment/          # system command orchestration and ownership envelopes

internal/terminal/setup/ # Huh renderer, theme, progress, and terminal cleanup
```

Provider implementation remains below its broker:

```text
brokers/github/internal/deployment/
brokers/huggingface/internal/deployment/
brokers/sudo/internal/deployment/
cmd/brokerkit-telegram/deployment/
plugins/openclaw/deployment/
```

`cmd/brokerkit` wires the guided frontend and shared host orchestrator. Provider
binaries expose guided enrollment and setup adapter actions through their
existing `setup` command. Shared packages do not import these provider
packages.

Use the standard library for JSON, hashing, file descriptors, subprocesses,
account lookup, and filesystem work. Reuse BrokerKit's strict JSON and safe
file packages together with the existing service, doctor, and runtime bundle
code.

The terminal renderer is the one justified dependency exception. Import
`charm.land/huh/v2` for fields, groups, accessibility, and its spinner package.
Import `charm.land/lipgloss/v2` only in `internal/terminal/setup` for the
BrokerKit theme. Keep Bubble Tea and Bubbles behind Huh unless a missing
renderer requirement proves that a direct import removes more code than it
adds. This feature does not justify a new configuration framework,
dependency-injection container, RPC framework, or database.

The transaction journal uses BrokerKit's existing local durable storage
conventions. If relational queries or cross-record constraints are required,
use the existing CGO-free SQLite stack with explicit V1 schema replacement.
Do not add a second migration authority.

## Protocol and state changes

Keep these identifiers at V1 and replace their schemas in place where needed:

```text
brokerkit.io/host-deployment/v1
brokerkit.io/setup-flow/v1
brokerkit.io/setup-session/v1
brokerkit.io/setup-component/v1
brokerkit.io/system-plan/v1
brokerkit.io/client/v1
brokerkit.io/runtime-bundle/v1
```

Add canonical JSON Schemas under `protocol/` and generated Go fixtures where
the repository already generates protocol artifacts. The profile, plan, setup
protocol, activation record, and transaction journal each have separate closed
schemas and size limits.

The installed host stores only resolved digests and required recovery state. It
does not copy the deployment pack into runtime state as a second source of
truth. Private transaction backups are removed after the configured rollback
retention period and successful integrity verification.

The client V1 file replacement requires coordinated removal of `client.env`.
Every broker CLI, MCP adapter, Git helper, and setup command changes in the
same release. The packaged skills and tests change with them. Mixed clients
fail with a direct instruction to run the new host deployment workflow. No code
reads both formats.

## Implementation sequence

### Current behavior fixtures

Add tests that freeze the current manual workflow and its gaps:

- each provider setup can create its service and client config independently.
- client commands currently require sourced environment configuration.
- Git setup is a separate user mutation.
- supplementary-group changes do not reach an already-running agent process.
- the host bundle transaction does not own provider configuration.
- the control-plane script must currently merge and apply GitHub rules itself.

Record a redacted Isengard inventory fixture with the current component, account,
group, service, socket, policy, client, Git, and OpenClaw resource shapes. The
fixture contains no live credential or state data.

### Guided setup frontend

Implement the `SetupPrompter` contract, setup-flow V1 types, Huh renderer,
BrokerKit theme, navigation footer, searchable selection, accessible renderer,
inline progress, terminal cleanup, hidden secret input, nonsecret session store,
cancellation, resume, browser opening, and deterministic profile builder.
Start with one fake component adapter and golden pseudo-terminal transcripts.
Prove that secrets never enter session files or renderer output.

Pin Huh and Lipgloss only after checking their licenses, module graph, Go version,
known vulnerabilities, Linux and macOS builds, binary size, cancellation, and
accessible behavior. Record the measured binary-size change in the implementation
PR. Do not fork the libraries or copy OpenClaw's TypeScript renderer.

Add the immutable bootstrap script after the setup binary works from an existing
checkout. The script installs only the verified user-local CLI and then execs
the wizard through `/dev/tty`.

### Profile loader

Implement the deployment pack loader, strict main schema, file references,
digest validation, path confinement, symlink refusal, limits, canonicalization,
and immutable resolved snapshot. Add provider and integration profile handles
without interpreting their contents. Implement `profile lock` and its
nonmutating `--check` mode over the same loader.

Generate the schema and add parser fixtures for every invalid path, unknown
field, duplicate ID, missing reference, digest mismatch, unsafe file mode,
cross-reference failure, and unsupported API version.

### Component setup protocol

Define setup-component V1 and a shared adapter harness. Convert one low-risk
component first, preferably Telegram, and prove plan, apply, verify, rollback,
output redaction, ownership envelopes, timeout, cancellation, malformed child
output, and child crash behavior.

Convert GitHub, Hugging Face, and sudo one at a time. Their existing provider
setup parsers become thin interactive adapters over the same internal setup
implementation. There must be one setup engine per provider.

### Client V1 replacement

Replace `client.env` with strict `client.json` and add automatic loading to all
broker CLIs, MCP servers, Git helpers, and provider clients. Keep explicit
configuration flags for tests and development. Reject ambiguous production
sources.

Update `setup client`, docs, packaged skills, and integration tests. Remove the
shell-source instructions and old parser in the same branch.

### Identity management

Add provider-neutral Linux and macOS account and group planning. Start with
`existing` accounts, then add safe `managed` agent creation. Operator creation,
password management, SSH setup, and account deletion stay outside BrokerKit.

Test root-equivalent groups, UID collisions, symlinked homes, unsafe shells,
existing mismatches, concurrent account changes, stale NSS results, and active
processes with stale supplementary groups.

### Privileged setup worker

Implement the short-lived root worker over bounded framed stdin and stdout.
Bind it to the `sudo` invoking UID, exact root-owned executable, immutable
deployment snapshot, one-use credential frames, review deadline, and one plan digest.
Accept only apply or cancel after planning. Add stale-state rechecks immediately
before mutation.

Test sudo cancellation, authentication failure, parent death, truncated and
repeated secret frames, timeout, malformed messages, repeated approval, a
user-writable worker path, bootstrap replacement, and worker crash. No worker
survives the setup command.

### Host planner

Combine the bundle plan, component plans, identity plan, client artifacts, Git
settings, and integration plan into one canonical action graph. Add plan digest
binding, observed-state fingerprints, stale-plan rejection, ownership conflict
detection, and secret-safe rendering.

No mutation command may bypass this planner.

### Host transaction

Extend the current activation transaction to cover component configuration,
client files, owned Git keys, service definitions, group membership, and
integration artifacts. Add explicit compensation rules for persistent accounts
and generated credentials.

Run failure injection after every step. Verify recovery after process death or
SIGKILL and after a host reboot.

### Provider policies

Move each deployment to a complete policy file in its provider profile. Add
provider validation before mutation and semantic plan summaries. Remove runtime
policy merging and local overlay retention.

Add a provider command that can render a safe starting policy into a deployment
pack for review. Rendering never reads live provider permissions or applies the
result.

### OpenClaw adapter

Package the OpenClaw setup adapter and exact npm tarball in the signed deployment
artifact set. Implement skills-only installation first, including plugin version,
OpenClaw compatibility, packaged-skill hashes, and process restart verification.
Then add direct and delegated-web profiles without moving OpenClaw behavior into
root packages.

### Redacted export

Implement deterministic observed-state export and replace the custom snapshot
logic in the private control-plane repository. Keep the deployment pack and
complete policy files as reviewed inputs. Remove the old control script after
Isengard has completed two clean plan/apply/verify cycles from the new path.

### Verified bootstrap

Add a top-level installer wrapper for the `brokerkit` host command using the
existing release checksum and attestation verifier. The operator pins a reviewed
BrokerKit commit or release for this first executable. The user bootstrap
installs the guided CLI below the user's home. The root phase independently
runs the immutable bootstrap to install the exact verified setup worker below
`/opt/brokerkit/bootstrap`. The worker then installs the signed runtime bundle
and pins the deployment public key.

The user binary installer remains nonprivileged and creates no accounts or
services. The root bootstrap installs only the short-lived worker executable;
it does not configure or start a service. The guided privileged worker and
direct `sudo brokerkit system apply` use the same host setup engine.

## Test strategy

### Unit and conformance tests

Cover strict parsing, canonical hashing, path safety, digest checks, account
validation, ownership envelopes, action ordering, plan stability, stale-plan
rejection, secret-slot handling, client file security, policy replacement,
component protocol bounds, setup-step validation, session resume, privilege
messages, and journal recovery.

Run the same setup-component conformance suite against the GitHub and Hugging
Face adapters. Run it unchanged against sudo and Telegram as well as the
OpenClaw adapter. A provider cannot skip redaction, ownership, rollback, or
verification requirements.

### Guided-flow tests

Run the wizard through pseudo-terminals with fixed adapters. Cover the default
path, every optional component, back and forward navigation, searchable selects,
multiselects, hidden input, inline progress, cancellation, EOF, `NO_COLOR`,
`FORCE_COLOR`, accessible mode, headless URL output, interrupted enrollment,
resume, invalid credentials, policy review, declined plans, stale plans, sudo
denial, root invocation, and completed session cleanup.

Add normalized visual transcript fixtures for 60-, 80-, and 120-column
terminals. Cover dark and light backgrounds where the renderer can detect them.
Assert that the renderer stays inline, wraps notes and option hints, collapses
completed answers, keeps navigation help visible, and restores the cursor and
terminal mode after success, cancellation, validation failure, panic, and
SIGINT.

Before the first release, record the complete recommended flow in real dark and
light terminals at 80 columns and run the accessible flow with a screen reader
or its supported test harness. A human reviews those artifacts for prompt order,
readability, color contrast, wrapping, progress stability, and final-plan
clarity. The artifacts contain fake credentials and disposable provider targets.

Credential canaries must be absent from terminal captures, argv, environment,
session JSON, deployment files, plan JSON, progress records, and error output.
The test harness may inspect the private one-use descriptor to prove that the
owning adapter received the exact bytes.

### Linux integration tests

Use clean disposable VMs because containers alone cannot prove systemd and
user/group behavior. The VM suite also covers sockets, process groups,
daemon reload, reboot behavior, and service ordering. Cover a fresh host, an
unchanged reapply, a policy-only change, one provider upgrade, a
credential rotation, an agent membership change, and rollback to the previous
bundle.

Restart an existing agent process after group changes and prove that it can
open every configured Agent V1 socket without `sg`, shell sourcing, or manual
login. Keep a stale process running in a negative test and require verification
to fail.

### macOS integration tests

Use clean macOS runners for launchd, account inspection, existing-agent setup,
client files, Git configuration, plugin installation, service ordering, and
rollback. Managed account creation ships only after its platform behavior has a
separate reviewed threat model and real-host tests.

### Security tests

Attempt profile path escape, symlink replacement, digest races, duplicate JSON
keys, oversized files, unknown fields, executable injection, unsafe adapter
claims, secret output, inherited-environment leakage, descriptor substitution,
malicious client homes, root-equivalent agent membership, and plan replay after
host drift.

Scan stdout, stderr, journals, plans, transaction records, exports, audits,
backup metadata, and failure diagnostics for credential canaries. Verify the
ownership, mode, retention, and deletion of protected credential rollback
files. Fuzz the pack loader, setup protocol decoder, canonical plan encoder,
and recovery journal parser.

### End-to-end host validation

The release gate provisions a clean Linux VM by running the documented one-line
bootstrap through a normal operator account. The test terminal answers the
wizard with reviewed fixtures and supplies protected credential descriptors.
No other BrokerKit machine configuration is supplied.

The test must create the deployment pack and agent account, install the signed
bundle, configure all providers, apply exact policies, install client
configuration, configure Git, install OpenClaw, start services, and run safe
real operations as the agent.
It then reboots, verifies again, changes one policy, upgrades the bundle, injects
a failed activation, rolls back, and verifies the previous deployment.

A successful build or service health check does not satisfy this gate. The real
agent path must work after initial install, reboot, upgrade, failed apply, and
rollback.

## Isengard adoption

Create the first deployment pack in the private control-plane repository from
the current explicit policies and installed nonsecret configuration. Pin the
active signed runtime bundle and the exact OpenClaw package. Map existing
credentials to retained slots so the first apply does not rotate them.

Run `brokerkit setup --profile <control-plane-pack>` from Onur's normal account
and bind the existing Bob account as the agent. This exercises the guided flow,
provider status checks, plan review, privilege transition, and real-agent
verification without asking Bob's untrusted process to handle a provider
credential.

The first plan must be reviewed against the current redacted host snapshot. Its
apply replaces client environment files with client V1 JSON, removes the shell
startup snippets, establishes group membership before restarting OpenClaw, and
keeps provider state and credentials in place.

After apply, reproduce these workflows as Bob:

- GitHub clone, fetch, branch creation, fast-forward push, typed repository
  read, and pull-request creation.
- Hugging Face Git fetch and one policy-allowed typed read.
- one harmless cataloged sudo operation through its complete approval path.
- OpenClaw discovery of all packaged BrokerKit skills.
- an approval decision through the configured trusted operator path.

Run a second unchanged apply and require a no-op plan with successful
verification. Reboot Isengard and repeat verification. Only then replace the
private control-plane apply and snapshot scripts with the deployment profile
and redacted export commands.

## Required checks

Run the root quality gates for every implementation branch:

```sh
go fmt ./...
go vet ./...
go test ./...
golangci-lint run
slophammer-go check .
```

Also run:

```sh
go test -race ./deployment/... ./internal/host/...
govulncheck ./...
go build ./cmd/brokerkit
```

Regenerate and check protocol artifacts whenever a V1 schema changes. Run every
provider setup suite when setup-component V1 changes. Run the OpenClaw package,
packed-install, and compatibility tests when the integration adapter or client
configuration changes.

Mutation tooling remains disabled and nonblocking unless it is explicitly
requested.

## Acceptance criteria

The implementation is complete when all of the following are true:

- A normal operator can begin from a clean host with one immutable installation
  command and complete setup through a guided terminal flow.
- The terminal flow has an OpenClaw-style connected guide, BrokerKit colors,
  notes, searchable selects, multiselects, masked secrets, inline progress, and
  a clear final plan.
- `NO_COLOR`, `FORCE_COLOR`, narrow terminals, basic terminals, and accessible
  screen-reader mode all produce usable output.
- The guided flow runs under the initiating user and elevates only one narrow,
  short-lived root-owned apply worker after profile generation.
- No user-writable executable is ever run with root privileges.
- The initiating operator and untrusted agent use separate safe Unix identities
  in the default production layout.
- One deployment pack describes the signed runtime, host identities, provider
  setup, complete policies, client access, Git routing, and OpenClaw integration.
- The pack and every referenced profile use closed V1 schemas and contain no
  secret values.
- `system profile lock --check` proves that every declared digest matches its
  exact referenced bytes.
- Interactive and declarative use of the same generated pack produce identical
  canonical plans.
- Setup interruption is resumable without storing a provider, broker, operator,
  OAuth, or Telegram secret.
- `system plan` produces one canonical secret-safe digest for the complete host
  change.
- Production apply refuses a missing or stale expected plan digest.
- A fresh Linux host can be installed from the bootstrap, pack, and protected
  credential files without manual provider setup commands.
- Reapplying an unchanged profile performs no writes or restarts and verifies
  the real agent path.
- GitHub and Hugging Face retain separate ownership and credential boundaries.
  Sudo, Telegram, and OpenClaw remain separate from them and from one another.
- Provider-specific profile fields and setup behavior remain in the matching
  component directories.
- Agent and service UIDs are distinct, and an unsafe agent account is rejected.
- New Unix group membership reaches the actual managed agent process before
  verification succeeds.
- Broker clients discover private client V1 files directly without shell startup
  edits or inherited production secrets.
- Complete reviewed provider policies replace live policy atomically, with no
  merge, overlay, or unknown-rule retention path.
- Credential slots preserve installed credentials by default and require an
  explicit action for rotation.
- OpenClaw skills-only installation uses an exact verified package and receives
  no operator credential.
- Interrupted apply recovers one prior or candidate deployment and reports any
  persistent retained resource honestly.
- Redacted export is deterministic and sufficient for control-plane review.
- The clean-VM and Isengard matrices pass through real agent-visible workflows
  after reboot, upgrade, failure, and rollback.
- Plans and logs contain no credential material. The same requirement covers
  journals, exports, backup metadata, diagnostics, and tests. Protected
  credential rollback files retain their required secret contents without
  exposing them through any output surface.

## Exclusions

This plan does not add a persistent privileged setup daemon, hosted fleet
controller, remote execution service, secret manager, password manager, SSH
provisioner, workspace manager, generic
configuration language, package marketplace, provider-permission importer,
arbitrary setup hook, shell-script field, or policy discovery loop.

It does not combine broker services, credentials, listeners, state databases,
audit streams, or release artifacts. It does not let an agent author or apply
its own policy. It does not make a healthy process or passing unit test stand in
for a successful real-agent workflow.
