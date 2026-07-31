# Guided installation

*Target implementation and release contract*

This document defines the next default unYOLO installer. The installer starts with the user's goal,
then creates a credential-service plan, an agent-connection plan, or both. It must use plain language
for every choice and keep internal deployment terms out of the normal flow.

The current `v0.6.3` installer does not meet this contract. It assumes a complete Linux host, uses a
fixed agent account, and does not provide client-only setup. Public documentation must describe
those limits until an implementation passes the completion criteria in this document.

## User terms

The installer uses these terms:

- **Credential service:** a broker process that holds a provider credential and applies policy.
- **Agent:** the program that asks a credential service to perform an operation.
- **Agent account:** the operating-system account or container that runs the agent.
- **Agent connection:** the endpoint and client credential that let one agent reach selected
  credential services.
- **Person approving requests:** a person allowed to review and approve requests that need more
  access.
- **System changes:** accounts and groups, filesystem entries, sockets, or background services
  created or changed with administrator access.

The normal flow must not use `deployment kit`, `deployment pack`, `materialize`, `operator-owned`,
`provider-owned enrollment profile`, `protected worker`, `runtime bundle`, `credential slot`, or
`plan digest`. A technical-details view may show the internal names after it explains their plain
meaning.

## Public commands

The normal command opens guided setup:

```sh
curl -fsSL https://unyolo.io/install.sh | sh
```

The command must resolve and verify one exact release before it runs release code. It must not
choose an installation path, provider, account, or integration before the first screen.

An advanced user may pin the source bootstrap and release:

```sh
curl -fsSL https://unyolo.io/install.sh \
  | UNYOLO_REV=<reviewed-commit> VERSION=unyolo/v<reviewed-version> sh
```

Named binary-only commands remain available for advanced use:

```sh
curl -fsSL https://unyolo.io/install.sh | sh -s -- github
curl -fsSL https://unyolo.io/install.sh | sh -s -- huggingface
curl -fsSL https://unyolo.io/install.sh | sh -s -- sudo
```

These commands skip guided setup. They must not be presented as the normal way to connect an agent
or install credential services.

## Setup paths

The first screen asks one question:

```text
What do you want to set up?

● Protect credentials and connect an agent on this computer
  Install the credential services and connect a local agent. Recommended.

○ Install credential services only
  Agents can be connected later.

○ Connect an agent to an existing unYOLO installation
  No credential services will be installed here.

○ Install the unYOLO command only
```

The available paths are:

| Path | Credential-service plan | Agent-connection plan | Administrator access |
| --- | --- | --- | --- |
| Complete local setup | Yes | Yes | Required for local services and account changes |
| Credential services only | Yes | No | Required for local services |
| Agent connection only | No | Yes | Only when the selected account or local files require it |
| Command only | No | No | Never |

The installer must not label these choices only as `server` and `client`. Those terms may appear in
technical details.

## Capability check

The staged CLI checks the platform before it asks questions that depend on the platform or saves
setup state. Each platform backend reports:

- whether it can inspect and select local accounts or create a new one
- whether it can install and remove background services
- which local endpoint types it supports
- whether Docker integration is available
- whether remote agent pairing is available
- whether it implements planning and rollback followed by real verification

A choice may be shown only when its complete backend is available. A disabled choice must state the
missing capability in one sentence. The installer must not continue into a Linux host plan on
macOS or wait until the final confirmation to report an unsupported platform.

The default complete setup may be called supported on a platform only after account management and
service management work with rollback and removal. It must also pass real end-to-end verification
on that platform.

## Agent location

A setup path that includes an agent connection asks:

```text
Where does the agent run?

● A new separate account on this computer
  Best isolation. unYOLO will create a restricted account.

○ An existing account on this computer
  Choose an account such as bob.

○ A Docker container on this computer

○ Another computer

○ My current account
  Less isolation: the agent may access files available to your account.
```

Only valid choices for the current setup path and platform are shown.

### New local account

The installer proposes `unyolo-agent` and lets the user change it. Before review, it must show the
account's home directory and login behavior, plus its groups and administrator status, in plain
language.

The platform backend must use native account-management tools. Linux and macOS implementations may
produce different system actions, but both must enforce these rules:

- the account is not an administrator
- the account does not receive provider credentials
- the account receives only the client configuration and access needed for its selected connection
- existing accounts and groups are preserved, and existing paths are never silently replaced
- rollback removes only resources created by the failed transaction

### Existing local account

The installer lists suitable local accounts and allows an exact account name. It validates the
account before planning. If the account has administrator access or can already read broker state,
the review must state that the account provides weaker isolation.

### Current account

The current account remains an explicit, nonrecommended choice. The installer explains that an
agent running with the user's full file access may be able to read files outside unYOLO's policy
boundary. It must not describe this choice as equivalent to a separate account.

### Docker container

The Docker path supports an existing container or Compose project without rebuilding an arbitrary
image. It creates or prints:

- the agent client configuration
- a read-only configuration or secret mount
- a local socket mount or verified remote endpoint
- required UID and GID settings
- a health check that performs real client authentication

The plan must not mount provider credentials, broker state directories, or broad host directories
into the container. Docker choices appear only when the installer can verify the selected engine
and connection method.

### Another computer

A remote agent uses a short-lived, one-use pairing flow. The agent verifies the credential service
identity before it stores a client credential. The installer must not ask users to transfer a
long-lived provider credential or silently expose a local Unix socket over TCP.

Remote setup may be offered only when an authenticated and encrypted transport is implemented and
verified. There is no insecure fallback.

## Agent identity

The setup keeps these names separate:

- the operating-system account or container identity
- the unYOLO client name used in policy and audit records
- the display name shown to the person approving requests

The installer derives sensible defaults from the selected account and lets the user edit them under
advanced options. It must not hardcode `agent` and `unyolo-agent` after the user selected another
account.

Multiple clients may use the same credential service, but each client must receive a distinct
credential and policy identity.

## Credential-service setup

A setup path that installs credential services first asks where they should run:

```text
Where should the credential services run?

● As background services on this computer
  Use the native Linux or macOS service manager. Recommended.

○ In Docker on this computer
  Create a Compose configuration with separate protected containers.
```

The Docker choice appears only when its backend can protect credentials and state while exposing
only the selected endpoints on the detected host. Each broker remains a separate container, credential domain, state volume, and audit
stream. The generated configuration pins image digests, mounts only the broker's own protected
files, and never mounts the Docker socket. Setup verifies restart behavior and one real client
request before reporting success.

The installer then asks which services to install. The menu shows every option when the full list
fits in the terminal. Longer lists show a visible scroll marker and the number of hidden items.

Each option uses a user-facing name and one-line purpose. For example:

```text
Which credentials should unYOLO protect?

[x] GitHub
    Repository access and pull requests, including Git operations.

[x] Hugging Face
    Hub repositories and Jobs, plus Buckets and inference.

[ ] Approved local commands
    Run only commands listed in a root-owned catalog.
```

At least one credential service is required for a credential-service plan. Provider metadata comes
from the verified release. Shared installer code must not import provider packages.

Provider-owned adapters may ask provider-specific questions after the shared flow establishes the
setup path and agent identity. Questions must say what value is needed, where the user can obtain it,
and how it will be stored. Raw internal secret-slot names must stay in technical details.

## Person approving requests

A local credential-service setup defaults to the person running the installer. Advanced options may
add another existing local account. The review shows who can approve requests and which interface
each person can use.

The installer must not call this person an `operator` in the normal flow.

## Integrations

After the agent location is known, the installer asks which supported agent software to configure.
The installer configures OpenClaw only when the user selects it. A generic client path must remain
available.

An integration owns only its generated client files and instructions. It must not change provider
selection, broker policy, or another integration's files.

## Setup intent

The wizard records nonsecret answers as one setup intent. This is the stable input to planning. It
is not the root deployment format.

A complete local setup for an existing account has this shape:

```json
{
  "api_version": "unyolo.io/setup-intent/v1",
  "goal": "complete_local",
  "credential_service": {
    "location": "local_host",
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

A client-only setup for the current account may use a remote pairing endpoint:

```json
{
  "api_version": "unyolo.io/setup-intent/v1",
  "goal": "agent_connection",
  "agent": {
    "location": "local_account",
    "connection_name": "onur",
    "account": {
      "mode": "current",
      "name": "onur"
    }
  },
  "connection": {
    "transport": "https",
    "endpoint": "https://unyolo.example.com",
    "enrollment": "pairing"
  }
}
```

The pairing code is secret input collected later and never appears in this object.

The V1 fields are:

| Field | Required | Meaning |
| --- | --- | --- |
| `api_version` | Yes | Must be `unyolo.io/setup-intent/v1`. |
| `goal` | Yes | `complete_local`, `credential_service`, `agent_connection`, or `command_only`. |
| `credential_service` | By goal | Where credential services run and which providers are selected. `location` is `local_host` or `docker`. |
| `agent` | By goal | Where the agent runs and how it is identified. |
| `connection` | By goal | The derived local or remote connection method. |
| `integrations` | No | Client integrations selected by the user. Omission means generic client files only. |

Unknown fields are errors. Provider and integration IDs must be unique and must exist in the
verified release catalog. `connection_name` uses 1 to 64 characters. It accepts lowercase letters
and digits with hyphens only between them. A remote `endpoint` must be an absolute HTTPS URL with no embedded credentials. The
platform backend validates operating-system account names instead of applying one cross-platform
account-name pattern.

Secrets, provider tokens, private keys, pairing codes, plan digests, and host inspection results must
not appear in the intent.

The installer generates an internal deployment configuration only for a local credential-service
plan. It generates client configuration only for an agent-connection plan. A complete setup creates
both from the same intent. The internal deployment name defaults to `default`; the installer asks
for another name only when the user is managing more than one installation or a name collision
requires a choice.

## Navigation and saved progress

Every choice screen must support Back and Continue as well as Cancel. The final review must provide Edit links
for setup path, agent, credential services, and integrations. Editing an answer invalidates every
derived plan and check that depends on it.

The interactive renderer must:

- show the full option list when it fits
- show which options are selected
- preserve answers when moving backward
- keep completed choices visible in the review
- fit at terminal widths of 60, 80, or 120 columns
- provide an accessible text mode with the same choices and defaults
- never require color, pointer input, or an alternate screen to understand the current step

The installer may save nonsecret answers after it says:

```text
Your choices were saved so you can continue later. No credentials were saved.
```

It must offer a way to discard a saved setup. Credentials remain in memory or one-use pipes and are
never written to the setup intent or session.

## Plain-language rules

Every screen has:

1. one direct question
2. one sentence explaining why the answer matters
3. options described by their result
4. a marked recommendation when one choice is safer for the detected environment

Copy must name the concrete action. For example, use `Create the account unyolo-agent` instead of
`Materialize the selected identity`. Use `Install two background services` instead of `Apply the
runtime component graph`.

Security text must explain the actual access boundary. It must not use `safe`, `secure`, `trusted`,
or `verified` without saying what was checked or restricted.

## Review

The normal review contains no internal identifiers:

```text
Ready to set up unYOLO

Credential services
  Install on this Mac
  GitHub and Hugging Face

Agent
  Existing account: bob
  Connection name: bob

System changes
  Install 2 background services
  Create local sockets
  Give bob access to the agent sockets
  Start the services when this Mac starts

Security
  bob will not receive provider credentials
  bob will not receive administrator access

[Edit]  [Show technical details]  [Install]
```

A client-only review says that no credential services will be installed. A command-only review says
that no administrator changes are required.

Technical details may show the release, source commit, file digests, internal configuration path,
exact system actions, and plan digest. They must not replace the normal review.

## Installation boundaries

CLI activation and administrator changes use separate confirmations:

```text
Install the unYOLO command for your account?
```

and, only when needed:

```text
Allow these administrator changes?
```

User-level activation must finish before administrator planning starts. A command-only or
client-only path that needs no protected files must never start a root worker.

The bootstrap may stage files in a private temporary directory, but normal output must not tell the
user to add that temporary directory to `PATH`. Temporary download and verification details appear
only in verbose mode.

## Release verification and activation

The bootstrap resolves one exact `unyolo/v*` release and performs these checks before executing the
staged CLI:

1. The selected tag has the expected `unyolo/v<version>` form.
2. The archive digest matches `checksums.txt`.
3. GitHub build attestations bind the archive and checksum manifest to the release workflow and tag.
4. The archive contains only declared regular files with no links or path escapes.
5. The pinned GitHub CLI used for attestation checks matches its recorded checksum.
6. The CLI build version, release tag, activation manifest, and setup runtime version agree.

A failed check removes staging and returns a nonzero status. No file from an unverified archive may
be executed or installed.

A release activates as one immutable file set under the user's configured data directory. The CLI,
provider catalog, integration helpers, and planning templates must come from the same release. A
failed activation keeps the previous release active.

## Planning and administrator work

The unprivileged wizard compiles the setup intent into separate server and client plans. Platform
and provider adapters contribute bounded actions. The shared coordinator owns ordering, review, and plan identity. It also owns the privilege
transition, rollback behavior, and final verification.

The root process receives an already reviewed plan. It must not ask product questions, widen the
plan, select accounts, or discover a replacement configuration. It rechecks host state and rejects
a stale plan before mutation.

Internal deployment configurations remain locked, nonsecret inputs for unattended validation and
planning. The same inputs drive apply, repair, or removal. Their format is documented in
[`HOST_DEPLOYMENT.md`](HOST_DEPLOYMENT.md). They are an implementation and automation interface, not
wizard vocabulary.

## Verification after installation

Setup is complete only after it tests the selected user workflow. A local complete setup verifies:

```text
Checking setup

✓ Credential services are running
✓ Agent account bob can connect
✓ bob cannot read provider credentials
✓ An allowed test request succeeded
✓ A disallowed test request was refused
```

A Docker setup also verifies real authentication from the selected container context and checks that
provider credentials are not mounted. A remote setup verifies the encrypted connection and server
identity from the remote client.

Health checks and service status support this evidence but do not replace a real client request.

## Failure behavior

| Failure point | Required result |
| --- | --- |
| Platform capability check | Explain the unsupported choice before saving setup state or planning system changes. |
| Release lookup, download, or verification | Remove staging and execute nothing from the failed release. |
| Cancellation before saved progress | Remove staging and leave no state from the run. |
| Cancellation after saved progress | Keep only the disclosed nonsecret session and offer a discard command. |
| CLI activation failure | Keep the previous CLI active and make no administrator change. |
| Planning failure | Keep the installed CLI and nonsecret session for inspection and retry. |
| Apply failure | Roll back the transaction and report every remaining change. |
| Verification failure | Report setup as failed and provide repair or removal steps. |

Signals must reach the foreground setup process. Cleanup preserves exit status, including 130 for
SIGINT and 143 for SIGTERM.

## Platform completion matrix

A platform path is complete only when every required cell has a real end-to-end test.

| Path | Linux | macOS | Docker on Linux | Docker on macOS |
| --- | --- | --- | --- | --- |
| Command only | Required | Required | Not applicable | Not applicable |
| Credential services only, native | Required | Required | Not applicable | Not applicable |
| Credential services only, Docker | Not applicable | Not applicable | Required | Required |
| Agent connection with current account | Required | Required | Not applicable | Not applicable |
| Agent connection with existing account | Required | Required | Not applicable | Not applicable |
| Agent connection with new account | Required | Required | Not applicable | Not applicable |
| Complete local setup with native services | Required | Required | Not applicable | Not applicable |
| Agent in an existing container | Not applicable | Not applicable | Required | Required |
| Remote agent pairing | Required | Required | Required when selected | Required when selected |

Tests cover amd64 and arm64 where releases support both. A choice must remain hidden or explicitly
unavailable until its backend passes the matching matrix row.

## Required test cases

The contract requires unit and integration coverage as well as PTY and real-target tests for:

- every setup path and every valid transition between screens
- complete option visibility and selection at supported terminal sizes
- Back and Edit navigation plus Cancel, resume, or discard behavior
- current and existing local accounts plus newly created accounts
- account collisions, administrator accounts, unsafe permissions, and rollback
- Linux systemd and macOS launchd installation with restart and boot enablement, followed by repair
  and removal
- Docker socket or remote connection mounts without provider credentials
- one-use remote pairing, server identity checks, expiry, replay rejection, and cancellation
- provider combinations and generic clients without OpenClaw
- mismatches in release identity, checksums, attestations, source commits, archives, or build
  versions
- preservation of the previous CLI after activation failure
- rejection of host drift between review and apply
- allowed and denied operations from the real selected agent context
- upgrade, reconfigure, repair, credential rotation, and uninstall

Mocked checks are supporting evidence. Release completion requires the public piped command to run on
clean target systems through apply, real client verification, and removal.

## Completion criteria

The new default may ship when:

- the first screen asks the setup goal
- unsupported platform paths are removed or explained before durable changes
- users can select the current account, an existing account, a new restricted account, Docker, or a
  remote agent when those paths are supported
- Custom mode has been removed and every supported choice is directly editable
- the normal flow contains none of the forbidden internal terms
- CLI installation and administrator changes have separate confirmations
- the review can be edited without restarting
- the selected workflow passes real end-to-end verification
- Linux and macOS meet the required matrix rows for every choice shown on each platform
- public documentation describes the behavior that was exercised

No automatic metric, mocked test, or successful build may mark an untested setup path as supported.
