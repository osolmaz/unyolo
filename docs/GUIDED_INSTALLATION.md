# Guided installation

*Implementation and release contract*

This document defines the default installation flow for unYOLO. The public command starts guided
host setup, lets the operator choose providers, and delays CLI activation until the operator
approves the reviewed setup. It also defines the separate binary-only path for people who need one
broker without host setup.

The short endpoint loads the bootstrap from the selected release's source commit. Existing releases
therefore keep their matching installer, while a release built from this implementation adopts the
flow below. Publication is complete only after the real-host checks pass.

## Public commands

The normal command has no positional argument:

```sh
curl -fsSL https://unyolo.io/install.sh | sh
```

It must open guided setup. It must not choose a broker or install a binary before the first setup
screen.

An operator may pin the source bootstrap and release:

```sh
curl -fsSL https://unyolo.io/install.sh \
  | UNYOLO_REV=<reviewed-commit> VERSION=unyolo/v<reviewed-version> sh
```

A named argument remains available for binary-only installs:

```sh
curl -fsSL https://unyolo.io/install.sh | sh -s -- github
curl -fsSL https://unyolo.io/install.sh | sh -s -- huggingface
curl -fsSL https://unyolo.io/install.sh | sh -s -- sudo
```

These commands install one broker and skip guided host setup. This advanced path bypasses the
default guided flow.

## First setup screen

The first interactive choice selects the providers for this host. GitHub and Hugging Face are
independent choices, so the operator may select either one or both. Local privileged operations may
appear as another component when the signed runtime includes it.

```text
Select providers
  [x] GitHub
  [x] Hugging Face
  [ ] Local privileged operations
```

At least one provider is required. Ctrl-C on this screen exits with status 130. At that point the
bootstrap must remove its private staging directory, and there must be no active CLI installation,
setup session, deployment pack, root worker, service, account, or credential file from this run.

The provider list comes from the verified runtime manifest selected for the run. The generic setup
command must not hardcode provider names or import provider packages. Each signed component supplies
its display metadata and setup adapter. Provider code remains under its matching `brokers/`
directory.

Existing deployment mode behaves differently because its locked pack already names the components.
Setup reads and displays those components instead of asking the operator to replace them.

## Release selection

The bootstrap resolves one exact `unyolo/v*` release before it opens setup. It records the selected
tag and uses that value for every later download and check. A floating release lookup must not occur
again during the run.

The bootstrap downloads the platform archive and checksum manifest once into a private directory. It
then performs these checks before executing the staged CLI:

1. The selected tag has the expected `unyolo/v<version>` form.
2. The archive digest matches `checksums.txt`.
3. GitHub build attestations bind the archive and checksum manifest to the unYOLO release workflow
   and selected tag.
4. The archive contains exactly the declared regular files with no links or path escapes.
5. The CLI build version, release tag, activation manifest, and setup runtime version agree.

A failed check removes staging and returns a nonzero status. No file from an unverified archive may
be executed or copied to an installation directory.

## Staged setup

Verification extracts the CLI and its declared companion files into a directory owned by the
invoking operator with mode `0700`. The bootstrap runs that CLI with `/dev/tty` as its interactive
input and output. The script itself does not collect configuration or credentials and never runs as
root.

The staged CLI may keep a nonsecret resumable setup session after the operator has made the first
choice. The UI must say when that session is saved. Credentials remain outside the session and
deployment pack.

Recommended and Custom modes build a locked deployment pack from the selected signed components. The
resulting pack contains only the providers and integrations the operator selected. Setup validates
the complete pack and shows the exact host plan before asking for activation or protected work.

## Activation boundary

Setup asks for one explicit confirmation after the deployment review and before `privilege.Start`:

```text
Install the verified unYOLO CLI and continue to protected host planning?
```

A negative answer or Ctrl-C leaves no active CLI installation and starts no root worker. A positive
answer commits the user-level installation. Activation must finish before setup copies a root
bootstrap, pins a runtime trust key, creates a service account, or changes any protected host path.

This boundary gives failures a usable recovery path. If user-level activation fails, setup stops
before protected mutation. If planning or apply fails after activation, the verified CLI and
nonsecret setup session remain available for `unyolo setup --resume` and its status, doctor, or
rollback commands.

Documentation must describe this boundary precisely. It must not claim that the system stays
untouched when an operator cancels after approving activation or host changes.

## Atomic CLI activation

A release is activated as one immutable file set. The default XDG layout is:

```text
~/.local/share/unyolo/releases/v<version>/
  unyolo
  openclaw-unyolo-setup
  manifest.json

~/.local/share/unyolo/current -> releases/v<version>
~/.local/bin/unyolo          -> ../share/unyolo/current/unyolo
```

The installer prepares the complete version directory on the destination filesystem, checks every
file again, and then replaces the `current` link with one atomic rename. The CLI and companion
therefore cannot come from different releases. Existing active files remain usable when preparation
fails.

Activation rejects symlinked source files, unexpected archive entries, unsafe directory ownership,
and a destination outside the invoking user's configured install roots. User-level activation never
invokes `sudo`.

The installed manifest records the release tag, source commit, archive digest, file digests,
attestation identity, and installation time. It contains no credentials. `unyolo --version` and a
future update command can use this record without another floating lookup.

## Provider setup

After activation, setup starts the matching verified root worker and plans the selected components.
Component adapters own provider-specific questions and profile generation. The host coordinator only
handles the shared setup protocol, component ordering, plan review, privilege transition, and
transaction.

GitHub and Hugging Face retain separate processes, listeners, credentials, state directories,
policies, release artifacts, and audit streams. Selecting both providers adds both component plans
to one host transaction without merging their security boundaries.

The final review shows the selected providers, agent identity, operator access, endpoints, services,
policy summaries, credential slots, runtime release, and plan digest. Apply proceeds only after a
separate confirmation of that exact plan.

## Failure behavior

| Failure point | Required result |
| --- | --- |
| Release lookup, download, or verification | Remove staging. Install and execute nothing from the failed release. |
| Ctrl-C on the provider screen | Exit 130 with no durable state from the run. |
| Cancellation before activation | Remove staging and start no protected worker. Retain a setup session only if the UI already disclosed it. |
| Activation preparation failure | Keep the previous CLI active and make no protected host change. |
| Planning failure after activation | Keep the new CLI and resumable session so the operator can inspect and retry. |
| Apply failure | Run the host transaction rollback, keep the CLI and audit evidence, and report the remaining drift. |
| Verification failure after apply | Report setup as failed and preserve enough state for doctor and repair. |

Signals must reach the foreground setup process. Cleanup must preserve the child's exit status,
including 130 for SIGINT and 143 for SIGTERM. Temporary files must be removed on normal exit or
cancellation, including handled signals.

## Script ownership

`install/bootstrap.sh` is the sole implementation of release work and staged setup launch. The
website publishes that canonical script as `/install.sh` during its static build.
`web/public/install.sh` must not grow a second copy of the bootstrap logic.

`install/install.sh` remains the shared binary installer for named broker installs and release
verification. Guided setup may reuse its archive validation functions, but it must not invoke the
installer twice or resolve `latest` in two child shells.

Shell code passes configured values as quoted arguments. It must not interpolate URLs, revisions,
paths, or tags into `sh -c` source text. Downloads go to private files so a failed `curl` cannot be
hidden by a successful empty shell pipeline.

## Verification gates

Unit and integration tests must cover the release and activation boundaries. The suite needs real
PTY tests because redirected byte streams do not reproduce Ctrl-C or terminal detection.

Required cases include:

- provider selection for GitHub, Hugging Face, and both together
- an existing pack whose provider set is displayed without replacement
- cancellation on the first screen with no durable files
- one release resolution and one archive download for a complete run
- mismatches across the checksum, attestation, source tag, archive, or build version
- preservation of the previous CLI after activation preparation fails
- proof that protected planning cannot start before activation succeeds
- matching versions in the staged CLI, installed manifest, and root worker
- cleanup and exit status under SIGINT, SIGTERM, terminal EOF, and setup errors
- shell metacharacters in every supported environment override
- Linux amd64 and arm64 runs against an actual published release
- complete setup with GitHub only, Hugging Face only, and both providers in a real target
  environment

Repository checks and mocked setup runs support these cases. Release completion still requires the
original piped command to be exercised through a real terminal on a clean Linux host.

## Completion criteria

The new default may ship when `curl -fsSL https://unyolo.io/install.sh | sh` opens provider
selection and early Ctrl-C leaves no installation. One verified release must then move through
staging and activation, followed by protected planning through apply and end-to-end verification.
The website, root documentation, release notes, and command help must describe the behavior that was
exercised.
