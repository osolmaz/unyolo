---
title: Installation
description: Install unYOLO or one broker from a verified release.
---

The installer downloads one release and verifies it before running any release code. On Linux, the
guided setup can install the `unyolo` command, install credential brokers, connect a local agent to
an existing installation, or set up the brokers and agent together.

Guided host setup currently works on Linux. Docker, remote pairing, and managed macOS setup are not
available yet.

See the
[guided installation contract](https://github.com/osolmaz/unyolo/blob/main/docs/GUIDED_INSTALLATION.md)
for the exact setup rules.

## Current guided setup

Run the command as your normal account, not as root:

```sh
curl -fsSL https://unyolo.io/install.sh | sh
```

The installer downloads the release into a private temporary directory and checks its checksum and
GitHub build record. It asks what you want to set up, then shows only the choices supported by that
release and host. Ctrl-C on the first screen removes the temporary files and leaves no installation
or saved setup.

After the first choice, setup saves only nonsecret answers so the run can be resumed. Local agents
can use the current account, an existing account, or a new restricted account. The default
installation name is `default`; setup asks for another name only when a real collision or multiple
installations require one.

One confirmation installs the same checked command release. A separate confirmation appears after
unYOLO inspects the host and lists the exact administrator changes. Provider credentials are
collected only after that plan is approved and are never stored in setup progress.

Run `unyolo setup` again to review or change the default installation. The explicit lifecycle
commands are `unyolo reconfigure`, `unyolo repair`, and `unyolo remove`. Removal first deletes
unchanged services, generated connections, and managed agent accounts. The separate
`--remove-state` confirmation is required before provider credentials, broker state, and provider
accounts can be deleted. Changed or ambiguous resources are retained and reported.

## Binary-only install

Name one broker to skip guided host setup:

```sh
curl -fsSL https://unyolo.io/install.sh | sh -s -- github
curl -fsSL https://unyolo.io/install.sh | sh -s -- huggingface
curl -fsSL https://unyolo.io/install.sh | sh -s -- sudo
```

The words after `-s --` become arguments to the piped script. This path uses the component wrapper
and canonical installer in `install/install.sh`.

## Pinned setup

The short endpoint resolves the newest `unyolo/v*` release once and fetches the bootstrap from that
release's source commit. Pin both values when you have reviewed a particular release and bootstrap:

```sh
curl -fsSL https://unyolo.io/install.sh \
  | UNYOLO_REV=<40-character-commit-sha> VERSION=unyolo/v<reviewed-version> sh
```

The release tag, source commit, archive digest, and GitHub attestation identity are recorded in the
installed manifest. No floating release lookup occurs after setup starts.

Binary-only installs also accept `VERSION` and `INSTALL_DIR`. Guided setup uses `XDG_DATA_HOME` and
`XDG_BIN_HOME`, defaulting to `$HOME/.local/share` and `$HOME/.local/bin`.

## Verification

The installer detects the supported platform and downloads its archive with `checksums.txt`. It
checks the archive digest and verifies GitHub artifact attestations against the repository, release
workflow, and selected tag. Verification uses a pinned GitHub CLI build when no separately verified
`UNYOLO_VERIFIER_FILE` is configured. Guided setup retains that checksum-verified executable and
uses it again before administrator changes, so a system `gh` installation is not required.

The archive is checked before extraction. Unknown entries, links, path escapes, missing companion
files, and version mismatches fail closed. Guided setup downloads and verifies this archive once.
The CLI, setup companion, and provider catalog all come from that same archive.

`UNYOLO_VERIFY_ONLY=true` verifies without installing. Release CI combines it with
`UNYOLO_VERIFY_RELEASE_SET=true` to check every platform archive, the checksum manifest, and the
SBOM after publication.

## Activation layout

Guided setup prepares an immutable user release and switches one `current` link:

```text
~/.local/share/unyolo/releases/v<version>/
  unyolo
  openclaw-unyolo-setup
  gh-attestation-verifier
  providers/
  manifest.json

~/.local/share/unyolo/current -> releases/v<version>
~/.local/bin/unyolo          -> ../share/unyolo/current/unyolo
```

Preparation happens before the link changes. A checksum, ownership, copy, or version error leaves
the previous CLI active and prevents the root worker from starting.

The binary-only installer has a narrower boundary. It writes the declared executables and data files
to explicit user-writable directories, never invokes `sudo`, and prints the installed version.
`sudo-broker-exec` goes into the adjacent `libexec` directory instead of `PATH`.

## Release assets

Every component release publishes Linux and macOS archives for amd64 and arm64 plus checksums and an
SBOM. The `unyolo/v*` archive also carries the setup companion and release-declared provider catalog.

## Building from source

The repository is one Go module. Build any component with the Go version declared in `go.mod`:

```sh
go build ./brokers/huggingface/cmd/hf-broker
go build ./brokers/github/cmd/gh-broker
go build ./brokers/sudo/cmd/sudo-broker ./brokers/sudo/cmd/sudo-broker-exec
go build ./cmd/unyolo ./cmd/unyolo-telegram
```

A source build carries no attestation, so keep it to development and to hosts where you control the
whole chain. Development builds cannot be used as a checked production release. The host command rejects them.

## The Xet helper for hf-broker

Hugging Face bucket object writes go through the maintained Xet implementation, which is a Python
package. Install the pinned version into an environment only the broker can reach, and point the
broker at that interpreter:

```sh
python3 -m venv /opt/hf-broker/xet
/opt/hf-broker/xet/bin/pip install 'hf-xet==1.5.2'
export HF_BROKER_XET_PYTHON=/opt/hf-broker/xet/bin/python
```

The helper receives the Hub token over a private stdin pipe. It uploads content and returns a file
hash; it never receives client requests and never chooses Hub URLs. Bucket reads and every non-Xet
operation leave it alone. For a service deployment, pass `--xet-python` to `setup systemd` so the
path is persisted in the service environment, because an interactive export is not inherited by a
managed service.

## Host deployment details

Guided setup creates a locked configuration for the selected Linux services. It contains no provider
credentials. Root independently recompiles the saved installation from the exact verified release
source set and compares every generated byte before planning. See
[host deployment](/docs/deploy/host-deployment) for the internal file format, administrator commands,
and recovery behavior.
