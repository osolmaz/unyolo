---
title: Installation
description: Verified release installs, what the installer will and will not do, and building from source.
---

Every broker installs through a component wrapper around one canonical POSIX installer in
`install/install.sh`. Each wrapper supplies the broker name along with its repository and release
tag prefix. The shared script then detects the platform, downloads the archive, verifies it, and
installs the binary. This page covers what that script guarantees, the environment variables it
reads, and the alternatives.

## Install a broker

Name the broker you want. The installer resolves its latest release to an exact commit, verifies
release checksums and build attestations, and installs the binary to `$HOME/.local/bin`:

```sh
curl -fsSL https://unyolo.io/install | sh -s github
```

Substitute `huggingface` or `sudo` for another broker.

## Pin the bootstrap

That command reads the bootstrap from the default branch, so you get whatever that branch says on
the day you run it. Everything downstream is already pinned, because the bootstrap resolves the
release tag to an exact commit and checks the archive against release checksums and GitHub build
attestations before installing anything. The bootstrap itself is the one link left, and naming a
commit you have reviewed closes it:

```sh
curl -fsSL https://unyolo.io/install | UNYOLO_REV=<40-character-commit-sha> sh -s github
```

Fetching that commit's bootstrap yourself does the same thing without going through the endpoint:

```sh
UNYOLO_REV=<40-character-commit-sha>
curl -fsSL "https://raw.githubusercontent.com/osolmaz/unyolo/$UNYOLO_REV/brokers/github/install.sh" | sh
```

Two environment variables change the outcome:

| Variable | Effect |
| --- | --- |
| `VERSION` | Install a specific release tag instead of the latest, for example `v0.1.0`. |
| `INSTALL_DIR` | Install to an absolute writable directory instead of `$HOME/.local/bin`. |

## Verification

The runtime detects `linux` or `darwin` and `amd64` or `arm64`, then downloads the matching tarball
and `checksums.txt`. It checks the archive digest against the manifest, and it verifies GitHub
artifact attestations for both files against the unYOLO repository, the release workflow, and
the selected tag. Verification uses a GitHub CLI build whose Linux and macOS checksums are embedded
in the installer itself, so the verifier is pinned rather than fetched from wherever.

A version label alone is never treated as evidence. The attestation ties the artifact to the
workflow run that produced it.

Two variables cover unusual situations. `UNYOLO_VERIFIER_FILE` points at an absolute executable
path for a verifier you obtained and checked separately, which is how an offline install works.
`UNYOLO_VERIFY_ONLY=true` authenticates and validates release contents without installing
anything; the release workflow combines it with `UNYOLO_VERIFY_RELEASE_SET=true`
after publication to check all four platform archives, the checksum manifest, and the SBOM. The
remaining `UNYOLO_*` URL and platform variables exist as test seams and normal installs do not
need them.

## Installer boundaries

The installer does not create users, service files, config files, token files, launchd plists, or
systemd units. It defaults to `$HOME/.local/bin`, never invokes `sudo`, and requires
an explicit writable `INSTALL_DIR` for any other destination. Privileged setup is a separate,
deliberate command.

It installs only the declared executable set. `hf-broker` and `gh-broker` each declare one CLI.
`sudo-broker` additionally declares its privileged `sudo-broker-exec` companion, which is installed
in the adjacent `libexec` directory rather than on your `PATH`.

After installing, the script prints the installed path and the binary's `--version`.

## Release assets

Every broker release publishes four archives plus a checksum manifest:

```text
<broker>_linux_amd64.tar.gz
<broker>_linux_arm64.tar.gz
<broker>_darwin_amd64.tar.gz
<broker>_darwin_arm64.tar.gz
checksums.txt
```

Each tarball contains the binary, `README.md`, and `LICENSE`. Every broker supports both
`<broker> --version` and `<broker> version`.

## Building from source

The repository is one Go module. Build any component with the Go version declared in `go.mod`:

```sh
go build ./brokers/huggingface/cmd/hf-broker
go build ./brokers/github/cmd/gh-broker
go build ./brokers/sudo/cmd/sudo-broker ./brokers/sudo/cmd/sudo-broker-exec
go build ./cmd/unyolo ./cmd/unyolo-telegram
```

A source build carries no attestation, so keep it to development and to hosts where you control the
whole chain. Development build identities cannot enter a signed production runtime bundle, which
the host command enforces rather than warns about.

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

## Installing a whole host

For a production Linux host, the guided host deployment flow installs and reconciles the complete
set of services from one locked, non-secret deployment pack, and activates them as a signed
immutable bundle. That is a different entry point from the per-broker installer above; see
[host deployment](/docs/deploy/host-deployment).
