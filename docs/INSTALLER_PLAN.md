# Installer Plan

Status: implemented and cut over to Brokerkit's shared operations runtime.

Goal: make `hf-broker` installable globally without requiring Go, Homebrew, apt,
or npm, then provide an explicit Linux service setup path for same-host broker
deployments.

Broker-family unification is tracked in
[BROKERKIT_UNIFICATION.md](BROKERKIT_UNIFICATION.md). hf-broker's current
installer is now a thin wrapper over Brokerkit's pinned canonical installer.
Client parsing, common systemd options, generated/file/stdin secret handling,
and systemd unit rendering also use Brokerkit. Hugging Face token copying,
scope generation, and provider-specific doctor probes remain local.

## User Experience

Primary install:

```sh
curl -fsSL https://raw.githubusercontent.com/osolmaz/hf-broker/main/install.sh | sh
```

Pinned version:

```sh
curl -fsSL https://raw.githubusercontent.com/osolmaz/hf-broker/main/install.sh | VERSION=v0.1.0 sh
```

Custom install directory:

```sh
curl -fsSL https://raw.githubusercontent.com/osolmaz/hf-broker/main/install.sh | INSTALL_DIR="$HOME/.local/bin" sh
```

Linux service setup:

```sh
sudo hf-broker setup systemd \
  --hf-token-file ./hf-token \
  --repo osolmaz/scraped-news \
  --repo-type dataset
```

## Implementation Steps

1. Add version support to `hf-broker`.
   - Add `hf-broker --version`.
   - Inject version at build time with `-ldflags`.
   - Default to `dev` when built locally.

2. Add a release build script.
   - Create `scripts/release.sh`.
   - Build these targets:
     - `linux/amd64`
     - `linux/arm64`
     - `darwin/amd64`
     - `darwin/arm64`
   - Package each build as:
     - `hf-broker_linux_amd64.tar.gz`
     - `hf-broker_linux_arm64.tar.gz`
     - `hf-broker_darwin_amd64.tar.gz`
     - `hf-broker_darwin_arm64.tar.gz`
   - Include `hf-broker`, `README.md`, and `LICENSE`.
   - Generate `checksums.txt`.

3. Add a GitHub release workflow.
   - Create `.github/workflows/release.yml`.
   - Trigger on tags matching `v*`.
   - Run tests first.
   - Build release assets.
   - Upload tarballs and `checksums.txt` to the GitHub Release.

4. Delegate `install.sh` to Brokerkit's canonical installer.
   - Keep only the broker/repository constants and pinned Brokerkit installer
     revision in this repository.
   - Brokerkit detects OS with `uname -s`.
   - Brokerkit detects architecture with `uname -m`.
   - Normalize platform names:
     - `Linux` -> `linux`
     - `Darwin` -> `darwin`
     - `x86_64` -> `amd64`
     - `aarch64` / `arm64` -> `arm64`
   - Resolve version:
     - use `$VERSION` when set
     - otherwise query the latest GitHub release
   - Download the matching tarball and `checksums.txt`.
   - Verify checksum with:
     - `sha256sum` on Linux
     - `shasum -a 256` on macOS
   - Install the binary to:
     - `$INSTALL_DIR` when set
     - otherwise `/usr/local/bin` when writable or usable through `sudo`
     - otherwise `$HOME/.local/bin`
   - Brokerkit prints final verification with the newly installed binary's
     `--version` output.

5. Add Linux systemd setup.
   - Add `hf-broker setup systemd`.
   - Create the `hf-broker` service user and group when missing.
   - Copy the upstream Hugging Face token to `/etc/hf-broker/hf-token`.
   - Generate `/etc/hf-broker/secrets` for broker client credentials.
   - Generate `/etc/hf-broker/scope.json` for one append-only repo.
   - Generate `/etc/hf-broker/env`.
   - Generate `/etc/systemd/system/hf-broker.service`.
   - Enable and start the service unless `--no-start` is set.
   - Print the broker URL and a secret-safe `setup client` command.
   - Never print generated client secrets.

6. Update README install docs.
   - Recommended curl installer.
   - Pinned version install.
   - Manual tarball install.
   - Developer install with `go install`.
   - Linux service setup with the dedicated `hf-broker` user.

7. Keep daemon setup separate from binary installation.
   - Do not make `install.sh` create users, token files, systemd units, or
     launchd plists.
   - `install.sh` installs only the binary.
   - `hf-broker setup systemd` performs privileged Linux service setup.

## Defaults

Install destination priority:

```text
$INSTALL_DIR
/usr/local/bin with sudo
$HOME/.local/bin
```

Supported platforms:

```text
linux amd64
linux arm64
darwin amd64
darwin arm64
```

Failure behavior:

- Unsupported OS or architecture: clear error.
- Missing checksum tool: clear error.
- Checksum mismatch: hard fail.
- No writable install directory: hard fail with a manual command suggestion.
- Installed but not on `PATH`: print the directory to add.

## Validation

Before merging:

```sh
go test ./...
go build ./cmd/hf-broker
scripts/release.sh v0.0.0-test
```

After publishing the first release:

```sh
VERSION=v0.1.0 sh install.sh
hf-broker --version
```
