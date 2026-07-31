#!/bin/sh
# macos-clean-host.sh removes unYOLO-owned launchd services, managed accounts,
# and host state directories from a macOS test host. It is intentionally
# conservative: it never deletes preexisting or changed resources, and it
# refuses to run on non-darwin hosts.
#
# Run under sudo. Exits nonzero if the host is not macOS.

set -eu

if [ "$(uname -s)" != "Darwin" ]; then
  printf '%s\n' 'macos-clean-host: this script only runs on macOS hosts' >&2
  exit 1
fi

if [ "$(id -u)" -ne 0 ]; then
  printf '%s\n' 'macos-clean-host: rerun under sudo' >&2
  exit 1
fi

state_root='/Library/Application Support/unyolo'
socket_root='/private/var/run/unyolo'
plist_root='/Library/LaunchDaemons'

for label in io.unyolo.github io.unyolo.huggingface io.unyolo.sudo io.unyolo.openclaw; do
  plist="$plist_root/$label.plist"
  if [ -e "$plist" ]; then
    if launchctl print "system/$label" >/dev/null 2>&1; then
      launchctl bootout "system/$label" || true
    fi
    rm -f "$plist"
  fi
done

for account in gh-broker hf-broker sudo-broker unyolo-agent; do
  if dscl . -read "/Users/$account" >/dev/null 2>&1; then
    dscl . -delete "/Users/$account" || true
  fi
done

for group in gh-broker gh-broker-agent gh-broker-operator hf-broker hf-broker-agent hf-broker-operator sudo-broker sudo-broker-agent sudo-broker-operator; do
  if dscl . -read "/Groups/$group" >/dev/null 2>&1; then
    dseditgroup -o delete "$group" || true
  fi
done

for path in "$state_root" "$socket_root"; do
  if [ -d "$path" ]; then
    rm -rf "$path"
  fi
done

printf '%s\n' 'macos-clean-host: complete'
