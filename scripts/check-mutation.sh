#!/usr/bin/env bash

set -euo pipefail

targets=(
	authorization/grants/decisions.go
	authorization/grants/notifications.go
	transport/http/httpx.go
	approval/notifier/telegram/decision_poll.go
)
backup_dir="$(mktemp -d)"
for target in "${targets[@]}"; do
	mkdir -p "$backup_dir/$(dirname "$target")"
	cp "$target" "$backup_dir/$target"
done
cleanup() {
	for target in "${targets[@]}"; do
		cp "$backup_dir/$target" "$target"
	done
	rm -rf "$backup_dir"
	rm -rf target
}
trap cleanup EXIT

for target in "${targets[@]}"; do
	slophammer-go mutate . --target "$target"
done
