#!/usr/bin/env sh
set -eu

slophammer_go() {
	if command -v slophammer-go >/dev/null 2>&1; then
		slophammer-go "$@"
	elif [ -x "$HOME/go/bin/slophammer-go" ]; then
		"$HOME/go/bin/slophammer-go" "$@"
	else
		echo "slophammer-go not found" >&2
		exit 127
	fi
}

targets="
internal/httpapi/grant_notification_ref.go
internal/httpapi/grant_request_validation.go
internal/httpapi/grant_retained_status.go
"
backup_dir="$(mktemp -d)"
for target in $targets; do
	mkdir -p "$backup_dir/$(dirname "$target")"
	cp "$target" "$backup_dir/$target"
done
cleanup() {
	for target in $targets; do
		cp "$backup_dir/$target" "$target"
	done
	rm -rf "$backup_dir"
}
trap cleanup EXIT

slophammer_go mutate . --target internal/httpapi/grant_notification_ref.go
slophammer_go mutate . --target internal/httpapi/grant_request_validation.go
slophammer_go mutate . --target internal/httpapi/grant_retained_status.go
