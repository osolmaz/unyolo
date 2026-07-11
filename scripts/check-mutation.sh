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

mutation_targets="
internal/approval/message.go
internal/hfgrant/hfgrant.go
internal/httpapi/grant_notification_ref.go
internal/httpapi/grant_request_validation.go
internal/httpapi/grant_retained_status.go
"
backup_dir="$(mktemp -d)"
for target in $mutation_targets; do
	mkdir -p "$backup_dir/$(dirname "$target")"
	cp "$target" "$backup_dir/$target"
done
cleanup() {
	for target in $mutation_targets; do
		cp "$backup_dir/$target" "$target"
	done
	rm -rf "$backup_dir"
	rm -rf target
}
trap cleanup EXIT

for target in $mutation_targets; do
	slophammer_go mutate . --target "$target"
done

full_mutation_gate_for_static_checks() {
	slophammer-go mutate . --target internal/policy/policy.go
}

if [ "${HF_BROKER_FULL_MUTATION:-0}" = "1" ]; then
	slophammer_go mutate . --target internal/policy/policy.go
else
	slophammer_go mutate . --target internal/policy --scan
	slophammer_go mutate . --target internal/gitproxy --scan
	slophammer_go mutate . --target internal/mirror --scan
fi
