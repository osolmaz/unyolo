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
