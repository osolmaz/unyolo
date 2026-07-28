#!/bin/sh
set -eu

root=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
image=${UNYOLO_E2E_IMAGE:-golang:1.26.5-bookworm@sha256:1ecb7edf62a0408027bd5729dfd6b1b8766e578e8df93995b225dfd0944eb651}

docker run --rm \
  --volume "$root:/src:ro" \
  --workdir /src \
  "$image" \
  sh -ceu '
    export GOWORK=off GOFLAGS=-buildvcs=false
    useradd --create-home --shell /bin/bash --gid operator operator
    cat >/usr/local/bin/systemctl <<"EOF"
#!/bin/sh
exit 0
EOF
    chmod 0755 /usr/local/bin/systemctl
    go build -o /tmp/unyolo ./cmd/unyolo
    go build -ldflags "-X github.com/osolmaz/unyolo/internal/buildinfo.Version=e2e" -o /tmp/fake-adapter ./internal/host/deployment/testdata/component
    go run ./internal/host/deployment/testdata/pack /tmp/deployment /tmp/fake-adapter
    groupadd --system unyolo-e2e-agent
    usermod --append --groups unyolo-e2e-agent operator

    cp -a /tmp/deployment /tmp/failure-deployment
    sed -i "s#/etc/unyolo-e2e#/proc/unyolo-e2e#g" /tmp/failure-deployment/components/fake.json
    /tmp/unyolo system profile lock --profile /tmp/failure-deployment
    /tmp/unyolo system plan \
      --development --profile /tmp/failure-deployment \
      --root /tmp/failure-runtime --state-dir /tmp/failure-state --json >/tmp/failure-plan.json
    failure_plan=$(awk -F\" '\''/"digest":/ {print $4; exit}'\'' /tmp/failure-plan.json)
    printf "%s" "rollback-secret-canary" >/tmp/failure-secret
    chmod 0600 /tmp/failure-secret
    if /tmp/unyolo system apply \
      --development --profile /tmp/failure-deployment \
      --root /tmp/failure-runtime --state-dir /tmp/failure-state \
      --expect-plan "$failure_plan" --secret-file e2e-token=/tmp/failure-secret; then
      echo "failure fixture unexpectedly applied" >&2
      exit 1
    fi
    ! getent passwd unyolo-agent >/dev/null
    ! getent passwd unyolo-e2e >/dev/null
    ! getent group unyolo-e2e >/dev/null
    id -nG operator | grep -qw unyolo-e2e-agent
    test ! -e /var/lib/unyolo-agent
    test ! -e /var/lib/unyolo-e2e
    test ! -e /tmp/failure-state/deployment-transaction.json

    /tmp/unyolo system profile lock --check --profile /tmp/deployment
    /tmp/unyolo system validate \
      --development --profile /tmp/deployment \
      --root /tmp/runtime --state-dir /tmp/state
    /tmp/unyolo system plan \
      --development --profile /tmp/deployment \
      --root /tmp/runtime --state-dir /tmp/state --json >/tmp/plan.json
    plan=$(awk -F\" '\''/"digest":/ {print $4; exit}'\'' /tmp/plan.json)
    test -n "$plan"
    printf "%s" "clean-host-secret-canary" >/tmp/secret
    chmod 0600 /tmp/secret
    /tmp/unyolo system apply \
      --development --profile /tmp/deployment \
      --root /tmp/runtime --state-dir /tmp/state \
      --expect-plan "$plan" --secret-file e2e-token=/tmp/secret
    test "$(cat /etc/unyolo-e2e/config.json)" = "{\"enabled\":true}"
    test "$(cat /etc/unyolo-e2e/token)" = "clean-host-secret-canary"
    test "$(stat -c %a /etc/unyolo-e2e/token)" = 640
    test -z "$(find /var/lib/unyolo-e2e/backups -name "*.json" -print -quit)"
    getent passwd unyolo-agent >/dev/null
    getent passwd unyolo-e2e >/dev/null
    id -nG unyolo-agent | grep -qw unyolo-e2e-agent
    ! id -nG operator | grep -qw unyolo-e2e-agent
    /tmp/unyolo system verify \
      --development --profile /tmp/deployment \
      --root /tmp/runtime --state-dir /tmp/state
    /tmp/unyolo system export \
      --development --profile /tmp/deployment \
      --root /tmp/runtime --state-dir /tmp/state --json >/tmp/export.json
    ! grep -q clean-host-secret-canary /tmp/export.json
    /tmp/unyolo system plan \
      --development --profile /tmp/deployment \
      --root /tmp/runtime --state-dir /tmp/state --json >/tmp/noop.json
    grep -q '\''"kind": "noop"'\'' /tmp/noop.json
  '
