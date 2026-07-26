#!/bin/sh
set -eu

root=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
image=${BROKERKIT_E2E_IMAGE:-golang:1.26.5-bookworm@sha256:1ecb7edf62a0408027bd5729dfd6b1b8766e578e8df93995b225dfd0944eb651}

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
    go build -o /tmp/brokerkit ./cmd/brokerkit
    go build -ldflags "-X github.com/osolmaz/brokerkit/internal/buildinfo.Version=e2e" -o /tmp/fake-adapter ./internal/host/deployment/testdata/component
    go run ./internal/host/deployment/testdata/pack /tmp/deployment /tmp/fake-adapter
    groupadd --system brokerkit-e2e-agent
    usermod --append --groups brokerkit-e2e-agent operator

    cp -a /tmp/deployment /tmp/failure-deployment
    sed -i "s#/etc/brokerkit-e2e#/proc/brokerkit-e2e#g" /tmp/failure-deployment/components/fake.json
    /tmp/brokerkit system profile lock --profile /tmp/failure-deployment
    /tmp/brokerkit system plan \
      --development --profile /tmp/failure-deployment \
      --root /tmp/failure-runtime --state-dir /tmp/failure-state --json >/tmp/failure-plan.json
    failure_plan=$(awk -F\" '\''/"digest":/ {print $4; exit}'\'' /tmp/failure-plan.json)
    printf "%s" "rollback-secret-canary" >/tmp/failure-secret
    chmod 0600 /tmp/failure-secret
    if /tmp/brokerkit system apply \
      --development --profile /tmp/failure-deployment \
      --root /tmp/failure-runtime --state-dir /tmp/failure-state \
      --expect-plan "$failure_plan" --secret-file e2e-token=/tmp/failure-secret; then
      echo "failure fixture unexpectedly applied" >&2
      exit 1
    fi
    ! getent passwd brokerkit-agent >/dev/null
    ! getent passwd brokerkit-e2e >/dev/null
    ! getent group brokerkit-e2e >/dev/null
    id -nG operator | grep -qw brokerkit-e2e-agent
    test ! -e /var/lib/brokerkit-agent
    test ! -e /var/lib/brokerkit-e2e
    test ! -e /tmp/failure-state/deployment-transaction.json

    /tmp/brokerkit system profile lock --check --profile /tmp/deployment
    /tmp/brokerkit system validate \
      --development --profile /tmp/deployment \
      --root /tmp/runtime --state-dir /tmp/state
    /tmp/brokerkit system plan \
      --development --profile /tmp/deployment \
      --root /tmp/runtime --state-dir /tmp/state --json >/tmp/plan.json
    plan=$(awk -F\" '\''/"digest":/ {print $4; exit}'\'' /tmp/plan.json)
    test -n "$plan"
    printf "%s" "clean-host-secret-canary" >/tmp/secret
    chmod 0600 /tmp/secret
    /tmp/brokerkit system apply \
      --development --profile /tmp/deployment \
      --root /tmp/runtime --state-dir /tmp/state \
      --expect-plan "$plan" --secret-file e2e-token=/tmp/secret
    test "$(cat /etc/brokerkit-e2e/config.json)" = "{\"enabled\":true}"
    test "$(cat /etc/brokerkit-e2e/token)" = "clean-host-secret-canary"
    test "$(stat -c %a /etc/brokerkit-e2e/token)" = 640
    getent passwd brokerkit-agent >/dev/null
    getent passwd brokerkit-e2e >/dev/null
    id -nG brokerkit-agent | grep -qw brokerkit-e2e-agent
    ! id -nG operator | grep -qw brokerkit-e2e-agent
    /tmp/brokerkit system verify \
      --development --profile /tmp/deployment \
      --root /tmp/runtime --state-dir /tmp/state
    /tmp/brokerkit system export \
      --development --profile /tmp/deployment \
      --root /tmp/runtime --state-dir /tmp/state --json >/tmp/export.json
    ! grep -q clean-host-secret-canary /tmp/export.json
    /tmp/brokerkit system plan \
      --development --profile /tmp/deployment \
      --root /tmp/runtime --state-dir /tmp/state --json >/tmp/noop.json
    grep -q '\''"kind": "noop"'\'' /tmp/noop.json
  '
