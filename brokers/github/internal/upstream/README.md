# Pinned GitHub metadata

This directory contains immutable upstream inputs used to generate the GitHub
operation inventory. Runtime builds and tests never fetch network content.

Run `go generate ./brokers/github/internal/upstream` to regenerate BrokerKit
artifacts from the checked-in snapshots. Refreshing a snapshot is a separate,
explicit review task; the generator does not update upstream inputs.
