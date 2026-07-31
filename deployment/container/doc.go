// Package container plans and applies Docker Compose based agent and
// credential-service deployments. It never installs Docker, never mounts the
// Docker socket into an unYOLO managed service, and never shares state volumes
// between brokers.
//
// The package is provider-neutral. Broker-specific rendering is performed by
// the release-attested provider adapter and passed to the compose compilers
// here.
package container
