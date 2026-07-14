# Listener Endpoint Architecture Plan

Date: 2026-07-14

Status: ready to implement

## Objective

Remove globally prescribed TCP ports from BrokerKit and every broker. Broker
processes must accept deployment-owned listeners instead of assuming that a
particular port is available. Local privileged traffic should use named Unix
sockets, standard HTTP and Git traffic should enter through an explicitly
configured listener, and clients should consume generated endpoint
configuration rather than infer a port from the broker name.

This is a coordinated fresh-state cutover. The current source defaults include
HF `8080`/`8081`, inconsistent GH direct and setup defaults across
`8080`-`8082`, and sudo `8084`/`8085`. Earlier pre-release installations may
also contain `18080`-`18082`. Remove all of them, along with bind-address/port
config pairs, compatibility readers, and documentation that presents any fixed
port as part of a broker's identity. Existing pre-release installations must
rerun setup after the cutover.

## Design Principles

1. There is no collision-free fixed TCP port, so BrokerKit defines no default
   TCP port.
2. A broker identity is a logical name, not a port number.
3. The deployment layer owns listener allocation, reservation, exposure, and
   TLS termination.
4. Operator and agent endpoints remain separate security boundaries even when
   they use the same transport type.
5. Local production endpoints prefer Unix sockets with filesystem access
   control.
6. TCP listeners are explicit. Wildcard and non-loopback binds require an
   explicit network-exposure acknowledgement.
7. A listener selected during setup is stable across restarts. Brokers do not
   scan for a different port at every launch.
8. Installers continue to install binaries only. Setup and deployment tooling
   create listeners, service definitions, and client configuration.
9. The same endpoint model must work on bare-metal Linux, macOS, containers,
   Kubernetes, foreground development, and reverse-proxy deployments.
10. Startup fails closed when a required production listener is absent,
    ambiguous, unsafe, or already occupied.

## Canonical Endpoint Model

Add a provider-neutral BrokerKit endpoint package. Configuration uses complete
endpoint URIs rather than separate host and port fields:

```text
unix:///run/brokerkit/github/agent.sock
unix:///run/brokerkit/github/operator.sock
tcp://127.0.0.1:52147
activation://agent
activation://operator
fd://3
```

The supported schemes are:

- `unix`: an absolute Unix-domain socket path;
- `tcp`: an explicit host and nonzero port;
- `activation`: a named listener supplied by systemd, launchd, or another
  supported service manager; and
- `fd`: an explicitly inherited file descriptor for supervised processes,
  tests, and container entrypoints.

`activation` is the preferred production abstraction because names remain
stable while each operating system retains its native listener lifecycle.
`fd` is a low-level escape hatch and is never generated into ordinary client
configuration.

The shared model owns:

- strict URI parsing and canonical rendering;
- scheme-specific validation;
- loopback, wildcard, and network-exposure classification;
- Unix path and permission policy;
- listener acquisition and inherited-descriptor verification;
- redacted diagnostics that never expose credentials; and
- conversion into client transports and server listeners.

Provider packages supply only endpoint values and additive filesystem access
requirements. They do not implement their own URI parsing, socket cleanup,
activation handling, or HTTP transport construction.

## Listener Ownership

### Direct Unix sockets

For a local system installation, setup creates separate runtime directories:

```text
/run/brokerkit/huggingface/
/run/brokerkit/github/
/run/brokerkit/sudo/
```

Each directory is root-owned, non-symlinked, and not writable by untrusted
users. Agent and operator sockets use distinct groups and modes. An agent such
as Bob may receive access to the relevant agent socket without receiving access
to the operator socket. Socket mode changes must not broaden access to the
containing runtime directory.

The service manager should own and pre-create production sockets when socket
activation is available. Direct broker-created Unix sockets remain supported
for foreground and environments without activation. Direct creation must
reject unsafe parent paths and remove a stale socket only after proving that it
is a socket owned by the expected service identity and not currently accepting
connections.

### Inherited listeners

Add a small activation boundary with Linux/systemd and Darwin/launchd adapters.
The broker receives a named listener and verifies:

- exactly one listener exists for each configured name;
- the descriptor is a listening stream socket of the expected family;
- its actual local address matches the configured security policy;
- no unexpected inherited listeners are silently accepted; and
- close-on-exec and lifecycle ownership are correct after acquisition.

The core broker runtime consumes `net.Listener`; it does not import systemd or
launchd APIs. Platform adapters end at that interface.

### Explicit TCP

TCP remains necessary for standard Git smart HTTP clients, remote callers, and
some container or orchestrator layouts. A TCP endpoint must always include an
explicit port. Production startup rejects port `0`; foreground development may
request `tcp://127.0.0.1:0` and receive a machine-readable selected endpoint.

Loopback TCP is accepted without a network-exposure override. Wildcard,
non-loopback, and externally routable addresses require an explicit
`network-exposure=allow` setting and a deployment-owned authentication and TLS
story. BrokerKit must not silently convert an omitted host into `0.0.0.0` or
`::`.

## Client Discovery

Extend shared client configuration so each endpoint is represented as a
structured URI plus optional transport metadata. Clients must support HTTP over
both TCP and Unix sockets without changing Agent V1 or Operator V1 payloads.

Generated client configuration contains the selected endpoint explicitly:

```text
BROKERKIT_AGENT_ENDPOINT=unix:///run/brokerkit/github/agent.sock
BROKERKIT_OPERATOR_ENDPOINT=unix:///run/brokerkit/github/operator.sock
```

Provider-specific setup may continue to write provider-prefixed files, but it
must use the shared endpoint fields and renderer. CLI, MCP, OpenClaw, and
trusted delegated-web backends consume the same client transport package.

Development port `0` is intentionally ephemeral. The foreground process emits
one bounded JSON readiness record containing its resolved endpoint. Test
harnesses consume that record directly. Production services never depend on a
mutable discovery file for an ephemeral port.

## Standard HTTP and Git Ingress

Unix sockets are not directly usable by ordinary Git HTTP clients. Support two
production patterns without forcing either one:

1. A broker may receive an explicitly configured or activated TCP agent
   listener directly.
2. A deployment may place a single BrokerKit-aware or general reverse proxy in
   front of broker Unix sockets.

When a shared ingress is used, broker identity is explicit in the route or
virtual host. It is not inferred from a port. The route contract must avoid
collisions between GitHub and Hugging Face repository paths, preserve bounded
streaming and cancellation, forward authentication without logging it, reject
ambiguous path normalization, and never expose an operator socket.

BrokerKit does not need to own TLS, public DNS, certificates, load balancing,
or cluster service discovery. Caddy, nginx, Envoy, Kubernetes Services, cloud
load balancers, and equivalent deployment components may own those concerns.
If a BrokerKit ingress binary is added, it remains a narrow transport router;
it does not become a second policy engine or credential holder.

## Deployment Profiles

### Bare-metal Linux

- Prefer systemd socket activation.
- Use permission-restricted agent and operator Unix sockets.
- Add an explicit activated loopback TCP socket only when ordinary Git HTTP is
  required without a local ingress.
- Write socket URIs or the explicit TCP URL into each authorized client's
  config.

### macOS

- Prefer named launchd sockets for LaunchDaemon installations.
- Use a protected runtime path under `/var/run/brokerkit` for direct Unix
  sockets when activation is unavailable.
- Keep operator sockets inaccessible to ordinary desktop users.
- Generate the same endpoint URI contract used on Linux.

### Containers

- Require the image invocation or manifest to configure every listener.
- Do not put `8080`, another fixed port, or a wildcard bind in the image's
  runtime defaults.
- Accept an inherited descriptor, a mounted Unix socket, or an explicitly
  declared TCP endpoint.
- Treat `EXPOSE` as documentation only and do not use it as listener
  configuration.

### Kubernetes

- Declare container and Service ports explicitly in the deployment manifest
  when TCP is used.
- Prefer Unix sockets for same-pod trusted sidecars.
- Keep the operator endpoint on a separate protected socket or private
  listener that is not part of the agent Service.
- Let the Service, ingress, and network policy own stable addressing.

### Foreground development and tests

- Allow `tcp://127.0.0.1:0`.
- Print the resolved endpoint as structured readiness output.
- Never persist the ephemeral endpoint as a production service setting.

## Configuration Cutover

Replace provider-local bind fields with shared endpoint fields. Delete:

- `*_BIND_ADDR` and `*_PORT` agent settings;
- `*_OPERATOR_BIND_ADDR` and `*_OPERATOR_PORT` settings;
- default functions that return any broker TCP port, including `8080`-`8085`
  and `18080`-`18082`;
- server code that reconstructs addresses with string concatenation;
- duplicate provider HTTP client transports; and
- documentation and examples that identify a broker by a fixed port.

Add explicit provider-prefixed environment variables only as thin inputs to
the shared model, for example:

```text
HF_BROKER_AGENT_ENDPOINT
HF_BROKER_OPERATOR_ENDPOINT
GH_BROKER_AGENT_ENDPOINT
GH_BROKER_OPERATOR_ENDPOINT
SUDO_BROKER_AGENT_ENDPOINT
SUDO_BROKER_OPERATOR_ENDPOINT
```

The exact provider prefix remains useful for independent service environment
files. Parsing, validation, rendering, and runtime behavior remain shared.

There are no compatibility aliases. Setup dry-runs must show the complete new
service and client configuration before applying it. Existing installations
must rerun setup, verify clients, and only then remove their old environment
files and units.

## Implementation Sequence

Implement this as one coordinated cutover branch. Keep each numbered slice
green and commit it separately, but do not merge an intermediate dual-config or
dual-listener architecture.

### 1. Shared endpoint types

- Add canonical URI parsing, validation, rendering, and security
  classification.
- Add table-driven tests for malformed URIs, ambiguous IPv6, relative Unix
  paths, traversal, symlinks, wildcard binds, port `0`, and duplicate listener
  names.
- Define the shared server-listener and client-transport interfaces.

### 2. Unix and inherited transports

- Implement safe Unix listener creation and client dialing.
- Implement generic inherited-fd verification.
- Add systemd and launchd activation adapters behind build tags.
- Prove clean shutdown, descriptor ownership, stale socket handling, and
  restart behavior.

### 3. Shared HTTP clients and servers

- Migrate Agent V1, Operator V1, sealed payload, stream, CLI, MCP, and OpenClaw
  HTTP clients to endpoint-aware transports.
- Make broker HTTP servers accept acquired `net.Listener` values rather than
  host/port strings.
- Preserve existing timeout, redirect, body-limit, authentication, and error
  redaction behavior.

### 4. Service setup

- Extend systemd setup to render socket units and service activation.
- Extend macOS setup with LaunchDaemon socket definitions.
- Generate agent and operator client config from the actual selected
  endpoints.
- Validate ownership and access for every socket path and authorized local
  user.

### 5. Git and network ingress

- Support explicit or activated TCP listeners for direct Git HTTP.
- Define and test the optional shared-ingress route contract.
- Verify clone, fetch, push, LFS, bounded streams, cancellation, and
  authentication over the selected ingress path.
- Keep operator routes unreachable from agent ingress.

### 6. Broker cutover

- Migrate HF, GH, and sudo brokers to the shared endpoint model.
- Remove every fixed production port and old config field in the same slice.
- Regenerate examples, doctor checks, setup output, service files, and client
  files.
- Add an architecture gate that rejects reintroduced fixed listener defaults or
  provider-local endpoint parsing.

### 7. Packaging and deployment fixtures

- Add bare-metal systemd integration fixtures.
- Add macOS launchd validation on a macOS CI runner.
- Add container and Kubernetes examples with explicit listener configuration.
- Verify that installing multiple brokers on one host creates no TCP listener
  collision and no cross-broker socket access.

## Security Requirements

- Agent and operator sockets must never share a filesystem group merely for
  convenience.
- Operator sockets are not exposed through Git or agent ingress.
- Unix parent directories and socket files must reject symlinks, unexpected
  owners, and group/other-writable trusted path components.
- TCP wildcard or non-loopback exposure requires explicit acknowledgement and
  is reported by doctor.
- Inherited descriptors are verified before serving and unexpected descriptors
  cause startup failure.
- Endpoint values are never allowed to inject service-manager syntax, shell
  syntax, query parameters, fragments, or credentials.
- Client authentication remains mandatory regardless of Unix permissions.
  Filesystem permissions are an additional boundary, not a replacement.
- Doctor reports the actual listener type, address class, owner, mode, and
  exposure without printing secrets.
- No automatic fallback may turn a failed Unix or activated listener into a
  TCP listener.

## Test Matrix

The implementation is complete only when all of the following pass:

- parser and canonicalization tests for every endpoint scheme;
- Unix ownership, mode, symlink, stale path, and unauthorized-user tests;
- inherited-fd and activation-name mismatch tests;
- simultaneous HF, GH, and sudo startup on one host without fixed ports;
- an unprivileged agent identity with operator-socket denial;
- Agent V1 and Operator V1 conformance over Unix and TCP transports;
- OpenClaw direct and delegated-web operation over Unix-backed sources;
- GH and HF Git clone/fetch/push through explicit TCP and shared ingress;
- service restart while listeners remain reserved by systemd or launchd;
- container startup failure without explicit listener configuration;
- Kubernetes manifest validation with no implicit broker ports;
- doctor output for local, activated, loopback, and externally exposed
  listeners;
- installer and setup dry-run snapshots for Linux and macOS;
- race, coverage, Slophammer, architecture, and secret-scanning gates; and
- end-to-end installation on clean Linux and macOS hosts.

## Acceptance Criteria

1. Production broker startup has no implicit TCP listener.
2. No production code or maintained deployment example assigns `8080`-`8085`,
   `18080`-`18082`, or another universal broker port.
3. All brokers use one shared endpoint parser, listener acquisition boundary,
   and client transport implementation.
4. Local operator access uses a permission-restricted Unix or activated socket
   by default.
5. Standard Git HTTP remains supported through an explicit direct listener or
   deployment ingress.
6. Multiple brokers and multiple installations can coexist without deriving
   ports from broker names.
7. Linux, macOS, container, and Kubernetes deployments use the same endpoint
   contract while retaining native lifecycle management.
8. Existing broker policy, approval, Telegram, audit, sealed payload, stream,
   CLI, MCP, and OpenClaw behavior remains green after the cutover.
9. The old port fields, defaults, compatibility readers, and duplicated
   transport code are deleted.
10. Documentation describes logical endpoints and deployment ownership, not a
    supposedly safe port range.
