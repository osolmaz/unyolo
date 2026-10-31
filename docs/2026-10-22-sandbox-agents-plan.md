---
date: 2026-10-22
author: Onur Solmaz <osolmaz@users.noreply.github.com>
title: Serve sandbox agents in OpenShell and Docker
tags: [setup, agents, sandbox, openshell, docker, telegram, github, tls]
---

# Serve sandbox agents in OpenShell and Docker

## Goal

An agent in a sandbox on the broker host, such as an OpenShell sandbox or a
Docker container, uses stock `gh` and `git` against GitHub through gh-broker.
The agent holds no provider credential. Approvals arrive in Telegram, and the
buttons work for every broker. One `unyolo setup` run installs and connects all
of it, with no manual host steps and no outside service: no overlay network, no
domain, and no public certificate.

## Why the current setup does not fit

The shipped setup supports one agent type: a local Linux account.

- The agent proves its identity with a local Unix socket, guarded by a group,
  plus a client secret in its home directory.
- `sudo-broker` runs approved privileged commands as that agent's Linux user.
- The setup intent already names `container` and `remote` agents, but neither
  ships, and they are designed as separate paths.
- gh-broker has one agent listener, and it is the local Unix socket.

An agent in a sandbox has no host account and cannot use host Unix sockets. For
the broker, an OpenShell sandbox and a Docker container are the same thing: a
client that connects over the network with a secret. They differ only in how
the secret reaches the agent and how the runtime restricts the agent's network.

An agent on another computer is not a sandbox agent. It stays the `remote`
agent type, with the one-use pairing designed in `GUIDED_INSTALLATION.md`, and
it is not part of this plan.

Two operational gaps also exist:

- Telegram approvals have two owners. Every broker holds the bot token and
  sends its own cards, while a separate process, `unyolo-telegram`, reads the
  button clicks and routes them back. That process is not in the release
  bundle, and guided setup does not install it. A host without it shows
  approval cards whose buttons do nothing, and the bot token sits in every
  broker's configuration.
- A host that still runs the older release layout can lose its broker binaries
  during a partial migration while the services keep running from deleted
  files. The next restart then fails.

## What stays

- Brokers run as native systemd services on the host and keep every provider
  credential. A broad provider credential is supported, because the broker
  narrows each request: policy, grants, and approvals decide every call, and an
  installation credential is narrowed to the target repository and minimum
  permissions.
- One broker process per provider, each with its own listeners, state, and
  audit stream.
- Local account agents keep the Unix socket path unchanged.
- The `remote` agent type keeps its pairing design.
- The GitHub-compatible API (`/api/v3` and `/api/graphql`) on the agent
  listener, with Git on the same host. Stock `gh` uses it through `GH_HOST`, and
  Git uses `gh auth git-credential`. The client secret is the token that `gh`
  sends.

## Requirements

- OpenShell v0.1.7 or later. The OpenShell adapter needs the gateway setting
  `[openshell.supervisor.network] additional_ca_bundle`, which first shipped in
  v0.1.7-pre.1. Setup refuses an older OpenShell with a message that names the
  required version.

## Decisions

1. **A sandbox agent is a broker client, not an account.** Each agent gets its
   own client id, client secret, and policy rules. No Linux account is created
   for it. The client secret is a static shared secret, rotated through setup.
   Short-lived workload credentials are not planned.
2. **Sandbox agents connect to a separate TLS listener.** gh-broker gets a
   second agent listener, `sandbox`, next to the local Unix socket. It serves
   the same agent API and accepts only TLS. The adapter selects the address:
   - OpenShell: a loopback address on the host. The OpenShell supervisor uses
     the host network and reaches it as `host.openshell.internal`, the name
     that OpenShell gives to services on the gateway host. Nothing outside the
     host can reach the listener.
   - Docker: the container bridge address, when that adapter ships.

   There is no plain TCP and no wildcard bind address.
3. **One core, one adapter per runtime.** The setup core creates the client,
   its secret and policy, the certificates, and the TLS listener. A runtime
   adapter turns that into the files and commands for one runtime, and setup
   runs those commands. Brokers contain no runtime-specific code.
4. **Each adapter declares where the client secret lives:**
   - `injected`: the runtime adds the secret outside the agent, so code in the
     agent cannot read it. OpenShell does this with a provider placeholder.
   - `in_agent`: the agent can read the secret, from a mounted file or from
     its own credential store.

   Setup states which case applies before it asks for approval.
5. **Setup owns a private certificate authority.** Setup creates a CA and signs
   the `sandbox` listener certificate with it, using only the Go standard
   library.
   - The CA carries critical name constraints that permit only the listener
     names, `host.openshell.internal` and `127.0.0.1`, so it cannot
     authenticate any other site.
   - Setup clears the CA key once the certificate is signed. The key never
     reaches a disk, and the CA can never sign anything else. The broker reads
     only the listener certificate and key files, as it does today.
   - The CA certificate is not secret. The OpenShell adapter gives it to the
     gateway through `additional_ca_bundle`. The Docker adapter mounts it into
     the container.
   - No public certificate, overlay network, or domain is involved.
6. **One Telegram owner per bot.** `unyolo-telegram` is the only process that
   holds the bot token. It follows each broker's Operator V1 event stream,
   sends and updates the approval cards, reads the button clicks, and decides
   through the owning broker's Operator V1 API. Brokers contain no Telegram
   code and no Telegram configuration. The operator inbox stays the same.
7. **No `sudo-broker` for sandbox agents.** It runs host commands as root for a
   local agent account. A sandbox agent has no such account and must not run
   host commands. Setup refuses to connect `sudo-broker` to a sandbox agent.

## Adapters

| Adapter | Runtime | Listener address | Secret | Network restriction | CA delivery |
| --- | --- | --- | --- | --- | --- |
| `openshell` | OpenShell sandbox | Loopback, reached as `host.openshell.internal` | `injected` | OpenShell network policy | Gateway `additional_ca_bundle` |
| `docker` | Docker container on the broker host | Container bridge address | `in_agent` | Container network | File mounted read-only |

The adapter contract is the same for both:

- **Input:** connection name, client id, secret slot, listener address and
  name, CA certificate, and the providers to connect.
- **Output:** the runtime files, the commands that setup runs, and the
  declared secret placement. A secret is written only to a file with
  owner-only access and is never printed.
- **Agent environment:** `GH_HOST`, the Git `insteadOf` rule for
  `https://github.com/`, and `gh auth git-credential` as the Git credential
  helper.

This plan builds the `openshell` adapter first. `docker` moves onto the shared
core when it ships, and keeps its existing design for secret delivery.

## Work

### 1. Make `unyolo-telegram` the single Telegram owner

Done in v0.9.0.

- **Cards.** For each configured broker, `unyolo-telegram` follows the
  Operator V1 event stream (`/api/operator/v1/events`) from a cursor that it
  stores durably. On `request.created` it reads the request, renders the card
  with the shared renderer, sends it, and stores the message id, the rendered
  content, and its digest. On later events it edits the card to the new state:
  approved, denied, expired, canceled, used, or failed. A restart resumes from
  the stored cursor and does not send a card twice.
- **Clicks.** It accepts a click only from the configured chat and operator. It
  matches the click to the stored message and digest, then decides through the
  broker's Operator V1 API with the request's expected revision and an
  idempotency key derived from the click. A repeated click returns the current
  state and makes no second decision. Transient broker failures retry with a
  bound, as in the current inbox.
- **Brokers.** Remove the Telegram notifier, its outbox, and the bot token and
  chat id settings from `gh-broker`, `hf-broker`, and `sudo-broker`. This is a
  hard cutover: a broker that still has Telegram settings fails its config
  check with a message that names the setting to remove.
- **Release and setup.** Add `unyolo-telegram` and its systemd unit to the
  release bundle, checksums, and SBOM. Add a Telegram step to `unyolo setup`:
  bot token file, chat id, and the route of each installed broker. Setup copies
  the bot token only into the configuration of `unyolo-telegram`, and takes
  each operator secret from the broker it installs, never from a command-line
  value. It installs `unyolo-telegram.service`, adds its account to each
  broker's operator socket group, and checks every route before it reports
  success.
- **One owner.** Setup refuses to install a second owner for the same bot
  token, and the doctor reports any other process that uses the bot.
- **Docs.** Rewrite `docs/TELEGRAM_INGRESS.md` and the Telegram section of
  `docs/CHAT_APPROVAL_SECURITY.md` for the single owner when this ships.

### 2. Add the sandbox listener and the sandbox agent core

Built: the broker listener in PR #156, the rest with the OpenShell adapter.

- **Broker.** Add the optional `sandbox` agent listener to gh-broker. It
  requires TLS and serves the same agent handler as the Unix socket, so the
  GitHub-compatible API, Git, and the agent API work on both.
- **Setup intent.** Add one `sandbox` location with a `runtime` field. It
  accepts `openshell` today. The existing `container` location keeps its
  Compose design until the `docker` adapter moves onto the sandbox core, and
  `remote` stays as it is. A sandbox agent uses the `sandbox` transport, which
  has no address fields: the broker and the adapter choose the address. This
  is an in-place change to setup intent v1.
- **Providers.** A provider that serves sandbox agents sets `sandbox_agents` in
  its setup descriptor. A sandbox connection gets only those providers, so
  `sudo-broker` never connects to a sandbox.
- **Render metadata.** A provider's renderer declares its `sandbox_access`: the
  loopback port of its listener, the variable for the client secret, plain
  environment variables with `{host}` and `{origin}` for the sandbox address,
  and the binaries that may use it. The adapter adds the runtime's address, so
  setup holds no provider details and the broker holds no runtime details.
- **Setup.** For a sandbox agent, setup:
  - creates the client id, the secret slot, and a policy rule set for the
    client, starting from the request-everything preset;
  - configures the `sandbox` listener on the address that the adapter selects,
    and refuses a wildcard bind address;
  - calls the adapter and shows its declared secret placement in the review
    step.
- A sandbox agent creates no Linux account and no client file in a home
  directory on the broker host.

### 3. Certificates

- When the plan installs a sandbox listener certificate, setup creates one CA
  with critical name constraints for the listener names, signs a certificate
  valid for two years for each listener, and clears the CA key.
- A new certificate therefore comes with a new CA. The gateway reads the CA
  only at startup, so the adapter restarts the gateway and the connected
  sandboxes. A setup run that keeps the certificate changes nothing in
  OpenShell.
- `gh-broker doctor github` warns 30 days before the listener certificate
  expires and fails after it expires.

### 4. Build the OpenShell adapter

- Write an OpenShell provider profile: one credential bound to
  `GH_ENTERPRISE_TOKEN`, endpoints for `host.openshell.internal` and the
  listener port with REST and GraphQL inspection, and binaries `gh` and `git`.
- The provider profile's endpoint is the sandbox network policy, so no
  separate policy fragment is needed.
- Write the CA bundle file and set `[openshell.supervisor.network]
  additional_ca_bundle` in the gateway configuration. Setup edits the file only
  when it has no supervisor network table, checks the result with
  `openshell-gateway config preflight`, and restores the file if the check
  fails. The gateway reads the CA only at startup, so setup restarts the
  gateway and then stops and starts each connected sandbox. This happens at
  the first connection and when the CA changes.
- Create the provider with the client secret and attach it to the sandbox.
  Setup runs the `openshell` commands as the account that owns the gateway,
  which is the account that runs setup. The secret travels only in the
  command's environment and is never printed.
- OpenShell sets a sandbox's environment only when it creates the sandbox; a
  provider's config keys do not reach it. Setup writes the environment to
  `~/.config/unyolo/sandboxes/<sandbox>.env` and shows the `--provider` and
  `--env` options for a sandbox that does not exist or lacks the environment.

### 5. Release-layout migration

- Treat a host with the older release layout as a fresh-state cutover: setup
  installs every selected broker from one release, stops and removes the old
  units and Telegram process only after the new ones are installed and
  healthy, and never deletes a binary that a running unit still uses.
- `unyolo setup` and `unyolo repair` must refuse to remove provider files that
  belong to brokers outside the current session, instead of reconciling them
  as legacy.
- Discarded or abandoned sessions leave the host unchanged.

### 6. Hugging Face

- Out of scope for this plan. A later plan adds a compatible endpoint for the
  Hugging Face client in the same way, so a sandbox agent can use stock `hf`.

## Verification

First, before the code: a probe in a temporary OpenShell sandbox with a test
TLS server on a loopback address confirms that `host.openshell.internal`
reaches it, that the gateway trusts the test CA through
`additional_ca_bundle`, that the provider placeholder is replaced in the
request, and that `gh` accepts the `GH_HOST` value with its port.

Then an end-to-end run in a real OpenShell sandbox, with a broker installed by
`unyolo setup` and nothing installed by hand:

- `gh api`, `gh pr list`, `gh pr view --json`, `gh pr checks`, and
  `gh api --paginate` return GitHub data.
- `git clone` and `git push` of a branch work. The push waits for a Telegram
  approval, the button press changes the card, and the push completes.
- A repository without a rule returns `403`, and `curl` to the broker is
  blocked by the sandbox policy.
- No file, environment variable, or process argument in the sandbox contains
  the client secret.
- The CA cannot authenticate a name outside its constraints.
- The local Unix socket keeps working for local account agents.
- Restarting each broker and `unyolo-telegram` keeps pending approvals,
  cards, and button handling working, and sends no duplicate cards.
- The bot token exists only in the configuration of `unyolo-telegram`.
- Unit and integration tests cover the sandbox intent, the `sandbox` listener,
  the CA and certificate issue, the adapter contract, the generated OpenShell
  files, and the refusal cases.

When the `docker` adapter ships, the same end-to-end checks run for it, except
the secret check, which then confirms that the secret exists only in the
declared place.

## Non-goals

- Running brokers inside sandboxes or containers.
- Exposing the agent listener to the internet.
- Public certificates, overlay networks, or domains for sandbox agents.
- Runtime-specific code in brokers.
- Short-lived workload credentials for sandbox agents.
- Agents on other computers. They stay the `remote` agent type.
- Adapters for other runtimes in this plan.
- Approving through a different chat application.
- Compatibility with the older release layout after the cutover.
