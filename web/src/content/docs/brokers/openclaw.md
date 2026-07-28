---
title: OpenClaw plugin
description: The openclaw-brokerkit package, its approvals tab and client skills, and the three trust modes.
---

`openclaw-brokerkit` is an OpenClaw plugin that adds a provider-neutral Approvals tab and
`/brokerkit` commands to OpenClaw. It connects to one or more BrokerKit Operator V1 sources. The
brokers remain authoritative and keep all provider credentials and executable plans.

The minimum supported host is `openclaw@2026.7.1`, the first stable SDK the package uses that
includes public tab descriptors.

## Install

```sh
openclaw plugins install npm:openclaw-brokerkit@<version>
```

From a local checkout, build and link the package explicitly:

```sh
pnpm --filter openclaw-brokerkit build
openclaw plugins install --link ./plugins/openclaw
```

## Client skills

The enabled plugin automatically provides `gh-broker`, `hf-broker`, and `sudo-broker` skills. They
teach agents to use the installed broker clients instead of looking for upstream provider
credentials or unrestricted privilege escalation.

OpenClaw loads the skills from the plugin package rather than copying them into the agent
workspace. A skill becomes eligible only when its matching broker executable is available, and the
skill itself grants no access. An agent that reads the `hf-broker` skill on a machine without
`hf-broker` installed simply does not see it.

This solves a problem that is easy to underestimate. An agent that does not know a broker exists
will keep looking for `HF_TOKEN`, fail, and then try something creative.

## Trust modes

The plugin has three modes, and the default is the least trusting one.

`skills-only` is what you get when configuration is absent. It loads the packaged client skills and
registers no approval UI, routes, commands, or background service.

`direct` trusts the OpenClaw process with operator SecretRefs. It enables the Approvals tab,
background reconciliation, `/brokerkit` commands, and channel delivery.

`delegated-web` packages only the tab UI and delegates authenticated browser requests to a
same-origin trusted backend. OpenClaw receives no broker credential and registers no command or
background source service.

The choice is about where the operator credential lives. In `direct` mode it lives in the OpenClaw
process, which means OpenClaw is a trusted operator client. In `delegated-web` mode it lives in
your backend and OpenClaw only renders.

## Direct mode configuration

```json5
{
  plugins: {
    entries: {
      brokerkit: {
        enabled: true,
        config: {
          mode: "direct",
          brokers: [
            {
              id: "hf-primary",
              // endpoint, operator credential reference, and display name
            },
          ],
        },
      },
    },
  },
}
```

Broker sources are registered statically. Browser input cannot select an endpoint, a credential, a
proxy, a header, or an executable plan, which is the property that keeps a rendered tab from
becoming an authority surface.

## Operator V1 consumers

Trusted hosts can consume the same generated Operator V1 types and runtime validators as the
plugin, without installing OpenClaw:

```ts
import {
  parseRequestPage,
  type RequestPage,
} from "openclaw-brokerkit/operator-v1";

const page: RequestPage = parseRequestPage(await response.json());
```

The subpath is generated from BrokerKit's canonical OpenAPI document. Its standalone validators use
no runtime code generation and reject unknown fields, invalid bounds, unsafe integers, and protocol
drift.

That makes it a reasonable dependency for a bespoke approvals UI even if OpenClaw is not part of
your setup.

## Plugin data access

The plugin is a trusted operator client, and its browser and outbound messages receive only the
safe Operator V1 projection. Requests carry the bounded presentation model: a title, a summary,
targets, risk, warnings, provider facts, and a plan hash. They do not carry provider execution
plans or credentials.

A decision from the plugin contains only the request ID, the expected revision, an idempotency key,
and bounded approval narrowing. The broker applies it to its own canonical stored request. The
aggregate UI payloads are defined in the same OpenAPI document: `UISnapshot` is the full
authoritative view, `UISnapshotEvent` is a cursor-only invalidation for bounded authenticated long
polling, and `UISummary` drives host badges without exposing request details.

## Aggregating several brokers

A host may aggregate several brokers into one view, but each broker stays the source of truth for
its own requests. One broker being down or rate-limited makes its source unhealthy without changing
another broker's authority.

The host should persist only UI preferences and durable event cursors. On disconnect or restart it
reconnects from the last cursor. On `cursor_expired` it refreshes that broker's bounded list,
replaces its local view, and starts from the newest returned lifecycle state.
