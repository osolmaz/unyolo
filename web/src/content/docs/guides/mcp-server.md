---
title: Run an MCP server
description: Running a broker as a stdio MCP server, what gets advertised, and how recovery works.
---

Both credential brokers run a strict stdio MCP server that exposes their operation catalog as
tools. The server is an adapter over Agent Operations V1 rather than a second lifecycle, which is
the property that makes an interrupted tool call recoverable.

```sh
hf-broker mcp
gh-broker mcp
```

## Advertised tools

`tools/list` returns the intersection of five things: agent-facing catalog entries, the client's
enabled operations, operations the policy vocabulary makes visible, operations with a registered
runtime adapter, and the operator exposure profile.

Catalog entries without an executor stay discoverable as documentation without becoming runnable
tools. For `gh-broker`, whose generated catalog is large, the full set is browsable through the
paged `github://operations` resource even when only a subset is advertised.

The intersection is worth understanding because it explains a common surprise: an operation in the
catalog that a client cannot see is usually invisible for a policy reason, not a bug.

## Submission and handles

Every ordinary operation tool submits one durable Agent V1 operation and returns immediately with a
closed `brokerkit.io/mcp-operation/v1` projection. That projection deliberately excludes clients,
canonical arguments, approval linkage, and plan data.

Submissions accept an optional `request_id`. Omit it and the broker generates a cryptographically
random one before durable admission. Supply the same ID with the same immutable request and you get
the existing operation back. Supply it with a conflicting request and you get a bounded
`request_id_conflict`.

The internal Agent V1 API calls this value `idempotency_key`. MCP does not expose that name.

## Recovery tools

Each provider exposes three lifecycle utilities with its own prefix:

```text
hf_operation_get     gh_operation_get
hf_operation_wait    gh_operation_wait
hf_operation_list    gh_operation_list
```

Waits default to 25 seconds, never exceed 25 seconds, and return the latest known state on timeout.
Listing defaults to 20 results, caps at 50, uses validated opaque cursors, and supports exact
request-ID recovery. Both are scoped to the authenticated client, so one agent cannot enumerate
another's work.

The reason submission never blocks is worth stating plainly. An LLM tool call that waits for a
human approval burns the model's turn budget doing nothing. Returning a durable handle immediately
lets the agent do something else and come back.

## Authorization and dispatch

Every ordinary provider operation tool enters Agent Operations V1. Static allow, active window
grant, approval request, and deny are authorization outcomes inside that lifecycle rather than
separate MCP dispatch paths.

An allowed operation executes immediately without creating approval state. An approved request
resumes the original durable operation. A matching active window grant authorizes the stored
operation and reserves one use.

The explicit `hf_grant_*` and `gh_grant_*` tools exist only for callers deliberately managing
temporary access that a native protocol such as Git will consume later. Using them as a preflight
before an ordinary operation tool creates approval requests that nobody needed and that an operator
then has to triage.

<div class="callout callout--note">
<span class="callout__title">A read does not need a grant</span>
<p>An allowed private-repository read executes immediately with the broker's credential. It does
not ask for a grant, and it does not expose the token. If your agent is requesting grants before
reads, its instructions are wrong rather than the policy.</p>
</div>

## Package boundaries

Four packages divide the work, and knowing which owns what helps when reading the source.
`mcp/server` owns bounded JSON-RPC and MCP stdio mechanics. `agent/mcp` owns the closed operation
envelope, submission, and lifecycle utility dispatch. `agent/client` owns authenticated Agent V1,
sealed-payload, and stream transport. `mcp/operation` owns request-ID generation, operation and
page projections, bounded recovery, and structured conflicts.

Providers own semantic field aliases, schemas, runtime adapters, result projection, and canonical
provider validation. `operation/capability` owns host compatibility classification and the
bidirectional JSON Pointer projection mechanics behind it.

## Secret safety in transcripts

Tool output goes into an agent transcript, which is a place secrets must never reach. Providers
project public names that collide with supported transcript redactors, and real secrets stay sealed
or credential-slot-backed.

The checked-in provider compatibility manifests summarise catalog-wide conformance against the
pinned host profile, so a regression in that projection is a test failure rather than something
discovered in a log.

## Connecting an agent host

The server speaks MCP over stdio, so any host that can launch a subprocess can use it. The broker
loads its client config from `~/.config/<broker>/client.json` automatically, which means the MCP
command needs no credential in its arguments or environment.

For OpenClaw specifically, the packaged plugin also ships client skills that teach an agent to
reach for the broker instead of hunting for provider credentials. See the
[OpenClaw plugin](/docs/brokers/openclaw).
