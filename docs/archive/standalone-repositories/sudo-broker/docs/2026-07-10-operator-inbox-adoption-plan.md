# Operator Inbox Adoption Plan

Date: 2026-07-10

Status: implemented

## Goal

Cut `sudo-broker` over to Brokerkit's shared operator inbox while preserving
its Unix-specific policy, execution, shell-session, and privilege boundaries.

This work must build on pull request
[#7](https://github.com/osolmaz/sudo-broker/pull/7), which makes notification
references, lifecycle status delivery, and uncertain execution settlement
durable. It must not replace or fork that state machine.

`sudo-broker` keeps client grant creation and status routes on its agent
listener. Brokerkit's operator routes run on a separate authenticated listener
and are the only HTTP surface for cross-client review and decisions.

## Ownership

Brokerkit owns bounded grant queries, common decisions, lifecycle events,
operator-safe DTOs, authentication primitives, handlers, fixtures, and
optional notification delivery.

`sudo-broker` continues to own command catalogs, request reclassification,
target users, shell semantics, privileged execution, session management,
Unix-specific presentation, and settlement across the privilege boundary.

## Required Changes

- rebase the adoption on pull request #7 or its merged result;
- implement the Brokerkit presenter for fixed-command and shell grants;
- replace local grant query and decision handlers with the common handler;
- preserve the existing separate operator authority for operator mutations;
- add `GET /api/grants/events` using Brokerkit's durable event cursor;
- allow requests to remain pending when Telegram is not configured;
- keep Telegram as an optional notification view over the same grant;
- preserve all pre-start, post-start, ambiguous-settlement, reservation, and
  session safety behavior from pull request #7;
- run Brokerkit conformance fixtures alongside privileged-boundary tests.

## Acceptance

- the same grant can be decided through Telegram or the operator API exactly
  once;
- no notifier is required for a pending request to exist and be reviewed;
- client credentials cannot list cross-client requests or make decisions;
- restart and reconnect preserve requests, history, and event delivery;
- no response or event exposes approval tokens, command input or output,
  session transcripts, broker secrets, or privileged environment data.

## Implemented Shape

- The agent listener defaults to `127.0.0.1:8082` and accepts only broker
  client credentials.
- The operator listener defaults to `127.0.0.1:8083` and uses a dedicated
  named credential from `/etc/sudo-broker/operator-secrets`.
- Brokerkit owns operator authentication, bounded list/detail projections,
  durable event cursors, optimistic revisions, decisions, and audit records.
- Sudo Broker owns only the Unix presenter and the command, shell, execution,
  session, and privilege-boundary logic.
- Telegram and the operator API decide the same grant store. A missing or
  unavailable Telegram transport does not prevent a durable pending request.

## Validation

The acceptance suite covers operator-only requests, Telegram delivery outage,
shared operator decisions, authentication separation, listener collision,
restart-safe grant storage, SSE events, and presentation redaction. Existing
execution and PTY tests continue to cover reservation settlement and the Unix
privilege boundary.

The release installer is a thin, revision-pinned wrapper around Brokerkit's
shared installer. Sudo Broker owns only its binary name and repository
identity; platform detection, release selection, checksum verification, and
global installation remain implemented and tested once in Brokerkit.
