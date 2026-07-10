# Operator Inbox Adoption Plan

Date: 2026-07-10

Status: implemented

## Goal

Adopt Brokerkit's provider-neutral operator inbox so a trusted browser, CLI,
or desktop application can review and decide GitHub approval requests without
requiring Telegram.

This is not a new grant system. `gh-broker` already exposes agent-authenticated
`POST /api/grants`, `GET /api/grants`, and `GET /api/grants/{id}` and already
uses Brokerkit grants and notification primitives. The adoption must reuse the
same durable grants and remove duplicate broker-local query and decision code.

## Ownership

Brokerkit owns bounded pending and history queries, approve/deny/cancel/revoke
transitions, lifecycle events, operator-safe response shapes,
operator-authentication primitives, common handlers, and optional notification
delivery.

`gh-broker` owns GitHub operation and target classification, GitHub App or
development PAT credentials, canonical execution plans, GitHub-specific risk
and display text, execution, auditing, and the operator transport boundary.

## Required Changes

- implement the Brokerkit presenter for GitHub grants;
- mount the common `/api/grants` operator surface behind a separate operator
  authority;
- keep agent reads client-scoped and prevent agent credentials from deciding;
- stream lifecycle events through `GET /api/grants/events`;
- allow request creation when Telegram is absent, leaving the request pending
  in the durable inbox;
- retain Telegram as an optional notification view;
- delete local handler and transition logic replaced by Brokerkit;
- add Brokerkit conformance fixtures plus GitHub-specific presentation and
  execution tests.

## Acceptance

- one durable grant is visible through Telegram, the operator API, or both;
- decisions through either transport update the same state exactly once;
- restart and reconnect recover pending requests and event cursors;
- no operator response contains GitHub credentials, decision tokens, raw
  request bodies, or unsafe upstream responses;
- existing narrow GitHub and Git smart-HTTP enforcement remains unchanged.
