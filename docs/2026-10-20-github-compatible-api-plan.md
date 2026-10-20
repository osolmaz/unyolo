---
title: "GitHub-Compatible API Plan"
author: "Onur Solmaz"
date: "2026-10-20"
---

# GitHub-Compatible API Plan

Date: 2026-10-20

## Context

An agent in a sandbox should use the stock GitHub CLI (`gh`) without a GitHub
credential in the sandbox and without a wrapper or a patched `gh`. Today the
agent can reach gh-broker for Git smart HTTP and for typed Agent V1
operations, but `gh` itself speaks the GitHub REST and GraphQL APIs. The agent
therefore needs either a GitHub token, which defeats the broker, or a second
tool, which the operator does not want.

`gh` already supports GitHub Enterprise Server hosts. With `GH_HOST` set to a
host name, it sends REST calls to `https://HOST/api/v3/...`, GraphQL calls to
`https://HOST/api/graphql`, and Git traffic to `https://HOST/OWNER/REPO.git`,
with `Authorization: token $GH_ENTERPRISE_TOKEN`. If gh-broker serves these
three surfaces on one listener, stock `gh` works against the broker, and the
broker client secret is the only value the sandbox holds.

## Design change

The 2026-07-14 operation coverage plan made these non-goals: a generic REST
proxy, arbitrary GraphQL, caller-supplied REST paths or GraphQL documents, and
raw upstream responses. Stock `gh` needs caller-supplied paths and documents,
and it reads full upstream responses. This plan replaces those non-goals with
a narrower rule:

- The broker accepts a GitHub REST path or a GraphQL document only on the
  GitHub-compatible routes, and only when it classifies the request to exactly
  one catalog operation or one reviewed GraphQL shape. It refuses every other
  request before any upstream call.
- Policy, grants, approvals, and audit apply to the classified operation, as
  they do for Git smart HTTP.
- Each forwarded request uses an installation token narrowed to the target
  repositories and to the minimum permissions of the classified operation, so
  GitHub itself rejects anything outside that scope.
- The broker returns the upstream status, body, and safe headers. It removes
  credential headers and never forwards operations that take sealed input or
  return a credential.

The typed Agent V1 surface, its immutable plans, and its projections do not
change.

## Scope

- Routes `/api/v3/*` (REST) and `POST /api/graphql` on the agent listener.
  They accept the `token` and `Bearer` authorization schemes with the broker
  client secret, and they return GitHub-style JSON errors.
- REST classification: match the method and path against the reviewed REST
  bindings. Literal segments must match; a terminal `path`, `ref`, or `branch`
  parameter may span more than one segment. The most specific template wins;
  a tie is refused. The operation must be implemented, agent-facing, use an
  installation credential, take no sealed input, return no credential, and
  target one repository.
- REST policy attributes use the same attribute vocabulary as the typed
  surface: authorization path parameters, declared query parameters, and the
  JSON body. A request that would need more than one value for one attribute
  is refused, because native requests carry one value per attribute.
- GraphQL classification, after a full parse of the document:
  - A query whose root fields are only `__type`, `__schema`, and `__typename`
    is schema introspection. `gh` sends these to every Enterprise host for
    feature detection. The broker forwards it with a metadata-only token.
  - A query whose root fields are `repository(owner:, name:)`, `node(id:)`,
    `viewer`, and `__typename` reads repositories. Each node is resolved to its
    repository first. Each repository is checked as the new `graphql.read`
    operation, and the forwarded token is narrowed to those repositories with
    read-only permissions from a reviewed list.
  - A mutation with exactly one root field from a reviewed table maps to the
    equivalent REST catalog operation, for example `mergePullRequest` to
    `pull_request.merge`. The broker resolves the subject node id to its
    repository and number, evaluates policy for that operation and target, and
    forwards the mutation with the token of that operation.
  - Everything else is refused: subscriptions, other root fields, fragments or
    directives at the root, and mutations outside the table.
- Approvals: a requestable decision creates the same idempotent grant request
  as Git transfers, sends the approval card, and holds the HTTP request until
  the operator decides or the request expires. Approval then continues the
  same request. Denial or expiry returns `403` with the grant id.
- Responses: `Link` and `Location` headers that point at the upstream API are
  rewritten to the broker host so `gh --paginate` keeps using the broker.
  Repository-id links (`/repositories/{id}/`) of a call scoped to one
  repository become `/repos/{owner}/{repo}/` links.
- Git on the agent listener: a request without credentials gets a `Basic`
  challenge, so Git sends the secret from `gh auth git-credential`.
- Policy presets add a requestable `graphql.read` rule next to the Git
  transport rules.

## Non-goals for this first version

- GraphQL `search`, `nodes`, `organization`, `user`, and viewer-only queries.
  Use REST, or name a repository or node.
- GraphQL mutations outside the table, including label and project
  mutations, and mutation inputs with `labelIds`.
- Release asset uploads (`/api/uploads`), Codespaces, Copilot, and
  `gh auth login`.
- Operations that use a user credential or the App JWT.
- Repositories outside the App installations, such as an upstream parent of a
  fork, in GraphQL reads.
- Deployment configuration: a TLS agent listener, the sandbox `GH_HOST`, the
  client secret placeholder, and a Git `insteadOf` rule are operator
  configuration and are not part of this change.

## Verification

- Unit tests for REST matching, GraphQL classification, the mutation table,
  token narrowing, node resolution, approvals, refusals, and header rewrites.
- A local smoke test with stock `gh` against a TLS broker listener and a fake
  GitHub upstream.
- The end-to-end check against GitHub from the sandbox needs a deployment and
  stays open until the operator deploys this change.
