# Approval Presentation Cutover Plan

Date: 2026-07-17

Status: implemented

## Objective

Give every broker and every operator channel one consistent, secure approval
experience without centralizing provider policy or execution semantics.

BrokerKit will own a channel-neutral, bounded approval view and the renderers
that turn that view into Telegram, web, terminal, and future channel output.
Hugging Face, GitHub, and sudo will only describe their own operation, target,
risk, warnings, and provider-specific facts.

This is a coordinated pre-release cutover. There is no backward compatibility
requirement for the current notification payload, rendered messages, persisted
notification records, callback wording, provider-local message builders, or
custom Telegram button labels. Replace version 1 in place, require fresh state
where persisted shapes change, and delete every replaced path in the same
change. Do not add adapters, aliases, dual rendering, fallback text, legacy
readers, or migrations.

## Required Outcomes

1. One root package owns the bounded semantic approval presentation contract.
2. The existing operator inbox and every notification channel consume that
   same contract.
3. Provider packages own only provider-specific presentation data and never
   render Telegram or other channel markup.
4. Telegram pending and terminal messages have one consistent layout, labels,
   emoji vocabulary, button set, and status behavior.
5. Decisions are represented by typed lifecycle states rather than
   broker-authored status strings.
6. Approval and denial buttons disappear whenever a request is no longer
   pending.
7. Rendering is deterministic, bounded, injection-safe, UTF-8-safe, and
   testable without a live Telegram bot.
8. The exact bounded presentation and rendered notification shown to an
   operator remain available for durable audit and retry behavior.
9. Provider operation names, target interpretation, risk classification,
   warnings, and execution authority remain provider-local.
10. The handwritten HF, GitHub, and sudo Telegram presentation paths are
    deleted.

## Design Principles

### One semantic view, many renderers

The semantic approval view is the shared boundary. It contains safe operator
meaning, not transport syntax. Telegram formatting, HTML escaping, emoji,
button labels, and message limits do not belong in a provider package.

Renderers consume the view independently:

```text
canonical grant + immutable plan
             |
             v
provider Presenter
             |
             v
bounded approvalview.View
       |           |
       v           v
operator API   notify message
                   |
             channel Renderer
                   |
          Telegram / future channels
```

The operator inbox remains the durable backend for web applications. It does
not render Telegram. Notification transports remain optional views over the
same canonical grant state machine.

### Presentation never grants authority

The view is descriptive only. Approval continues to bind the immutable
operation, target, attributes, plan digest, duration, use count, revision, and
decision token held by the canonical grant machinery. Rendered text is never
parsed to authorize or execute an operation.

### Shared mechanics, provider-owned meaning

BrokerKit owns validation, normalization, generic request facts, risk display,
layout, rendering, status transitions, and transport behavior. Providers own
the meaning of their operation catalogs and produce only bounded semantic
values.

The root package must not contain Hugging Face operation names, GitHub target
rules, sudo command semantics, provider-specific risk tables, or branches on a
provider ID.

## Package Architecture

### New `approvalview` root package

Move the provider-neutral presentation types and validation currently owned by
`operatorinbox` into a small root `approvalview` package. The exact API should
remain narrow, but it should express these concepts:

```go
type Risk string

const (
	RiskUnknown  Risk = "unknown"
	RiskLow      Risk = "low"
	RiskMedium   Risk = "medium"
	RiskHigh     Risk = "high"
	RiskCritical Risk = "critical"
)

type Fact struct {
	Label string
	Value string
}

type Warning struct {
	Severity Risk
	Text     string
}

type Presentation struct {
	Title    string
	Summary  string
	Target   string
	Risk     Risk
	Facts    []Fact
	Warnings []Warning
	PlanHash string
	Audit    []Fact
}

type Presenter interface {
	Present(context.Context, grants.Grant) (Presentation, error)
}
```

The package owns bounds, control-character rejection, copying, validation, and
the safe generic fallback. It must reject invalid provider output rather than
silently passing malformed text to a renderer. The fallback must visibly mark
presentation data as unavailable while retaining the canonical request.

Use the canonical Operator V1 OpenAPI schemas for wire representations. Update
the version 1 presentation schema in place to include structured warnings if
they are exposed to web clients, regenerate Go and TypeScript artifacts, and
delete handwritten duplicate wire shapes. `approvalview` remains the internal
domain model; it is not a second wire specification.

### Shared notification envelope

Replace `notify.ApprovalMessage` with a semantic envelope containing:

- grant ID and opaque decision token;
- broker display name;
- requester identity;
- operation identifier;
- reason;
- requested duration and use limit;
- pending expiry;
- the validated `approvalview.Presentation`; and
- no raw rendered text or arbitrary transport markup.

Delete `ApprovalMessage.Text` and the provider-local fallback fields that
duplicate the presentation. Construction should go through one shared projector
so the operator inbox and notifications apply identical bounds and fallback
behavior.

Do not place secrets, credentials, provider request bodies, execution payloads,
or unrestricted attribute maps in the envelope.

### Channel renderers

Define a renderer at the notification-channel boundary. It receives only the
validated semantic envelope and a typed lifecycle state. It returns a bounded
rendered message plus channel controls.

The Telegram renderer belongs in `notify/telegram` and owns:

- pending-message layout;
- terminal-message layout;
- fixed `✅ Approve` and `❌ Deny` controls;
- risk and status emoji;
- strict escaping for the selected Telegram parse mode;
- deterministic ordering of facts and warnings;
- Telegram text and callback limits;
- UTF-8-safe truncation with a visible truncation marker;
- removal of controls for every non-pending state; and
- stable handling of an already-updated message.

Providers cannot override button labels, callback answers, parse mode, status
phrasing, or layout. Delete `ApproveText`, `DenyText`, and `IgnoredAnswer` from
Telegram options. Configuration should contain transport behavior only.

Use centrally generated Telegram HTML so headings and important values have a
consistent visual hierarchy. Brokers must never supply raw HTML. The renderer
must escape every dynamic value before applying its own fixed markup, and no
configuration may enable provider-supplied formatting.

### Typed terminal states

Replace free-form status strings passed through `notify.Notifier.UpdateStatus`
and `notify.DecisionResult` with one typed presentation state derived from the
canonical grant transition:

- approved and active;
- denied;
- expired while pending;
- expired after activation;
- consumed;
- revoked;
- canceled by requester;
- retained/ambiguous execution closed; and
- failed to commit, which remains retryable and does not close controls.

The shared state mapper owns callback answers and human-readable status text.
Provider code returns canonical transition results, not prose. Repeated taps
must report the current terminal state, never a misleading `not found` result,
and must not create a second decision.

## Canonical Telegram Layout

Pending messages use one layout:

```text
🔐 Approval needed for GitHub

👤 Requester: agent-a
⚙️ Operation: repository.delete
📍 Target: example/project
🛡️ Risk: critical

Delete repository
Permanently delete the selected repository.

Details
• Visibility: private
• Plan digest: sha256:...

📝 Reason: Remove an obsolete test repository
⏱️ Access: 5 minutes
🔁 Uses: 1
⌛ Request expires: 2026-07-17 10:00 UTC

⚠️ This operation permanently deletes the repository.
```

The broker name, title, summary, facts, and warning text are data. The ordering,
labels, generic icons, punctuation, whitespace, duration/use wording, and risk
presentation are shared. Empty optional sections disappear without leaving
blank structural artifacts.

Terminal rendering preserves the pending snapshot and appends or replaces one
authoritative status block, for example:

```text
✅ Approved. Access is active.
```

Every terminal edit clears the inline keyboard in the same Telegram request
where possible. Retry and reconciliation must converge on the same text and
empty keyboard after crashes or ambiguous Telegram responses.

## Provider Cutover

### Hugging Face

- Keep Hugging Face operation wording, target projection, risk mapping, plan
  title, plan summary, plan digest, refs, modes, and safe attributes in its
  provider presenter or operation catalog.
- Convert the current rich HF message into the initial shared renderer fixture.
- Move operation descriptions out of the Telegram-specific `message.go` path
  so the inbox and every channel use the same wording.
- Delete `brokers/huggingface/internal/approval/message.go` after its semantic
  data has moved into the provider presenter/catalog.
- Remove `approval.Text`, `approval.Message`, raw notification text, custom
  emoji status strings, and broker-local terminal formatting.

### GitHub

- Keep GitHub target summaries, operation descriptors, generated projection
  facts, risk mapping, plan summaries, and destructive warnings in the GitHub
  presenter/catalog.
- Prefer catalog descriptions over exposing raw operation identifiers as the
  only operator-facing title, while retaining the identifier as a fact.
- Delete the handwritten `fmt.Sprintf` Telegram body in
  `brokers/github/internal/httpapi/grants.go`.
- Remove plain button options and duplicate status formatting from the GitHub
  runtime.

### sudo

- Keep command descriptions, bounded arguments, target user, working
  directory, timeout, and command risk in the sudo presenter/catalog.
- Never include an unrestricted command line, environment, secret argument, or
  value outside the reviewed command catalog projection.
- Delete the handwritten approval text in
  `brokers/sudo/internal/routes/agent_operations.go`.
- Remove plain button options and duplicate status formatting from sudo setup
  and runtime code.

## Persistence And Audit

Persist enough notification state to retry and reconcile without asking the
provider to reconstruct historical wording:

- normalized semantic presentation snapshot;
- exact rendered pending message;
- renderer/channel identity;
- Telegram chat and message IDs;
- canonical grant revision and status last rendered; and
- delivery/reconciliation timestamps and bounded error category.

The authorization audit remains based on the canonical grant and decision.
Notification audit records additionally bind the normalized presentation and
rendered message with a digest so an operator can determine what was submitted
to and acknowledged by the channel. Never log the decision token or Telegram
bot token.

If the persisted notification shape changes, replace it in version 1 and
require fresh state. Do not teach the runtime to read old `MessageRef.Text` or
provider-authored message records.

## Failure Behavior

- Invalid provider presentation fails to the shared bounded generic view and
  records `presentation_unavailable`; it must not hide a pending request.
- Rendering failure prevents notification delivery but leaves the canonical
  request available in the operator inbox.
- Telegram delivery failure remains retryable through the durable outbox.
- A durable decision failure leaves controls open and returns a short retry
  answer.
- A committed decision followed by a Telegram edit failure remains committed;
  reconciliation later renders the terminal state and removes controls.
- Unknown canonical statuses fail closed and render a generic closed state
  without exposing decision controls.
- Oversized optional facts are rejected at presentation validation. The
  Telegram renderer may omit lower-priority facts to satisfy its final channel
  limit, but it must never omit broker, requester, operation, target, risk,
  reason, expiry, or terminal status.

## Testing Strategy

### Shared model tests

- bounds for every string and collection;
- invalid UTF-8 and control-character rejection;
- defensive copying and deterministic fact ordering;
- structured warning and risk validation;
- generic fallback behavior; and
- confirmation that secrets and unrestricted maps cannot enter the model.

### Renderer tests

- golden pending messages for HF, GitHub, and sudo semantic fixtures;
- golden terminal messages for every lifecycle state;
- fixed button labels and callback payload bounds;
- Telegram markup injection and escaping corpus;
- exact channel-limit boundaries with multibyte text and emoji;
- deterministic truncation priorities;
- empty optional sections;
- idempotent repeated rendering and `message is not modified`; and
- terminal updates always clearing controls.

### Broker conformance tests

Each provider must prove that:

- every requestable operation can produce a valid presentation;
- every catalog risk maps to the shared risk vocabulary;
- destructive and critical operations provide an explicit warning;
- target and immutable plan identities are represented consistently;
- provider secrets and raw request bodies are absent;
- the operator API and Telegram receive the same normalized presentation; and
- no provider imports or invokes Telegram rendering directly.

Use generated catalog-wide tests rather than a few hand-selected operations.

### Lifecycle and recovery tests

- send, approve, deny, expire, consume, revoke, and cancel end to end;
- repeated and concurrent button taps;
- decision committed while Telegram edit fails;
- process restart between send, decision, and terminal edit;
- outbox replay and message reconciliation;
- one shared Telegram ingress routing HF, GitHub, and sudo callbacks; and
- exact audit/presentation digest retention.

Run the repository quality gates after the cutover:

```sh
go fmt ./...
go vet ./...
go test ./...
golangci-lint run
slophammer-go check .
```

Also run protocol generation drift checks, OpenClaw plugin checks, packed
installation tests, and browser tests because the Operator V1 presentation
schema is consumed by the packaged operator UI.

## Implementation Sequence

1. Add `approvalview`, move the existing operator-inbox presentation contract
   and bounds into it, and update Operator V1 generation and consumers.
2. Add structured warnings and catalog-wide provider presenter coverage.
3. Replace `notify.ApprovalMessage` and free-form terminal strings with the
   semantic envelope and typed lifecycle state.
4. Implement the one Telegram renderer, fixed controls, bounded formatting,
   and durable terminal reconciliation.
5. Migrate HF, using its current rich message as the visual baseline, then
   delete the HF message builder and status overrides.
6. Migrate GitHub and sudo to the same envelope and renderer, then delete their
   handwritten bodies, options, and status helpers.
7. Replace persisted notification state in place, update setup/doctor output,
   and require fresh pre-release state.
8. Update maintained architecture, operator inbox, Telegram ingress, provider,
   and OpenClaw documentation to describe only the final design.
9. Run all shared, provider, protocol, plugin, recovery, quality, and
   installation gates; install the resulting binaries and perform real
   Telegram approve/deny smoke tests for each broker.

This sequence is for implementation organization only. The change is complete
only when all brokers use the shared path and all replaced code is gone. Do not
merge an intermediate dual architecture.

## Deletion Gate

Before completion, repository searches must confirm the absence of:

- provider-authored `ApprovalMessage.Text` values;
- `ApprovalMessage.Text` and its generic fallback renderer;
- Telegram `ApproveText`, `DenyText`, and `IgnoredAnswer` options;
- provider-local `Approval needed for` format strings;
- provider-local approved, denied, expired, consumed, or revoked status prose;
- raw Telegram markup from provider packages;
- duplicate presentation bounds outside `approvalview` and generated protocol
  validation; and
- compatibility readers or converters for the replaced notification shape.

## Acceptance Criteria

The cutover is ready to merge only when:

1. HF, GitHub, and sudo produce the same Telegram structure and controls.
2. Provider-specific information remains complete and accurate in that shared
   structure.
3. All requestable provider operations pass presentation conformance tests.
4. The web operator inbox and Telegram derive from the same validated provider
   presentation.
5. Every terminal lifecycle state removes decision controls and converges after
   retry or restart.
6. Dynamic provider text cannot inject Telegram markup or exceed channel
   limits.
7. Durable records can prove the normalized and rendered presentation accepted
   by the notification channel without storing secrets.
8. All old per-provider rendering and status code has been deleted.
9. No compatibility layer, old-state reader, dual renderer, or fallback to raw
   broker text remains.
10. Go, Slophammer, protocol-generation, OpenClaw plugin, packed-install,
    browser, and real Telegram smoke-test gates pass.

## Implementation Report

Completed on 2026-07-17.

- `approvalview` now owns the bounded provider-neutral presentation model,
  validation, safe fallback, and provider presenter contract.
- `approvalnotify` projects one semantic approval used by the operator inbox,
  Telegram, provider notification outboxes, and recovery paths.
- `notify/telegram` owns the canonical escaped HTML layout, fixed controls,
  typed lifecycle rendering, callback answers, and durable reference builder.
- HF, GitHub, and sudo retain only operation-specific presentation semantics;
  their handwritten Telegram layouts and status wording were deleted.
- Operator V1 carries the exact renderer, semantic snapshot, rendered message,
  and SHA-256 bindings needed for atomic callback recovery.
- JSON and SQLite stores reject incomplete or digest-invalid Telegram records;
  no old notification-shape reader or migration was added.
- Catalog-wide presentation tests cover every requestable HF and GitHub
  operation and the complete sudo command catalog fixture.
- Protocol drift, architecture, generated GitHub surfaces, SQL, migrations,
  formatting, vet, all Go tests, race tests, aggregate coverage, golangci-lint,
  Slophammer, vulnerability, and secret scans pass.
- The OpenClaw package passes 53 unit tests, production build, packed-install
  verification, and 54 browser tests across desktop and mobile Chromium,
  Firefox, and WebKit.
- Live Telegram delivery smokes pass for HF, GitHub, and sudo using the shared
  renderer and fixed inactive test controls.
