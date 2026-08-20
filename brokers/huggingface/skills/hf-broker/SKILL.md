---
name: hf-broker
description: Use unYOLO for Hugging Face Hub Git, repositories, datasets, models, Spaces, inference, grants, and typed Hub operations when hf-broker is installed. Use instead of exposing, retrieving, or configuring a Hugging Face access token.
metadata:
  { "openclaw": { "emoji": "🤗", "requires": { "bins": ["hf-broker"] } } }
---

# Hugging Face Broker

Use `hf-broker` whenever the runtime is enrolled with unYOLO. The upstream
Hugging Face credential stays inside the broker and must never be requested,
printed, copied, or exported to the agent.

## Authenticate to unYOLO

`hf-broker` loads its private client V1 document directly from
`~/.config/hf-broker/client.json`. Do not source it or copy its credential into
the environment. Environment configuration is only for isolated development.

Do not run an interactive Hugging Face login or read the system broker token.

## Git transport

Use ordinary Hugging Face URLs and Git commands. The installed Git
configuration and scoped credential helper route clone, fetch, pull, push, and
supported Git LFS traffic through the broker:

```sh
git clone https://huggingface.co/OWNER/REPO
git fetch origin
git push origin HEAD
```

Run `hf-broker git doctor` if routing is in doubt. Keep normal remote URLs; do
not write broker endpoints or credentials into repository configuration.

History rewrites, ref deletion, and tag movement require their own explicit
unYOLO policy and grants. Do not work around a broker rejection.

## Typed Hub operations

Use the generated catalog client commands for typed Hub operations. Supply the
exact target and argument JSON accepted by the command:

```sh
hf-broker client repo create \
  --target-json '{"kind":"repo","type":"dataset","owner":"OWNER","name":"REPO"}' \
  --arguments-json '{"visibility":"private"}' \
  --reason "Create the requested private dataset repository" \
  --request-id STABLE-REQUEST-ID \
  --wait=true \
  --wait-timeout 15m
```

Catalog commands wait by default. Keep that behavior for agent-driven work so
the command returns only after a terminal result, explicit cancellation, or an
unrecoverable error. `--wait-timeout` is an internal retry interval. The CLI
keeps waiting on the same operation ID when an interval expires.

The CLI explains every returned lifecycle state. `pending`, `approved`, and
`executing` are not completion. Follow the printed `Next:` wait command with
the same operation ID and do not report the requested action as completed.
Only `succeeded` means it completed. `failed`, `denied`, `expired`, and
`canceled` mean it did not complete.

Requestable operations default to reusable window grants. Each invocation still
has its own immutable plan, operation ID, result, and audit record. Policy may
select `execution` mode for an exact single-use approval. Do not assume a
reused window skips plan validation or expands the approved target and attrs.

Approval waiting is part of the same agent turn. Do not return control to the
user while the operation remains pending. If a wait interval expires,
immediately wait again with the same operation ID. Continue until the user
clicks or otherwise records a decision and the operation reaches a terminal
state. Stop only for a terminal result, an explicit user cancellation, or an
unrecoverable broker error.

Use a stable request ID for mutations. If a call is interrupted, recover the
printed durable operation instead of submitting it again:

```sh
hf-broker client operation get OPERATION-ID
hf-broker client operation wait --wait-timeout 15m OPERATION-ID
hf-broker client operation cancel OPERATION-ID
```

For capabilities exposed through the MCP adapter, run `hf-broker mcp` and use
only the advertised tools. Never replace a missing typed operation with direct
authenticated Hub API calls.

## Temporary grants

Request a reusable grant when the user explicitly asks to authorize repeated
operations. Always use the number of uses the user requested; do not substitute
a fixed example value.

For `job.run` and `job.uv.run`, distinguish these requests exactly:

- "Allow any N jobs" means `max_uses: N` with `attrs` omitted or empty. Job
  arguments may change between uses, but the operation and target must still
  match.
- "Run this exact job N times" means `max_uses: N` with the exact target and
  argument digest attrs.
- If the wording does not say whether job arguments may change, ask one short
  question before requesting the grant.

Before requesting approval, state the scope plainly: either "any job arguments
for this target" or "exact job arguments only." Never silently add exact digest
attrs to a request for any N jobs, and never omit attrs from an exact-job
request.

For Git actions, use a stable request ID and the narrowest repository, ref,
duration, and use budget:

```sh
hf-broker client grant request git.push.force OWNER/REPO \
  --type model \
  --ref refs/heads/main \
  --minutes 5 \
  --max-uses 1 \
  --reason "Repair the reviewed branch" \
  --request-id STABLE-REQUEST-ID
```

Resume grant state with `hf-broker client grant get|wait|cancel|revoke`. A
pending request means approval is required, not that authentication is absent.
Keep waiting on the same grant without ending the agent turn until the user
records a decision or explicitly cancels it.

## Inference

When configured, OpenAI-compatible inference uses the broker endpoint and the
unYOLO client secret. Never substitute the upstream Hugging Face token. Use
only models and operations allowed by the broker policy, and do not expose the
client secret in output, logs, or generated files.
