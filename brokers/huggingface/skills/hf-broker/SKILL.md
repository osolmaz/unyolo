---
name: hf-broker
description: Use BrokerKit for Hugging Face Hub Git, repositories, datasets, models, Spaces, inference, grants, and typed Hub operations when hf-broker is installed. Use instead of exposing, retrieving, or configuring a Hugging Face access token.
metadata:
  { "openclaw": { "emoji": "🤗", "requires": { "bins": ["hf-broker"] } } }
---

# Hugging Face Broker

Use `hf-broker` whenever the runtime is enrolled with BrokerKit. The upstream
Hugging Face credential stays inside the broker and must never be requested,
printed, copied, or exported to the agent.

## Authenticate to BrokerKit

The runtime normally provides `HF_BROKER_AGENT_ENDPOINT` and
`HF_BROKER_SHARED_SECRET`. If either is missing and the client file is
readable, load it before running broker commands:

```sh
. "$HOME/.config/hf-broker/client.env"
```

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
BrokerKit policy and grants. Do not work around a broker rejection.

## Typed Hub operations

Use the fixed client commands for protected Hub mutations. Supply exact typed
target and argument JSON:

```sh
hf-broker client repo create \
  --target-json '{"kind":"repo","type":"dataset","owner":"OWNER","name":"REPO"}' \
  --arguments-json '{"visibility":"private"}'
```

If an operation is interrupted, recover the printed durable operation ID:

```sh
hf-broker client operation wait OPERATION-ID
```

For capabilities exposed through the MCP adapter, run `hf-broker mcp` and use
only the advertised tools. Never replace a missing typed operation with direct
authenticated Hub API calls.

## Temporary grants

Request a grant only when the user explicitly needs a policy-gated Git action.
Use a stable request ID and the narrowest repository, ref, duration, and use
budget:

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

## Inference

When configured, OpenAI-compatible inference uses the broker endpoint and the
BrokerKit client secret. Never substitute the upstream Hugging Face token. Use
only models and operations allowed by the broker policy, and do not expose the
client secret in output, logs, or generated files.
