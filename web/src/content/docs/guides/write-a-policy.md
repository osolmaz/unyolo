---
title: Write a policy
description: Build a working scope.json from a deny-all baseline, one rule at a time.
---

Policy is the part of unYOLO you will spend the most time in, and it is a file you edit by hand.
This page builds one from nothing, adding a rule at a time and explaining what each one buys you.
The [policy engine](/docs/concepts/policy) page covers the evaluation semantics in full; this one
is about getting to a file that works.

## Start from deny-all

An explicitly empty rules array is a valid policy, and it is the right place to start:

```json
{ "rules": [] }
```

Every request against this policy returns `no_match`, which denies. Nothing an agent tries will
succeed, and the audit log will tell you exactly what it tried. Running an agent against a deny-all
policy for an hour is a cheap way to discover the operation names you actually need.

## Allow the safe reads

Reads are the natural first grant. This rule lets one client read contents and fetch from one
dataset repository:

```json
{
  "id": "agent-a-read-scraped-news",
  "effect": "allow",
  "clients": ["agent-a"],
  "operations": ["repo.contents.read", "git.fetch"],
  "targets": [
    { "kind": "repo", "type": "dataset", "owner": "osolmaz", "name": "scraped-news" }
  ]
}
```

Four fields are doing work. `clients` names authenticated client identities, and it accepts globs.
`operations` must be names the provider registry knows, so a typo fails policy loading rather than
silently matching nothing. `targets` are objects with a required `kind`, and the registry decides
which other fields that kind requires. `id` has to be unique and shows up in audit records as a
matched rule, which is why it is worth naming it after intent rather than calling it `rule-3`.

## Allow the writes you are comfortable with

For a dataset an agent appends to, `git.push.append` covers fast-forwards, new branches, and new
tags. It cannot rewrite history, because history rewrites classify as `git.push.force` and would
need their own rule:

```json
{
  "id": "agent-a-append-scraped-news",
  "effect": "allow",
  "clients": ["agent-a"],
  "operations": ["git.push.append"],
  "targets": [
    { "kind": "repo", "type": "dataset", "owner": "osolmaz", "name": "scraped-news" }
  ]
}
```

On GitHub the equivalent shape is usually narrower, because you want an agent pushing to its own
branch namespace rather than to whatever branch it likes. That is what attrs are for:

```json
{
  "id": "agent-a-push-own-branches",
  "effect": "allow",
  "clients": ["agent-a"],
  "operations": ["git.push.fast_forward"],
  "targets": [{ "kind": "repo", "owner": "osolmaz", "name": "unyolo" }],
  "attrs": { "refs": ["refs/heads/agent-a/**"] }
}
```

Git ref attributes use recursive path globs, so `**` crosses `/` and covers nested branch names
like `agent-a/fix/parser`. A push to `refs/heads/main` does not match this rule and falls through
to whatever else the policy says, which by default is nothing.

<div class="callout callout--note">
<span class="callout__title">Attr names are exact</span>
<p>unYOLO applies no aliases. <code>ref</code> and <code>refs</code> are different attrs, as are
<code>path</code> and <code>paths</code>. Use the name the provider registry declares for that
operation; the broker normalizes provider input into those names before policy runs.</p>
</div>

## Require approval for the dangerous ones

A `request` rule does not permit execution. It permits the creation of a pending grant, and it must
carry `grant_policy` bounds saying how long an approval may last and how many times it may be used:

```json
{
  "id": "request-scraped-news-force",
  "effect": "request",
  "clients": ["agent-a"],
  "operations": ["git.push.force"],
  "targets": [
    { "kind": "repo", "type": "dataset", "owner": "osolmaz", "name": "scraped-news" }
  ],
  "grant_policy": {
    "mode": "window",
    "default_minutes": 5,
    "max_minutes": 10,
    "default_max_uses": 1,
    "max_uses": 1
  }
}
```

A caller may ask for less than the default but never more than the maximum, and an operator
approving the request may narrow it further. The bounds in the file are the ceiling.

Grantable Git capabilities have to be enabled one at a time. `git.push.force` covers history
rewrites, `git.ref.delete` covers non-tag branch and ref deletion, and `git.tag.update` covers
moving or deleting tags. Enabling one does not enable the others.

## Add the denials that must always win

A `deny` rule beats everything, including an active approved grant. This is where you put the
things that should never happen regardless of what someone approves at two in the morning:

```json
{
  "id": "deny-ref-deletion-everywhere",
  "effect": "deny",
  "clients": ["*"],
  "operations": ["git.ref.delete"],
  "targets": [{ "kind": "repo" }],
  "description": "Deletion is never delegated."
}
```

Deny is also how you carve exceptions out of a broad allow. If a wildcard rule lets an agent read
every repository in an owner's namespace, a specific deny for the one repository holding customer
data still wins.

For a batch operation such as a multi-ref push, a deny matching any single concrete value denies
the whole batch. A forbidden ref cannot hide beside an allowed one in the same push.

## The generated preset

Running `setup systemd` without `--scope-file` installs the provider-owned
`request-all-agent-operations` preset rather than leaving you with nothing. It allows safe reads,
discovery, and inference directly; it requires approval for writes, administration, and destructive
operations; and it denies internal and credential-output operations outright.

That preset is a reasonable starting point and a poor finishing point, because "requires approval"
becomes "operator approves everything reflexively" surprisingly fast. Narrow it to the repositories
and operations you actually need. Add repeatable `--deny-operation <exact-name>` flags to switch
more operations off, and note that setup refuses to overwrite an installed policy unless you pass
`--replace-policy`, after printing the current and candidate policy digests and the change in
operation counts.

## Check your work

Policy loading is strict, so many mistakes surface as a refusal to start. Loading rejects missing
or null `rules`, unknown fields, duplicate rule IDs, unsupported effects, unsupported operations,
unsupported target kinds, unsupported attrs, attrs a rule's operations do not all support, invalid
glob patterns, `request` rules without `grant_policy`, `allow` or `deny` rules that carry one, and
overlapping request rules with conflicting normalized grant policies.

For `hf-broker`, check that generated policy artifacts still match the current catalog:

```sh
hf-broker doctor policy \
  --profile /etc/hf-broker/policy-profile.json \
  --scope /etc/hf-broker/scope.json \
  --manifest /etc/hf-broker/policy-manifest.json
```

The habit worth building is reading the audit log after a change. Each decision records the rule
IDs that matched, so a rule that never appears is either dead or misnamed, and a rule appearing on
requests you did not expect is too broad.
