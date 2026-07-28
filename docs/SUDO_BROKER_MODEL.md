# sudo-broker Model

sudo-broker is the Unix privilege-transition broker in the unyolo family.
It protects the ability to act as another local user.

The protected resource is different from `hf-broker` and `gh-broker`, but the
control-plane shape is the same:

```text
client
  ↓
unyolo auth
  ↓
sudo-broker classifier
  ↓
unyolo policy and grants
  ↓
approval channel
  ↓
sudo-broker executor
  ↓
target Unix user
```

## unYOLO Responsibilities

unyolo should provide:

- named-client authentication
- policy rules and decisions
- generated grant rules
- grant lifecycle and expiry
- audit-safe decision metadata
- approval workflow
- notifier interfaces
- reusable Telegram approval transport
- common config, storage, and HTTP safety helpers

## sudo-broker Responsibilities

sudo-broker should provide:

- Unix user, group, and host validation
- command catalog parsing
- fixed-command execution
- Linux and macOS executor backends
- local isolation doctor checks
- sudo-specific approval wording

## Initial Policy Vocabulary

Operations:

| Operation | Meaning |
| --- | --- |
| `exec.command` | Run one declared command as a target user. |

Targets:

| Kind | Meaning |
| --- | --- |
| `user` | A local Unix user. |

Attrs:

| Attr | Meaning |
| --- | --- |
| `command_id` | Declared command id. |
| `argument.<slot>` | One catalog-declared normalized typed slot value. |

## V1 Boundary

V1 supports only `exec.command` with one exact cataloged command shape. It does
not support shell sessions, TTY attachment, arbitrary command lines, caller
environment variables, stdin, or command discovery.

## Runtime Boundary

sudo-broker uses unYOLO policy and grants directly and does not implement a
separate local control plane.
