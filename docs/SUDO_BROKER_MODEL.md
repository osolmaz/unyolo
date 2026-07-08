# sudo-broker Model

sudo-broker is the Unix privilege-transition broker in the brokerkit family.
It protects the ability to act as another local user.

The protected resource is different from `hf-broker` and `gh-broker`, but the
control-plane shape is the same:

```text
client
  ↓
brokerkit auth
  ↓
sudo-broker classifier
  ↓
brokerkit policy and grants
  ↓
approval channel
  ↓
sudo-broker executor
  ↓
target Unix user
```

## Brokerkit Responsibilities

brokerkit should provide:

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
- shell session lifecycle
- TTY handling
- Linux and macOS executor backends
- local isolation doctor checks
- sudo-specific approval wording

## Initial Policy Vocabulary

Operations:

| Operation | Meaning |
| --- | --- |
| `exec.command` | Run one declared command as a target user. |
| `session.shell` | Start a short-lived shell as a target user. |
| `session.attach` | Attach to a broker-managed session. |
| `session.terminate` | Terminate a broker-managed session. |
| `catalog.read` | Read command ids visible to the client. |

Targets:

| Kind | Meaning |
| --- | --- |
| `user` | A local Unix user. |
| `group` | A local Unix group. |
| `host` | A host identity for fleet-scoped policy. |

Attrs:

| Attr | Meaning |
| --- | --- |
| `command_id` / `command_ids` | Declared command id. |
| `cwd` / `cwds` | Allowed working directory. |
| `timeout_seconds` | Maximum command runtime. |
| `tty` | Whether a shell session requires a TTY. |
| `shell` / `shells` | Allowed shell path or login shell marker. |

## Command Versus Shell

`exec.command` can be tightly scoped because the broker runs a declared command
shape.

`session.shell` is an identity grant. Once the shell starts, the user can do
whatever the target Unix user can do until the session ends. The broker can
time-limit and audit the session, but it must not claim command-level
confinement inside that shell.

## Cutover Rule

sudo-broker starts on brokerkit. It should not implement a separate local policy
or grant runtime first and migrate later.
