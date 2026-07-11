# sudo-broker Catalog

The catalog is a root-reviewed allowlist of executable shapes, not a command
history or shell configuration. See [catalog.example.json](../catalog.example.json).

Each command fixes:

- one absolute executable and working directory;
- zero or more literal, bounded integer, enum, or path-beneath arguments;
- an explicit target-user allowlist;
- a timeout and combined output limit;
- an optional fixed environment; and
- bounded operator description and risk text.

There are no raw string, regex, glob, variadic, shell, flag-map, stdin, or
caller-environment fields. Executables such as shells and common shell
equivalents are rejected. Loader and interpreter-startup environment names are
rejected. Unknown fields and duplicate keys invalidate the entire catalog.

`path_beneath` values are normalized and resolved beneath one declared root.
The helper resolves them again immediately before execution. They are command
data, not executable paths; the executable and working-directory chains must
remain root-owned, non-symlinked, and immutable to non-root users.

Catalog changes produce a new digest. Existing approvals whose immutable plan
does not match the active digest fail activation and execution. Replace the
catalog through reviewed setup, then request new approvals.
