# Admission Control

unYOLO applies one admission controller before creating durable Agent V1
operations or approval notifications. The defaults allow 60 submissions per
client per minute, 25 active and 10 pending operations per client, 512 active
operations globally, and 64 executing operations globally. Stream, sealed
payload, and pending-grant stores also enforce independent global and per-client
storage caps.

HF and GitHub read an optional absolute configuration path from
`HF_BROKER_ADMISSION_CONFIG` and `GH_BROKER_ADMISSION_CONFIG`. Sudo accepts the
same file through `sudo-broker serve --admission-config`. An omitted file uses
the conservative defaults. A configured file is a closed JSON object and must
define every default and global value:

```json
{
  "requests_per_window": 60,
  "window_seconds": 60,
  "client_active": 25,
  "client_pending": 10,
  "global_active": 512,
  "global_executing": 64,
  "clients": {
    "automation-a": {
      "requests_per_window": 20,
      "window_seconds": 60,
      "active": 8,
      "pending": 4
    }
  }
}
```

Client override keys must exactly match configured authentication identities.
Unknown clients, duplicate or unknown JSON fields, partial values, non-positive
limits, pending limits above active limits, and client active limits above the
global active limit fail startup. The file is bounded to 64 KiB and its path
must be absolute and normalized.

Authentication, request validation, and idempotent replay happen before quota
charging. A refusal returns a stable `429` code and `Retry-After`, creates no
operation or approval, and does not consume another slot. Cancellation,
operator decisions, liveness, and readiness do not pass through submission
admission and remain available during overload.
