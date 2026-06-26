# Prahari Graph Model (Phase 2)

The provenance/entity graph is the correlation core. The ingester
(`services/graph/ingest.py`) consumes the Redis `events:raw` stream via a
dedicated consumer group **`graph`** and MERGEs nodes + relationships into Neo4j
idempotently. The mapping below was derived from the **actual field population**
of the synthetic telemetry (verified in STEP 0), not from assumptions.

## Field reality (seed=42)

| activity | populated fields | absent |
|----------|------------------|--------|
| process  | `actor.user`, `actor.host`, `process.{name,pid,cmdline}` | src, dst, file |
| network  | `actor.host`, `src.ip`, `dst.ip`, `dst.port` | **process**, file |
| auth     | `actor.user`, `actor.host`, `src.ip`, `dst.ip`, `dst.port` | process, file |
| file     | `actor.user`, `actor.host`, `file.path` | **process**, src, dst |

Two consequences drove the model: **network and file events carry no process**,
and for **auth**, `actor.host` is the host being *logged into* while `src.ip` is
the *origin* host.

## Nodes

| label | key | properties |
|-------|-----|------------|
| `Host` | `name` (unique) | name |
| `User` | `name` (unique) | name |
| `IP` | `addr` (unique) | addr, `internal` (bool) |
| `File` | `key = host\|path` (unique) | path, host |
| `Process` | `key = host\|pid\|name` (unique) | name, pid, cmdline, host |

IPs present in the scenario host map are `internal=true`; all others (e.g. the
external C2 `203.0.113.66`) are `internal=false`. Internal IPs are linked to
their host via `(:Host)-[:HAS_IP]->(:IP)`.

## Relationships

Every **event** relationship is keyed on `event_id` (idempotent) and carries
`ts` (Neo4j `datetime`), `activity`, and the **ground-truth-only** properties
`gt_malicious` / `gt_attack_stage` / `gt_technique` (read from `raw.label`).
`ON_HOST` and `HAS_IP` are *structural* (not event-keyed).

> ⚠️ `gt_*` properties are for scoring / inspection ONLY. They must never be
> used as inputs to detection logic in later phases.

| event | pattern |
|-------|---------|
| process | `(:User)-[:STARTED]->(:Process)-[:ON_HOST]->(:Host)` |
| auth | `(:User)-[:AUTH {success, offhours}]->(:Host)` (Host = `actor.host`, the host logged into) |
| network | `(:Host)-[:CONNECTED_TO {dst_port}]->(:IP)` — host branch, since telemetry has no process. If a process were present: `(:Process)-[:CONNECTED_TO]->(:IP)` (implemented, currently unused). |
| file | `(:User)-[:ACCESSED {action}]->(:File)-[:ON_HOST]->(:Host)` — adapted from the spec's `(:Process)-[:ACCESSED]->(:File)` because file events have no process. `action` ∈ {read, write} derived from the event detail. |

Derived properties: `offhours = hour < 9 or hour >= 17`; `success = true`
(no failed logons are modeled); `action = write` if the file detail mentions
dropped/staged/archive/dump/created else `read`.

## Lateral-movement projection (`REACHED`)

In addition to the per-event relationships, internal host-to-host connectivity
is projected onto `(:Host)-[:REACHED {via, ts, event_id, gt_*}]->(:Host)`,
which is what makes lateral-movement path-finding clean:

- **auth**: `resolve(src.ip) -[:REACHED {via:'auth'}]-> actor.host`
  iff `src.ip` is internal **and** its host ≠ `actor.host`.
  This captures *remote* logons only — local/kerberos logons (where `src.ip`
  is the host's own IP and `dst` is the KDC on :88) are **excluded**, and
  external foothold logins (`src.ip` external) are excluded.
- **network**: `actor.host -[:REACHED {via:'network'}]-> resolve(dst.ip)`
  iff `dst.ip` is internal **and** ≠ `actor.host`.
  External C2 beacons and exfil (`dst.ip` external) are excluded.

Because no benign traffic originates from `DC01` and the clerk's benign DB
access goes `WS03 → DB-EXAMS` directly (never via DC01), the edges
`WS03 → DC01` and `DC01 → DB-EXAMS` are **malicious-only**. The lateral path
`WS03 → DC01 → DB-EXAMS` is therefore cleanly reconstructable, and filtering
`REACHED` edges on `gt_malicious` isolates the kill chain exactly.

`REACHED` is per-event (keyed on `event_id`), so multiple parallel edges can
exist between the same hosts; path queries use `DISTINCT` on host-name
sequences for readability.

## Ingester behaviour

- Consumer group **`graph`** at id `0` (reads the whole stream), independent of
  the spine consumer group.
- **Batch mode** (default): drain the stream until exhausted, then exit.
- `--reset`: `MATCH (n) DETACH DELETE n` and re-read the stream from id 0
  (clean reproducible load; constraints persist).
- `--follow`: reserved for a future live mode (not implemented).
- Writes are batched per pattern via `UNWIND` for throughput.

## Make targets

- `make graph-load` — clear stream, wipe graph, fresh seed=42 replay, ingest.
- `make graph-stats` — node counts by label + relationship counts by type.
- `make graph-killchain` — malicious edges in temporal order.
- `make graph-verify` — all verification queries (counts, kill-chain, lateral, crown).
