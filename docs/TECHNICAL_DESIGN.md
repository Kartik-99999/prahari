# PRAHARÍ — Technical Design

How each stage actually works, with the design decisions and trade-offs. Companion to [`ARCHITECTURE.md`](ARCHITECTURE.md) (the map) and [`RESULTS.md`](RESULTS.md) (the measurements).

---

## a · UEBA — unsupervised behavioural scoring (`services/ueba`)

**Features (streaming, per entity):**
- *Temporal* — off-hours activity relative to the entity's own diurnal pattern.
- *Novelty* — first-time `user→host` pairing, new external destination for a host, first sighting of a process on a host, rare archiver/tooling processes.
- *Structural/velocity* — 24 h per-host event velocity, fan-out.

The feature builder is **O(1) per event** (running aggregates, no window re-scans) — this is what makes the 1M-event benchmark linear.

**Scoring:** `anomaly_score = 0.5 · model_ensemble + 0.5 · novelty_score` (`services/ueba/score.py`). The ensemble is **IsolationForest(n_estimators=200, random_state=42) + ECOD**, fit unsupervised. The 50/50 blend is deliberate: pure novelty over-fires on legitimately-new-but-benign behaviour; the point-anomaly models under-weight *contextual* novelty. Blending keeps recall while the FPR budget stays ~1%.

**Detector selection is honest:** on CIC-IDS-2017 NetFlow, ECOD's marginal-CDF assumption inverts (validation ROC 0.04–0.39), so members are retained only if **validation** ROC > 0.5 — selection happens on the val split, never on test labels, and the reduction to IForest-only is reported (`RESULTS.md` §1).

**OT-native features (G7):** for Modbus-bearing streams only, three extra columns join the matrix — `ot_modbus_write` (wire-observable write function code 5/6/15/16 parsed from the protocol text; benign operator writes exist by design so the flag is not a label proxy), `ot_new_write_pair` (first WRITE ever from this host to this PLC — the OT transplant of the first-time user→host novelty), and `ot_write_pair_rarity` (`1/(1+count)`, mirroring the existing rarity features, so repeat rogue writes stay warm). IT streams contain no port-502 traffic, so their matrices are **bit-identical** to the pre-G7 pipeline — re-verified after the change. Measured effect: `RESULTS.md` §4.

**No-leakage discipline:** `assert_no_leakage` hard-fails scoring if model inputs contain `label`, any `gt_*`, or the planted `severity` proxy. It runs in every scoring path (scenario 1, scenario 2, OT) and was observed passing in the independent verification.

## b · Graph model (`services/graph`, Neo4j)

Nodes `Host · User · Process · File · IP`; relationships `AUTH · CONNECTED_TO · STARTED · ACCESSED · ON_HOST · HAS_IP · REACHED` (scenario 1 materializes 849 nodes / 3,453 rels from 2,128 events). Ingest consumes `events:raw` via consumer group `graph` and **MERGEs idempotently** — replays are safe, reprocessing is free. The mapping was derived from measured field population per activity type, not assumption (see [`graph_model.md`](graph_model.md)).

**`:REACHED`** is the lateral-movement projection: auth/network edges that cross hosts, which is what lets one Cypher query surface `WS03 → DC01 → DB-EXAMS`.

## c · Fusion — "anomaly lift" (`services/graph/fuse.py`)

The core detection idea. Build an **event-similarity graph** (2,128 nodes / ~97k edges on scenario 1: events linked by shared entities and temporal proximity), then:

```
lift(e) = PPR(e) / PR_uniform(e)          PR_ALPHA = 0.85
          ↑ personalized PageRank, teleport mass on high-anomaly events
                        ↑ same graph, uniform teleport
```

**Why the ratio:** naive (uniform) PageRank measures *centrality* — it promotes busy benign hubs (domain controllers, file servers) because everything touches them. Personalized PageRank seeded by anomaly scores measures *proximity to suspicion* — but still inherits hub bias. **Dividing the two cancels the hub term**, leaving "how much more probability mass lands here than its connectivity alone explains" — i.e., membership in a suspicious *neighbourhood*, not popularity. Measured effect: the four weak signals (anomaly 0.68–0.75, individually ignorable) lift to ≥0.90 and join the campaign — **4/4 recovered**.

**Trade-off, made explicit:** the similarity graph **excludes the user pivot** — linking all events by shared account drags a compromised (mostly-benign) account's routine activity into incidents. Right call for IT APTs; it is *why* the all-internal insider (scenario 2) fragments into 2 incidents and the OT rogue-engineer gains 0 fusion recovery — both measured, published, and addressed in the roadmap (domain-conditional user pivot).

## d · Incident assembly & scoring (`services/graph/incidents.py`)

Events with `fused ≥ TAU (0.90)` are clustered by entity/time adjacency into incidents; each is scored by campaign evidence (anomaly mass, entity spread, lateral reach, duration). Scenario 1: 4 incidents; INC-001 (the APT) scores **34.16 ≈ 4× the next** — separation, not just detection. Incident *precision* is 21.7% because member events include the campaign's **benign context** on compromised hosts (the analyst needs it); malicious *recall* in the top incident is 13/13. `TAU=0.90` is frozen for all held-out evals; its measured cost (drops moderate-novelty bulk reads in scenario 2 → 62% union recall) is documented rather than tuned away.

## e · Attribution (`services/attribution`)

- **Knowledge:** live MITRE ATT&CK STIX bundle → 697 techniques (222 parents) + 11 curated advisory docs (clearly labelled REPRESENTATIVE — CERT-In's live listing is JS+PDF, verified not statically ingestable) → **Chroma** index, 233 documents; retrieval probes 4/4.
- **Deterministic mapper** (`mapper.py`): rule table over behavioural patterns → techniques. Scenario 1: **92.3% exact (12/13), 0 false attributions**; the one non-exact is defensible-adjacent (T1071 C2 vs stage label T1566). Its limits are quantified: scenario-2 insider techniques it has no rules for (T1087/T1005/T1052) → 2/45 exact.
- **Claude agent** (`agent.py`): Anthropic tool-use loop (model `PRAHARI_AGENT_MODEL`, default `claude-sonnet-4-6`), tools = RAG search + incident/event inspection. Constraints: **cite-or-abstain** (every technique claim must reference retrieved KB text), **gt-free inputs**, `--no-write` mode so held-out runs never touch the demo graph. Predicts next moves (T1070 anti-forensics, T1486 ransomware) from technique co-occurrence in the KB. **Live transports:** an `ANTHROPIC_API_KEY` (Messages API, `run_live`) **or** a Claude Code subscription (`run_cc`, `make attribute-agent-live`, no key). **Fallback:** with neither, it emits a data-driven deterministic narrative (external-C2 vs insider shaped) — the demo never breaks, and mode is always surfaced in the UI badge. Run live end-to-end on both scenarios (2026-07-04, subscription CLI) — it generalizes past the rule table exactly on the held-out insider case, recovering T1087/T1005 the mapper misses: [`LIVE_AGENT_RUN.md`](LIVE_AGENT_RUN.md).

## f · SOAR (`services/soar`)

The planner (agent, same fallback discipline) proposes `{action, target, rationale}` per step. **The platform, not the agent, computes blast radius** (how much legitimate capability the action removes: users cut off, services degraded) and assigns LOW/MEDIUM → auto-execute, HIGH → human gate. Measured: 8 steps → **6 auto (75%), 2 gated** — isolate `DB-EXAMS` (exam service outage) and disable `admin.it` (domain-admin lockout). The agent *cannot* change a gate: gate assignment happens after planning, in platform code. Connectors are simulated except `notify.py` — a real webhook POST that is **dry-run unless** `PRAHARI_WEBHOOK_URL` is set **and** `--send` passed, sends summary-only, env-sourced destination, short timeout. Containment latency once confirmed: **0.0043 s**.

## g · Audit ledger (`services/soar/audit.py`, Postgres)

Append-only table; each entry stores `seq, ts, actor, action, target, rationale, prev_hash, entry_hash` with `entry_hash = SHA-256(prev_hash ‖ canonical_payload)`.

Two independent layers:
1. **Prevention** — a `BEFORE UPDATE OR DELETE` trigger raises, making the table append-only at the DB level.
2. **Detection** — `verify_chain()` recomputes every hash from genesis; any rewrite breaks equality at that exact `seq`.

The tamper demo (`make audit-tamper-demo`) plays the strongest adversary: a privileged insider who *disables the trigger* and rewrites entry 10 (`admin.it` → `intern.account`). Verification fails at seq 10 (stored `8fec1aee…` ≠ recomputed `787d5c71…`). Human gate approvals from the console (`POST /api/…/decision`) append real entries — the ledger grows 10 → 11 during the API smoke and re-verifies.

## Cross-cutting decisions

| Decision | Why | Cost accepted |
|---|---|---|
| Unsupervised-only detection | CNI defenders have no labelled attacks; signatures are the failure mode being replaced | Lower single-event precision → mitigated by fusion |
| Frozen-threshold held-out evals | The only honest generalization test | Publishes our own weak spots (TAU, user pivot) |
| One OCSF schema for IT+OT | One pipeline, one graph, cross-domain correlation | IT-shaped features missed OT write semantics (measured in G4; closed in G7 with OT-native features emitted only for Modbus streams — IT matrices stay bit-identical) |
| Agents propose, platform disposes | Autonomy must be bounded by non-AI code to be trustworthy | Slightly lower automation ceiling |
| Deterministic seeds everywhere (42/77/1337) | Bit-for-bit reproducibility — verified independently | None meaningful |
