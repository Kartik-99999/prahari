# PRAHARÍ — Air-Gapped / Zero-Egress Mode

**The whole detect → respond → audit loop runs with zero external network
dependency.** For critical national infrastructure — often air-gapped and legally
barred from sending telemetry to third-party APIs — the LLM is an *optional*
enhancement layer, not a requirement. This is verified with the network physically
blocked, not just asserted.

## How to run it

```bash
export PRAHARI_OFFLINE=1        # hard air-gap switch
make up && make health         # local Neo4j / Redis / Postgres (localhost only)
make graph-load && make ueba-score && make fuse && make incidents
make attack-kb && make attack-rag          # KB from local cache/subset; local TF-IDF RAG
make attribute-baseline && make attribute-agent   # deterministic mapper; agent forced to fallback
make respond && make soar-eval             # deterministic playbook; 75% automation
make audit-verify && make audit-tamper-demo
```

`PRAHARI_OFFLINE=1` is a **hard** switch: it forces deterministic fallback for both
Claude agents (attribution + response-planner) *even if* an `ANTHROPIC_API_KEY` or
the Claude CLI is present, and makes the ATT&CK KB skip its live fetch.

## What was made zero-egress (and why it wasn't before)

| Component | Hidden external call (before) | Now |
|---|---|---|
| RAG embeddings (`services/attribution/rag.py`) | Chroma's default embedder **downloads an ~80 MB ONNX MiniLM model** from S3 on first use | On-box **scikit-learn TF-IDF** vectorizer, fitted on the local corpus at build time and pickled — no download |
| Chroma client | Sends **anonymized telemetry** by default | `Settings(anonymized_telemetry=False)` |
| ATT&CK KB (`attack_kb.py`) | Live-fetches MITRE STIX from GitHub | `PRAHARI_OFFLINE=1` skips the fetch; uses local cache → committed subset (`packages/attack_subset.json`) |
| Attribution / planner agents | Call the Anthropic API / Claude CLI | `PRAHARI_OFFLINE=1` forces deterministic fallback |
| Webhook notifier (`soar/notify.py`) | Opt-in POST (already dry-run by default) | `PRAHARI_OFFLINE=1` refuses egress regardless of `--send` |

Local infrastructure (Neo4j, Redis, Postgres over `localhost`) is not "external
API" — it is the on-prem datastore tier and stays.

## Proof — run with sockets rejected

Every outbound connect to a non-loopback host was monkeypatched to raise, then the
retrieval path (the one that used to download the model) was exercised:

```
PRAHARI_OFFLINE=1, non-loopback sockets + external DNS hard-blocked
[1] ATT&CK KB   source=cache   parents=222          # no fetch
[2] RAG build   indexed=233 docs (prahari_offline_tfidf)   # no ONNX download
[3] retrieve 'pg_dump database exfiltration…'  -> ['advisory_exfiltration.md', …]
PASS — KB + RAG build + retrieve ran with ZERO external network.
```

And the full loop under `PRAHARI_OFFLINE=1`:

```
[kb]   ATT&CK KB loaded: source=cache
[rag]  Indexed 233 documents into Chroma collection 'prahari_intel'
[agent]  MODE=FALLBACK — deterministic mapper output + templated narrative
[planner] MODE=FALLBACK — deterministic playbook   ·   AUTOMATION COVERAGE 6/8 = 75%
[audit]  verify_chain … "ok": true   ·   tamper demo → BROKEN at seq 10
```

## What you keep vs. what degrades offline

- **Keep (LLM-free):** UEBA detection (ROC 0.9988 controlled / 0.9987 held-out /
  0.845 public benchmark), graph fusion, incident assembly, **deterministic ATT&CK
  attribution 92.3%**, SOAR planning with platform-enforced human gates (75%
  automation), the tamper-evident hash-chained audit ledger, the API + console.
- **Degrade gracefully:** the agentic *narrative* + next-move reasoning become a
  data-driven template; the live agent's grounded-citation behaviour is unavailable
  (see [`LIVE_AGENT_RUN.md`](LIVE_AGENT_RUN.md)). Offline attribution is the
  deterministic mapper, which does not depend on RAG.

**Trade to state honestly:** offline attribution is the mapper's rule coverage, not
an LLM reasoning over novel patterns. When connectivity exists, adding a key (or the
Claude CLI subscription) turns the agent back on as an enhancement.
