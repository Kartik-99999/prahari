# PRAHARÍ — Roadmap

Every near-term item below closes a gap **we measured and published ourselves** (see `RESULTS.md`); the platform vision maps the remaining PS#7 capabilities as roadmap — not claimed as built.

## Near-term (weeks)

1. **Quantified live-agent run.** The tool-use Claude agents are implemented and wired (`make attribute-agent`, `make scenario2-agent`); with an `ANTHROPIC_API_KEY` we publish live-vs-deterministic attribution accuracy — specifically closing the measured scenario-2 gap (deterministic mapper: 2/45 exact on insider techniques T1087/T1005/T1052 it has no rules for; the agent reasons over the 233-doc ATT&CK+advisory RAG instead).
2. ✅ **OT-native features — SHIPPED (G7).** G4 measured the gap (setpoint-writes evade IT-shaped scoring); G7 closed it with write-function-code + first-writer→PLC novelty + write-pair rarity, on a scenario hardened with benign operator writes: ROC 0.840→0.895, malicious writes alarmed 8/16→13/16 @1% FPR, IT scenarios bit-identical. Residuals stay honest: 3 repeat writes below the 1% budget, T0859 undetectable in a 24/7 plant.
3. ✅ **Insider-aware / user-pivoted correlation — SHIPPED & now AUTOMATIC (ML-4).** The similarity graph excludes the user pivot by design (avoids benign drag in the external-C2 IT case); the correlator now **auto-detects the attack shape** (external-anchor fraction among flagged events, <0.15 ⇒ add the user pivot) and adapts itself — scenario-2 insider fusion recall **62%→69%** with the campaign consolidated into one incident, scenario-1 APT auto-selecting external mode (zero regression, 13/13 held). Force with `PRAHARI_INSIDER_FUSION=1/0`. Next: per-*incident* mode (not per-run) so a mixed environment can run both. Details: `RESULTS.md` §7 + §1b.
4. **Operating-point + TAU tuning.** The adversarial probe showed off-hours is load-bearing at 1% FPR (recall 13% under evasion, 80% @5% FPR); expose the FPR budget as an explicit SOC dial and lower incident `TAU` for low-and-slow bulk reads (measured cause of the 62% union recall in scenario 2).
5. **Real CERT-In advisory ingestion.** The corpus is curated/representative today (CERT-In's listing is JS + PDF — verified not statically ingestable); build the PDF-parsing feed so advisories flow into the RAG store live.
6. ✅ **Streaming detection on the wire — SLICE SHIPPED (`make stream`).** `services/ingest/stream_scorer.py` is a long-running `events:raw` consumer that warms up on the first N events, then scores every subsequent event **continuously in O(1)** via the already-streaming `FeatureBuilder`, ALERTing on the kill chain as it arrives (verified: 1 828 events scored live, 7 kill-chain alerts). Remaining hardening: refit on a rolling window (vs one warmup fit), and vectorise the O(n) reason-string formatter (called out in G5).
7. **Analyst-in-the-loop feedback.** The audit ledger already captures every human gate decision (approve/deny per action); feed those verdicts back to tune per-deployment thresholds and suppress repeat false positives — closing the loop from *detection* to *learned local baseline*. The data plumbing (ledger + decision endpoint) already exists.
8. **Incident lifecycle.** Stable incident IDs with states (new → triaged → contained → closed) so re-runs update rather than duplicate — the step from a demo to something a SOC runs a shift on.

## Platform vision (PS#7 full scope)

- **Cyber-resilience digital twin** — attack-path simulation over the existing Neo4j provenance graph: "if WS03 falls, what can reach DB-EXAMS?" pre-computed, not post-incident.
- **CVE-driven vulnerability prioritization** — live CVE/KEV feeds ranked by *reachability in the twin*, not CVSS alone — built for 70%-end-of-life estates where patch-everything is fantasy.
- **Multi-tenant for state CERTs** — one deployment, per-tenant graphs/ledgers, cross-tenant campaign correlation (the same APT hitting three states is one incident).
- **Production connector library** — EDR (isolate), firewall (block), IdP (disable/step-up), backup-freeze; the safe opt-in webhook connector (`make notify`) is the pattern: dry-run by default, explicit egress, ledgered.
- **Real OT integration** — historian/OPC-UA taps and passive Modbus monitoring on real hardware, replacing the synthetic OT generator.
