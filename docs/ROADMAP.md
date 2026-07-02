# PRAHARÍ — Roadmap

Every near-term item below closes a gap **we measured and published ourselves** (see `RESULTS.md`); the platform vision maps the remaining PS#7 capabilities as roadmap — not claimed as built.

## Near-term (weeks)

1. **Quantified live-agent run.** The tool-use Claude agents are implemented and wired (`make attribute-agent`, `make scenario2-agent`); with an `ANTHROPIC_API_KEY` we publish live-vs-deterministic attribution accuracy — specifically closing the measured scenario-2 gap (deterministic mapper: 2/45 exact on insider techniques T1087/T1005/T1052 it has no rules for; the agent reasons over the 233-doc ATT&CK+advisory RAG instead).
2. **OT-native features.** The frozen IT detector transfers to Modbus/SCADA at ROC 0.792 but misses setpoint-*writes* (read-vs-write function code isn't an IT feature — measured, G4). Add write-function-code + writes-from-non-controller features; target 4/4 ICS techniques surfaced.
3. **User-pivoted OT correlation.** The similarity graph excludes the user pivot by design (avoids benign drag in IT); a single rogue engineer is best correlated *by user*. Make the pivot domain-conditional.
4. **Operating-point + TAU tuning.** The adversarial probe showed off-hours is load-bearing at 1% FPR (recall 13% under evasion, 80% @5% FPR); expose the FPR budget as an explicit SOC dial and lower incident `TAU` for low-and-slow bulk reads (measured cause of the 62% union recall in scenario 2).
5. **Real CERT-In advisory ingestion.** The corpus is curated/representative today (CERT-In's listing is JS + PDF — verified not statically ingestable); build the PDF-parsing feed so advisories flow into the RAG store live.
6. **Streaming hardening.** Vectorise the O(n) reason-string formatter (called out in G5), then wrap the scoring core as a long-running `events:raw` consumer for true streaming.

## Platform vision (PS#7 full scope)

- **Cyber-resilience digital twin** — attack-path simulation over the existing Neo4j provenance graph: "if WS03 falls, what can reach DB-EXAMS?" pre-computed, not post-incident.
- **CVE-driven vulnerability prioritization** — live CVE/KEV feeds ranked by *reachability in the twin*, not CVSS alone — built for 70%-end-of-life estates where patch-everything is fantasy.
- **Multi-tenant for state CERTs** — one deployment, per-tenant graphs/ledgers, cross-tenant campaign correlation (the same APT hitting three states is one incident).
- **Production connector library** — EDR (isolate), firewall (block), IdP (disable/step-up), backup-freeze; the safe opt-in webhook connector (`make notify`) is the pattern: dry-run by default, explicit egress, ledgered.
- **Real OT integration** — historian/OPC-UA taps and passive Modbus monitoring on real hardware, replacing the synthetic OT generator.
