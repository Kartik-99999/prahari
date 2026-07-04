# PRAHARÍ — Executive Summary

**Behavioural Cyber Resilience for Critical National Infrastructure** · PS#7 · https://github.com/Kartik-99999/prahari

**The problem, in one line:** India's critical infrastructure (1.59M CERT-In incidents/yr; AIIMS, CBSE breaches; 70% end-of-life government IT) is defended by signature tools that APTs evade for ~200 days at a time.

**The solution:** one closed, auditable loop — behavioural anomaly detection (no signatures, no labels) → graph fusion of weak signals into a single attack chain → Claude-agent MITRE ATT&CK attribution with next-move prediction → autonomous response behind platform-enforced human gates → a tamper-evident hash-chained audit ledger — fronted by a cinematic SOC console.

## Five headline numbers

| | |
|---|---|
| **1.66 days** | MTTD after foothold (vs ~200-day industry dwell) — containment fires **17 days before** the planned exfiltration: **breach prevented** |
| **0.9988 ROC-AUC · 100% recall @ ~1% FPR** | detection on the controlled 21-day APT scenario — and **0.845 macro ROC on public CIC-IDS-2017** (held-out, unsupervised), reported separately and honestly |
| **92.3%** | MITRE ATT&CK technique-level attribution accuracy, **0 false attributions** |
| **75%** | of the response playbook executes autonomously; the 2 high-impact actions are human-gated **by the platform, not the AI** |
| **Tamper-evident** | every automated action in a SHA-256 hash-chained ledger; a privileged row-rewrite is detected at the exact entry — live demo |

**Generalization, proven:** the *frozen* pipeline (nothing re-tuned) catches a held-out insider attack with no external C2 at **ROC 0.9987, 100% recall @1% FPR, MTTD ~7 min** — and runs natively on OT, where we **measured the IT-only gap, then closed it** with OT-native behavioural features (Modbus/SCADA PLC attack: ROC 0.840→**0.895**, malicious setpoint-writes alarmed **8/16→13/16** @1% FPR, MTTD ~4 min). Scale: **~54k events/s at 1M events** on one core. An **independent end-to-end re-run passed every gate** (`VERIFICATION_REPORT.md`).

![PRAHARÍ console — the attack chain emerges from the system's own scores](docs/console_graph.png)

**Honest scope:** loop metrics are from a controlled synthetic scenario (public-benchmark number reported alongside); the Claude agent has been run live end-to-end on both scenarios (subscription CLI, no API key — [`docs/LIVE_AGENT_RUN.md`](docs/LIVE_AGENT_RUN.md)), with the deterministic mapper still the reproducible number; OT modelled synthetically. Roadmap: OT-native hardware pilot, CERT-In feed, digital-twin simulation, multi-tenant state-CERT deployment.

*Detection in hours, not months — with every autonomous action provable after the fact.*
