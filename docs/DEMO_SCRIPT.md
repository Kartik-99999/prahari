# PRAHARÍ — Demo Video Script & Shot List

**Target: ~2.5 minutes · 1920×1080 · console Demo mode · replay at 4× · calm SOC-operator voice, not hype.**

## Pre-flight checklist (before recording)

Run once, top to bottom (takes ~10 min; the live-agent step is the slow one):

```bash
make up && make health                      # all three stores OK
make graph-load && make ueba-score          # deterministic scenario, scored
make fuse && make incidents                 # INC-001 assembled
make attribute-agent-live                   # LIVE agent via Claude Code subscription — NO API KEY
                                            #   → badge shows ● LIVE (~3–5 min; falls back safely if it can't reach the CLI)
make respond                                # playbook: 6 auto + 2 human-gated
make audit-build && make audit-verify       # ledger ready (10 entries)
make api                                    # BFF :8000   (leave running)
cd console && npm run dev                   # console :3000 → enable Demo mode (16:9)
```
Keep a second terminal cued for the tamper beat: `make audit-tamper-demo`.
Optional: `make score-agent` if you want the live-agent numbers (20-vs-2) on hand for Q&A.

## Script

| Time | Beat | On screen | Voice-over |
|---|---|---|---|
| 0:00–0:20 | **Problem** | Title card → CERT-In / CBSE headlines | "CERT-In handled 1.59 million incidents in one year. AIIMS was down for two weeks. CBSE's exam records were breached. The industry's mean time to detect an intrusion is around 200 days — because by the time a signature exists, the attack already succeeded." |
| 0:20–0:35 | **Setup** | The console, incident list empty, hit **Play (4×)** | "This is PRAHARÍ — behavioural cyber-resilience. It never sees a signature and is never told what's malicious. Let's replay 21 days of an exam authority's telemetry." |
| 0:35–1:00 | **Attack unfolds** | Provenance graph reveals; nodes light up | "A phishing macro on WS03. Two nights later, a reused credential at 2 a.m. Then a memory dump. Individually? A SOC ignores these. But the graph doesn't see events — it sees connections. Watch the chain fuse: WS03… to the domain controller… to the exam-records database." |
| 1:00–1:12 | **Detection** | CONFIRMED banner at May 4 | "Confirmed on day 1.7 — seventeen days before the planned data theft. Not 200 days. 1.7." |
| 1:12–1:35 | **Attribution** | ATT&CK frame; technique chips; prediction panel | "The Claude agent maps every step to MITRE ATT&CK — 92.3% technique accuracy, zero false attributions — and predicts the next moves: log wiping, then ransomware. Before they happen." |
| 1:35–2:00 | **Response** | Playbook executes; 2 gated actions; click approve | "Response is autonomous where it's safe: command-and-control severed in milliseconds — 75% of the playbook runs itself. The two high-impact actions — isolating the database, disabling a domain admin — wait for a human. One click. The May 21st exfiltration never happens. Breach prevented." |
| 2:00–2:20 | **Trust** | Audit view; run `make audit-tamper-demo`; chain breaks at seq 10 | "Every decision lands in a hash-chained ledger. Watch what happens when a privileged insider rewrites one row… the chain breaks at exactly that entry. If PRAHARÍ acts, you can prove *why* — and nobody can rewrite history." |
| 2:20–2:35 | **Close** | Metrics ribbon (MTTD 1.66 d · 100% recall @1% FPR · 92.3% ATT&CK · 75% auto · <1 s MTTR) | "Behavioural detection. Graph fusion. Auditable autonomy. PRAHARÍ — detection in hours, not months." |

## Shot-list notes

- **Ground-truth toggle beat (during 0:35–1:00):** flip the "ground-truth overlay (eval only)" toggle ON then OFF while saying *"the system is never told which events are malicious — this coloring is its own scoring."* This is the credibility moment; don't skip it.
- Capture the graph reveal and the CONFIRMED banner as your two hero frames (also used in the deck).
- **No API key needed:** `make attribute-agent-live` runs the agent through the Claude Code subscription, so the badge shows ● LIVE without any `ANTHROPIC_API_KEY`. If the CLI can't be reached it degrades to FALLBACK — in that case either re-run or say "deterministic mode," and **do not** claim live-agent output while the badge shows fallback.
- The "92.3% technique accuracy" line is the deterministic mapper's benchmark number (the stable, reproducible figure). The live agent additionally beats the mapper on the held-out insider case (20 correct vs 2, `docs/LIVE_AGENT_RUN.md`) — keep that for judge Q&A rather than the voice-over, to avoid conflating the two.
- Keep cursor movement slow; 4× replay does the drama for you. No background music louder than -20 dB.
- Optional 15-s cold open for social: the 1:00–1:12 detection beat, cut standalone.
