# PRAHARÍ — Demo Video Script & Shot List

**Target: ~2.5 minutes · 1920×1080 · the live console (badge must read ● LIVE · BFF) · replay at 4× · calm SOC-operator voice, not hype.**

## Pre-flight checklist (before recording)

Run once, top to bottom (takes ~10 min; the live-agent step is the slow one):

```bash
make up && make health                      # all three stores OK
make graph-load && make ueba-score          # deterministic scenario, scored
make fuse && make incidents                 # INC-001 assembled
make attribute-agent-live                   # LIVE agent via Claude Code subscription — NO API KEY
                                            #   (~3–5 min; falls back safely if it can't reach the CLI)
make respond                                # playbook: 6 auto + 2 human-gated
make audit-build && make audit-verify       # ledger ready (10 entries)
make api                                    # BFF :8000   (leave running)
cd console && npm run build && npx next start -p 3000    # console :3000
rm -f data/action_states.json               # stage the 2 gated actions as PENDING
                                            #   (so you can approve one live on camera)
```

Open `http://localhost:3000` and confirm the header badge reads **● LIVE · BFF** —
that is the proof the page is running on the real system, not fixtures. If it says
**◌ FIXTURES · BFF OFFLINE**, the BFF isn't reachable: fix that before recording.

**Fresh-dates option:** `make attack` replays the same seeded intrusion with the
window **anchored to today** (whole-week shift → every number identical, calendar
dates current — the console then reads "detected last week", not May). It replaces
the `graph-load … audit-verify` block above in one ~20 s command. If you use it,
say the on-screen dates instead of "May 4 / May 21" in the voice-over below;
`make attack NOW=0` keeps the canonical May window that matches this script.

**Or from the console itself:** the header's **⟳ run fresh attack** button (live
mode) does the same thing in one click — staged progress in the header, then the
new run auto-replays at 4×, and the two human gates come back **PENDING** (it
replaces the `rm -f data/action_states.json` step too). Clicking it *on camera*
as the opening beat is a strong alternative: "watch the whole loop run, live."

Useful deep links while rehearsing: `?lens=graph`, `?lens=events`, `&day=2.9`
(replay parked just after confirmation).

## Script

| Time | Beat | On screen | Voice-over |
|---|---|---|---|
| 0:00–0:20 | **Problem** | Title card → CERT-In / CBSE headlines | "CERT-In handled 1.59 million incidents in one year. AIIMS was down for two weeks. CBSE's exam records were breached. The industry's mean time to detect an intrusion is around 200 days — because by the time a signature exists, the attack already succeeded." |
| 0:20–0:35 | **Verdict** | The console top: LIVE badge, verdict hero, metric slate counting up | "This is PRAHARÍ — behavioural cyber-resilience, running live. One sentence an analyst can trust: a nation-state-style intrusion, detected in 1.66 days, contained in under a second, the exam-records theft prevented. Everything below proves it." |
| 0:35–0:42 | **Rewind** | Hit **▶ Replay attack** at **4×** | "Let's rewind 21 days and watch it happen." |
| 0:42–1:05 | **Attack unfolds** | Story spine ignites station by station; switch to **Graph** lens mid-replay; nodes/edges reveal | "A phishing macro on a clerk's workstation. Two nights later, a valid credential at 2 a.m. Then a memory dump. Individually? A SOC ignores these. The graph doesn't see events — it sees connections: WS03… to the domain controller… to the exam-records database." |
| 1:05–1:15 | **Detection** | Green **Confirmed** banner pulses at May 4 (day 2.7); the spine shows ✓ confirmed · contained | "Confirmed on day 1.66 — seventeen days before the planned data theft. Not 200 days." |
| 1:15–1:35 | **Evidence** | Click a red spine edge → drawer shows event id, technique, anomaly score, reasons; then **ATT&CK** lens with predicted next moves | "Every claim drills to evidence: this lateral hop — event, technique, the exact reasons it fired. Attribution maps the chain to MITRE ATT&CK — 92.3% technique accuracy, zero false attributions — and predicts what comes next: log wiping, then ransomware." |
| 1:35–2:00 | **Response** | SOAR queue: 6 auto-executed; click **Approve** on *isolate DB-EXAMS* → tag flips, audit chip ticks 10 → 11 | "Response is autonomous where it's safe — C2 severed in milliseconds, 75% of the playbook runs itself. The crown-jewel actions wait for a human. One click… and that decision just landed in the ledger. The May 21st exfiltration never happens. Breach prevented." |
| 2:00–2:20 | **Trust** | Ledger: real hashes; click **⚠ Simulate tamper** — chain breaks and cascades; click restore | "Every decision lands in a hash-chained, append-only ledger. Mutate one row and every hash after it breaks — you can prove *why* the system acted, and nobody can rewrite history." |
| 2:20–2:35 | **Close** | Scroll to top: verdict + slate (MTTD 1.66 d · 100% recall @1% FPR · 92.3% ATT&CK · 75% auto · <1 s MTTR) | "Behavioural detection. Graph fusion. Auditable autonomy. PRAHARÍ — detection in hours, not months." |

## Shot-list notes

- **Ground-truth toggle beat (during 0:42–1:05, Graph lens):** flip the "ground-truth overlay (eval only)" toggle ON then OFF while saying *"the system is never told which events are malicious — this colouring is its own scoring."* This is the credibility moment; don't skip it.
- **The approve beat writes to the real ledger** (that's the point — the audit chip ticking 10 → 11 on camera is the money frame). It's append-only, so re-record takes it to 12, 13…: fine, or `make audit-build` to rebuild the base chain between takes.
- Capture the confirmed-banner Story frame and the Graph-lens spine as your two hero frames (also used in the deck).
- **No API key needed:** `make attribute-agent-live` runs the agent through the Claude Code subscription. If the CLI can't be reached it degrades to deterministic fallback — say "deterministic mode" if so, and **do not** claim live-agent output in that case.
- The "92.3% technique accuracy" line is the deterministic mapper's benchmark number (the stable, reproducible figure). The live agent additionally beats the mapper on grounding for the held-out insider case (`docs/LIVE_AGENT_RUN.md`) — keep that for judge Q&A rather than the voice-over.
- Keep cursor movement slow; 4× replay does the drama for you. No background music louder than -20 dB.
- Optional 15-s cold open for social: the 1:05–1:15 detection beat, cut standalone.
