# PRAHARÍ Console — Design-Generation Prompt

> Paste everything below the line into a Claude design/artifact generation. It is a
> complete, self-contained brief: real data, real numbers, the design thesis, the
> information architecture, and the non-negotiable constraints. The generator should
> produce a **self-contained interactive prototype** (single-file React or HTML+JS,
> all data baked in as static fixtures — it does NOT call a backend).

---

You are the design lead redesigning **PRAHARÍ**, an AI cyber-resilience console for a
Security Operations Center (SOC) analyst. This is a from-scratch restructuring of a
single-incident analyst view. The previous version was functionally complete but read
like a dense dashboard; your job is to make it an **explorable instrument** — the way a
stock app lets you open one ticker and drill from a headline into deeper and deeper
charts. The centerpiece — the thing to spend real craft on — is the **Provenance Graph
& ATT&CK Kill Chain: its presentation and its animation.**

Build a self-contained interactive prototype. Bake the data below in as fixtures. No
backend, no lorem — every label, number, host, and technique below is real and must
appear verbatim.

## The one job

An analyst opens this console and must, in under a minute, understand and *trust* a
single verdict: **a patient nation-state-style intrusion against a government exam board
was detected on day 1.66, contained before it could exfiltrate the exam records on day
19, and every step is provable.** The design's job is to let them see that story at a
glance, then drill into any part of it — the graph, the kill chain, a single technique,
a single event — and find the evidence underneath.

## The subject's world (use this vocabulary and these exact values)

**The incident — INC-001, "low-and-slow APT", CONTAINED.**
- Target: the **State Examinations Authority** (a CBSE-style government exam board). Crown-jewel asset is the **exam-records database**.
- Incident score **34.16** (4× the next incident). Span **19.74 days** (May 1 → May 21, 2026). **60 correlated events.**
- **Mean Time To Detect: 1.66 days** — confirmed 2026-05-04, **17.04 days before the planned exfil**. Industry dwell baseline ≈ 200 days (Mandiant).
- **Mean Time To Respond: < 1 second** auto-containment once confirmed.
- **The counterfactual (the business headline):** auto-containment severed the C2 channel at confirmation, so the **May-21 exfiltration never completed — breach prevented.**

**Entities (the graph nodes).** Give each type a distinct shape:
- **Hosts** (round-rectangle): `WS03` (the clerk's workstation, patient zero), `DC01` (domain controller), `DB-EXAMS` (the crown-jewel database server — mark it with a ★).
- **Users** (circle): `exam.clerk` (compromised first), `admin.it`, `db.service`.
- **Processes** (diamond): `pg_dump`, `7z.exe`, `rundll32.exe`, `backup.sh`, `powershell.exe`, `vacuumdb`, and benign context `winword.exe`, `chrome.exe`, `outlook.exe`, `teams.exe`, `excel.exe`, `onedrive.exe`, `explorer.exe`.
- **Files** (rectangle): `out.dmp` (credential dump on WS03), `exam-records.7z` (staged archive), `results_draft.docx`, `daily_report.csv`, `circular.pdf`.
- **IPs** (hexagon): internal `10.10.0.10`, `10.10.0.20`; **external C2 `203.0.113.66`** (ring it red — this is the adversary infrastructure).

**The lateral-movement path (the spine of the attack):** `WS03 → DC01 → DB-EXAMS`, then out to `203.0.113.66`.

**The reconstructed ATT&CK kill chain (7 techniques, in order):**
1. `T1566` Phishing — *Initial Access* (email → WS03)
2. `T1071` Application Layer Protocol — *Command & Control* (C2 beacon)
3. `T1078` Valid Accounts — *Defense Evasion / Persistence* ← **this is the "confirmed · contained" beat**
4. `T1003` OS Credential Dumping — *Credential Access* (produces `out.dmp`)
5. `T1021` Remote Services — *Lateral Movement*
6. `T1560` Archive Collected Data — *Collection* (produces `exam-records.7z`)
7. `T1041` Exfiltration Over C2 — *Exfiltration* ← **PREVENTED (never completed)**

**Predicted next moves (what the attacker would have done next):** `T1070` Indicator Removal, `T1486` Data Encrypted for Impact (ransomware), `T1078` Valid Accounts (re-entry), `T1041` again.

**The verified metrics slate (show these; never invent others):**
| Metric | Value | Sublabel |
|---|---|---|
| UEBA ROC-AUC | **0.9988** | 13 malicious / 2115 benign |
| Recall @ 1% FPR | **100%** | weak-signal detection |
| Technique accuracy | **92.3%** | 0 false attributions |
| Automation coverage | **75%** | 6 auto / 2 human-gated |
| MTTD | **1.66 d** | vs ~200 d industry |
| MTTR | **< 1 s** | auto-containment |
| Audit | **✓** | 10-entry hash chain, tamper-evident |

**The correlation strategy strip (a signature element — the system showing its work):**
`CORRELATION STRATEGY: EXTERNAL-C2 · AUTO-SELECTED`. The correlator auto-decided this
is an external-C2 (not insider) campaign because the **external-anchor fraction = 0.308
≥ 0.15** threshold. Pivots used: `extip`, `file`, `host`, `process`. (For an insider
case this flips to `INSIDER` and adds a user pivot — show the mechanism, not just a badge.)

## Information architecture (the restructuring)

Reorganize the page from "dashboard of panels" into a **top-down narrative that invites
drill-down**, like a stock detail page:

1. **Header** — wordmark PRAHARÍ (a single saffron tick on the Í), incident selector `INC-001`, and an `AUDIT VERIFIED · 10` chip (green, tamper-evident).
2. **The verdict line (hero)** — the single most important sentence, large: *detected day 1.66 · contained · exam-records exfil prevented.* Pair it with the incident score `34.16` and the 7-tile metric slate. This is the "headline + key stat" of the stock page. Make it confident and scannable, not a wall of tiles.
3. **Correlation strategy strip** — the auto-selected EXTERNAL-C2 decision with the anchor gauge (0.308 vs the 0.15 threshold) and pivot chips.
4. **The replay scrubber** — a timeline May 1 → May 21 with play speeds 1× / 4× / 12×, key beats marked (Foothold 05-02, **Confirmed 05-04**, Lateral→DC01 05-09, Lateral→DB-EXAMS 05-13, Staging 05-19, **Exfil-PREVENTED 05-21**). **This scrubber is the master clock — it drives every animation below.**
5. **★ THE INSTRUMENT — Provenance Graph & ATT&CK Kill Chain** (see next section). This is the heart of the page and should own the most space and the most polish.
6. **Attribution** — the reconstructed kill chain + campaign assessment + predicted next moves, each technique citing threat-intel advisories.
7. **Response action queue** — 8 SOAR actions, 6 auto-executed + 2 human-gated (isolate DB-EXAMS, disable admin.it), each with a blast-radius chip.
8. **Tamper-evident audit ledger** — the 10-entry SHA-256 hash chain, append-only, with a "tamper demo" that shows a mutated row breaking the chain.

## ★ The centerpiece: the graph + kill-chain instrument

Design this as **one instrument with five lenses** the analyst toggles between — same
incident, different ways to read it. All five are driven by the shared replay clock, so
scrubbing time animates whichever lens is open. Spend your best design and motion here.

**Lens 1 — Story (default): the kill-chain spine.** A horizontal left→right chain of the
7 techniques as "stations" on a rail. As the replay playhead crosses each technique's
first-observed time, that station **ignites** (dot fills, label brightens, the rail fills
up to it) — so scrubbing lights the chain in true temporal order. Two stations carry the
verdict: `T1078` gets a green **"confirmed · contained"** flag; the final `T1041` renders
struck-through / dashed with an **"exfil prevented"** flag. Each station shows its
technique id, name, the host it touched, and the date. This is the money shot.

**Lens 2 — Graph: the provenance graph.** A force-directed node-link graph of the
entities above. **This is where the previous design failed and where you must excel.**
Requirements:
- **Focus + context, not a hairball.** The malicious attack path must *lead* visually; benign context must *recede into the paper*. Encode this with opacity, size, and saturation — benign nodes go small, translucent, and desaturated; the attack nodes stay solid and prominent. Do NOT give every node equal weight.
- **The lateral path `WS03 → DC01 → DB-EXAMS → C2` must read as a single clean spine** — bold, animated (marching-ants along the flagged hops), unmistakable. Benign connections stay thin and quiet; never let them tangle across the middle.
- Node **shape = entity type** (host/user/process/file/ip as above); **color = the system's own anomaly heat** (see honest-viz below); the crown-jewel `DB-EXAMS` wears a ★ and the external C2 wears a red ring.
- Labels must stay legible over any fill (pill backgrounds); shorten file labels to basenames.
- **Interaction (the Groww drill-down):** hover spotlights a node's neighborhood and dims the rest; click a node or edge opens a **detail drawer** with its evidence — for an edge: the event id, the inferred technique, the anomaly score, the timestamp, and the plain-language reasons the system flagged it. This is the "tap a data point, get the underlying detail" pattern.
- As the replay plays, nodes/edges **reveal** as their timestamp arrives and malicious edges **flare** as the playhead crosses them.

**Lens 3 — ATT&CK: the technique matrix.** The 7 observed techniques laid on their
tactics (Initial Access → … → Exfiltration), plus the **predicted next moves** in a
distinct "forecast" treatment (amber, pulsing) so observed vs predicted is unmistakable.
Tap a technique → its evidence and its advisory citations.

**Lens 4 — Path: the lateral-movement walk.** A focused, linear presentation of just
`WS03 → DC01 → DB-EXAMS`, each hop a card showing which credential/technique carried it
and when — the attack narrated as a three-step journey to the crown jewel.

**Lens 5 — Events: the ranked evidence table.** The raw correlated events, ranked by
anomaly score (highest first), each row linking back to its node/edge in the graph. The
bottom of the drill-down — the primary sources.

## Visual system (honor and elevate the "Daylight SOC" identity)

The established identity is deliberate and must be kept, then elevated: **"clarity is a
security feature — every SOC ships a dark cockpit; PRAHARÍ reads like a clean, trustworthy
report."** It is a **light** theme. Do not turn it dark.

- **Palette:** canvas `#F6F8FA`, white cards, hairline borders `#E5EAF0`, ink text `#101828`, muted text `#475569`, faint `#94A3B8`. **Accent (the system's own voice) = deep teal `#0D9488`** (AA-legible on white). **Threat ramp = amber `#D97706` → red `#DC2626`** (used *only* for threat). **Success/contained = `#059669`.** The saffron `#F59E0B` appears *only* as the wordmark tick.
- **One voice per color (non-negotiable):** **teal = the system speaking** (its decisions, its confidence); **gray = the benign world** (recedes); **amber→red = threat, and nothing else**; teal is never used for threat and threat colors are never used for chrome.
- **Type:** Inter for UI/copy, **JetBrains Mono for all data** (ids, scores, hosts, timestamps) with `tabular-nums`. Set a real type scale; give the verdict line genuine display size and `text-wrap: balance`.
- **Surface:** rounded-xl cards, soft paper shadow (not glows), generous air. Numbers align in columns.
- Include a subtle legend for the graph (shape = type, color = anomaly heat) and a keyboard-focus style throughout.

## Honest-visualization constraints (do not violate — this is the product's integrity)

- **Color the graph by the system's OWN computed score** (`anomaly_score` / `fused_score`), NEVER by the ground-truth `malicious` flag. The attack must *emerge from the detection*, not be painted in by cheat labels.
- Provide a **"ground-truth overlay (eval only)"** toggle, **off by default**, that outlines the truly-malicious edges — clearly labeled as an evaluation aid, never the default coloring.
- Never fabricate a metric. Only the slate values above exist. If a number would be invented, omit the element.

## Motion & interaction principles

- **The replay scrubber is the master clock.** Scrubbing animates ignition (Story), reveal + flare (Graph), lane fill (ATT&CK) — all synced to real event timestamps.
- **The confirmation beat:** when the playhead reaches day 1.66 (2026-05-04), the "C2 severed · breach prevented" banner arrives with a single deliberate pulse — the emotional peak.
- **Count-up on the metric tiles on load** — but they MUST settle on the exact true value even if frames are throttled (a backgrounded tab or a screenshot must never freeze a tile on an intermediate, wrong-looking number). Respect `prefers-reduced-motion` everywhere.
- Motion should be purposeful and sparse. One orchestrated moment (the kill-chain igniting as you scrub) beats scattered effects.

## Deliverable

A polished, self-contained interactive prototype with all data baked in: the full page
top-to-bottom, the five-lens instrument fully interactive (lens toggle, hover spotlight,
click-to-drill drawers), and the replay scrubber driving the animations. Design for a
wide analyst monitor but keep it responsive. Make the graph lens and the Story spine the
two things a viewer remembers.
