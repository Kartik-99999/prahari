# PRAHARÍ — Demo Video Production Prompt

A ~2:30 hackathon demo. **It must show the real, live console** — the whole
pitch is "this works." So the recipe is: **screen-record the real console →
AI voiceover from the script below → light editing + captions.** Do **not** use
generative text-to-video (Runway / Sora / Pika / Kling) for the product — those
invent footage; a judge needs to see the actual system. (A 3-second generative
title card is the only place that's OK.)

---

## Which AI software to use

**Recommended stack (best result, ~free):**

1. **Screen recording — [Screen Studio](https://screen.studio) (Mac).** Records
   the console with automatic zoom-to-cursor and smooth motion — makes a product
   demo look professional with zero effort. (Free trial; QuickTime works too but
   looks flatter.)
2. **Voiceover — [ElevenLabs](https://elevenlabs.io).** Paste each VOICEOVER
   line, pick a calm measured voice, download the audio. Free tier (~10k chars/mo)
   is enough for 2.5 min. Voice prompt is below.
3. **Assemble & caption — [Descript](https://descript.com)** (or **CapCut**, free).
   Drop in the screen recording + the ElevenLabs audio, trim by transcript, add
   auto-captions, export 1080p.

**All-in-one alternative:** **Descript** alone can record the screen, generate an
AI voice, edit by transcript, and caption — one tool, one export.

**Skip:** avatar tools (Synthesia/HeyGen) — a talking head can't show your
product; generative video tools — they hallucinate the console.

---

## AI voiceover — voice & tone prompt

> Narrate as a **calm, confident SOC analyst giving a briefing** — measured, not a
> hype announcer. Neutral clear English. Pace ~145 wpm. Small pause before each
> number. No exclamation marks, no rising "ad" energy. Trust the facts to land.
> Reference: a security operations briefing, not a movie trailer.

Pick an ElevenLabs voice like **Adam / Daniel** (calm male) or **Alice / Matilda**
(calm female). Stability ~55%, similarity ~75%, style exaggeration low.

---

## Pre-flight (before you record)

- `colima start && make up` → wait ~40s → `make api` → run the console
  (`cd console && npm run build && npx next start -p 3000`), open
  `http://localhost:3000/console`.
- Confirm the header reads **● LIVE** (not OFFLINE) — that's the proof it's real.
- `rm -f data/action_states.json` so the two crown-jewel gates show **PENDING**
  (you'll approve one on camera).
- Record at **1920×1080**, hide bookmarks/other tabs, cursor large.

---

## The script — scene by scene

Each scene = **[SCREEN]** what to record · **[VO]** the exact voiceover to
generate · **[CAPTION]** on-screen text.

### 0 · Problem  (0:00–0:12)
- **[SCREEN]** Title card: "PRAHARÍ" + one line "AI cyber-resilience". (Optional
  3s generative or static background.)
- **[VO]** "The industry's mean time to detect an intrusion is about two hundred
  days. By the time a signature exists, the attack has already succeeded. So we
  detect behaviour — not signatures."
- **[CAPTION]** ~200 days to detect · behaviour, not signatures

### 1 · The verdict  (0:12–0:28)
- **[SCREEN]** Top of the console — the serif verdict hero, then scroll so the
  saffron stats band (1.66 days · 100% · 92.3% · <1s) is in frame.
- **[VO]** "This is PRAHARÍ, running live. One sentence an analyst can trust: a
  twenty-one-day nation-state intrusion, detected in one-point-six-six days,
  contained in under a second — the exam records prevented from ever leaving.
  Everything below proves it."
- **[CAPTION]** ● LIVE · real system, not fixtures

### 2 · Run it live  (0:28–0:40)
- **[SCREEN]** Click **Run fresh attack** in the header. Show the "Running a
  fresh intrusion… 3/6 · CORRELATE" indicator; when it finishes the timeline
  rewinds to day 0 and starts playing.
- **[VO]** "This isn't a recording. One click runs the entire loop live — ingest,
  detect, correlate, attribute, respond, audit — and then replays the intrusion
  from day zero."
- **[CAPTION]** one click → the whole loop runs live

### 3 · The attack unfolds  (0:40–1:05)
- **[SCREEN]** The "Watch it happen" timeline plays: stations ignite left to
  right — T1566 phishing → T1071 C2 → T1078 valid account.
- **[VO]** "A phishing macro on a clerk's workstation. Two nights later, a valid
  credential at two a.m. Then a memory dump. Individually, a SOC ignores each of
  these. PRAHARÍ's graph doesn't see events — it sees connections."
- **[CAPTION]** weak signals, fused into one chain

### 4 · Detection  (1:05–1:20)
- **[SCREEN]** The green "Confirmed · day 1.66" banner pulses; the confirmed
  station shows ✓ contained.
- **[VO]** "Confirmed on day one-point-six-six — seventeen days before the planned
  data theft. Not two hundred days. The command-and-control channel is severed in
  under a second."
- **[CAPTION]** confirmed day 1.66 · C2 severed <1s

### 5 · Evidence & attribution  (1:20–1:45)
- **[SCREEN]** Scroll to "Every claim drills to evidence." On the **Graph** tab,
  click a red spine edge → the drawer shows event id, technique, anomaly score,
  reasons. Then switch to the **ATT&CK** tab (observed + predicted moves).
- **[VO]** "Every claim drills to raw evidence — the event, the technique, the
  exact reasons it fired, and the system's own score. Attribution maps the chain
  to MITRE ATT&CK at ninety-two-point-three percent accuracy, with zero false
  attributions — and predicts what comes next."
- **[CAPTION]** 92.3% ATT&CK · 0 false attributions

### 6 · Response  (1:45–2:08)
- **[SCREEN]** The **Response** section: six actions auto-executed. Click
  **Approve** on *isolate DB-EXAMS*; the tag flips and the audit chip ticks up.
- **[VO]** "Response is autonomous where it's safe — seventy-five percent of the
  playbook runs itself in milliseconds. The two actions that could hurt wait for
  a human. One click… and that decision lands in the ledger. The exfiltration
  never happens. Breach prevented."
- **[CAPTION]** 75% auto · humans hold the crown-jewel gates

### 7 · Trust  (2:08–2:24)
- **[SCREEN]** The **Audit** section — real hashes. Click **⚠ Simulate tamper**:
  the chain breaks and cascades; then restore.
- **[VO]** "Every decision lands in a hash-chained, append-only ledger. Rewrite
  one row and every hash after it breaks — you can prove why the system acted, and
  no one can rewrite history."
- **[CAPTION]** tamper-evident · SHA-256 hash chain

### 8 · Close  (2:24–2:35)
- **[SCREEN]** Scroll back to the verdict / stats band.
- **[VO]** "Behavioural detection. Graph fusion. Auditable autonomy. PRAHARÍ —
  detection in hours, not months."
- **[CAPTION]** PRAHARÍ · detection in hours, not months · github.com/Kartik-99999/prahari

---

## If you use an all-in-one "script → video" tool (Descript / Pictory / InVideo AI)

Paste this as the master brief, then replace its stock B-roll with your own
screen recording of the console (the tool's stock footage won't show your product):

> Create a ~2.5-minute product demo for "PRAHARÍ", an AI cyber-resilience platform
> for critical infrastructure. Calm, confident SOC-briefing voiceover (~145 wpm),
> clean light aesthetic (near-white, a warm saffron accent, a serif headline
> feel). Use the scene-by-scene voiceover lines provided. All product visuals are
> a real screen recording of the console — do not generate synthetic UI. Add
> minimal lower-third captions per scene. End on "detection in hours, not months."

---

## Shot-list notes
- The **Run fresh attack → auto-replay** beat (scene 2–3) is the strongest moment
  — it proves the loop is live. Lead with it.
- The **Approve** click writes to the real append-only ledger, so re-record takes
  it to the next entry — fine, or `make audit-build` to reset the base chain.
- Keep the cursor slow; Screen Studio's auto-zoom does the drama for you.
- If the header ever reads OFFLINE, the backend isn't up — fix before recording.
- Keep background music under -20 dB; the voiceover carries it.
