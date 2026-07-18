# PRAHARÍ — Demo Video Production Prompt

A ~2:40 hackathon demo that walks the **actual website** — the landing page tells
the story, then the live console proves it. The whole pitch is "this works," so
the recipe is: **screen-record the real site → AI voiceover from the script below
→ light editing + captions.** Do **not** use generative text-to-video (Runway /
Sora / Pika / Kling) — it invents footage; a judge needs to see the real thing.
(A 3-second generative title card is the only place that's OK.)

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
  (`cd console && npm run build && npx next start -p 3000`).
- The video **opens on the landing page** `http://localhost:3000`, then cuts into
  the console `http://localhost:3000/console` — have both ready.
- On the console, confirm the header reads **● LIVE** (not OFFLINE) — that's the
  proof it's real.
- `rm -f data/action_states.json` so the two crown-jewel gates show **PENDING**
  (you'll approve one on camera).
- Record at **1920×1080**, hide bookmarks/other tabs, cursor large.

---

## The script — scene by scene (walks the website)

Each scene = **[SCREEN]** what to record · **[VO]** the exact voiceover to
generate · **[CAPTION]** on-screen text. The video follows the site itself:
**Act 1 = the landing page** (`localhost:3000`) tells the story; **Act 2 = the
live console** (`/console`) proves it.

---

### ACT 1 — the landing page · the story

#### A · Open on the hero  (0:00–0:16)
- **[SCREEN]** Load `localhost:3000`. Hold on the hero — the serif "The breach
  that never happened" over the soft dawn (peach→lavender) wash, the प्रहरी line.
  Scroll very slowly.
- **[VO]** "The industry's mean time to detect an intrusion is about two hundred
  days — by the time a signature exists, the attack has already succeeded. PRAHARÍ
  makes a different bet: watch behaviour, not signatures."
- **[CAPTION]** प्रहरी — the sentinel who keeps the watch

#### B · The measured numbers  (0:16–0:32)
- **[SCREEN]** Keep scrolling to the gold **stats strip** — 1.66 days · 100% ·
  92.3% · <1 s. Let the numbers sit in frame.
- **[VO]** "In a twenty-one-day nation-state intrusion, it confirmed the attack in
  one-point-six-six days, contained it in under a second, and prevented the theft.
  Every number here is measured on our own evaluation suites — not claimed."
- **[CAPTION]** measured, not claimed

#### C · One closed loop  (0:32–0:50)
- **[SCREEN]** Scroll through the "One closed, auditable loop" section — the three
  gradient cards (Behavioural detection · Graph correlation · Auditable autonomy).
  Pause briefly on each.
- **[VO]** "One closed loop, six stages, no signatures. Unsupervised detection
  scores behaviour. A provenance graph fuses weak signals into one ranked
  incident. And every autonomous action is provable — written to a tamper-evident
  ledger."
- **[CAPTION]** detect · correlate · attribute · respond · audit

#### D · The verdict moment  (0:50–1:04)
- **[SCREEN]** Scroll through "Built for the watch, not the demo" (Sovereign by
  design / Human at the core / Honest to a fault), landing on the cinematic gold
  **"Breach prevented"** panel.
- **[VO]** "Sovereign by design — it runs air-gapped. Human at the core — the AI
  can propose, but only a person opens a crown-jewel gate. Honest to a fault —
  ground truth is never a model input. The result: a breach that never happened."
- **[CAPTION]** breach prevented — 17 days before the theft

#### Transition  (1:04–1:10)
- **[SCREEN]** Scroll back up; click the **"Open the live console"** pill in the nav.
- **[VO]** "But a landing page can claim anything. So here's the real system —
  running live."
- **[CAPTION]** → the live console

---

### ACT 2 — the live console · the proof

#### E · The verdict, live  (1:10–1:24)
- **[SCREEN]** The console loads; header shows **● LIVE**. The serif verdict hero
  over the saffron stats band.
- **[VO]** "This is the analyst console, hydrated live from the running backend.
  One sentence you can trust — and everything below it drills to evidence."
- **[CAPTION]** ● LIVE · real system, not fixtures

#### F · Run it live  (1:24–1:44) ⭐ *the strongest beat*
- **[SCREEN]** Click **Run fresh attack**. Show "Running… 3/6 · CORRELATE"; on
  completion the timeline rewinds to day 0 and auto-plays. (Speed this ~20s up 2–3× in the edit.)
- **[VO]** "One click runs the entire loop live — ingest, detect, correlate,
  attribute, respond, audit — in about twenty seconds. Then it replays the
  intrusion from day zero."
- **[CAPTION]** one click → the whole loop runs live

#### G · The attack unfolds → confirmed  (1:44–2:04)
- **[SCREEN]** The timeline plays; stations ignite T1566 → T1071 → T1078; the
  green **"Confirmed · day 1.66"** banner pulses.
- **[VO]** "A phishing macro. A two-a.m. credential. A memory dump. Individually
  ignorable — but the graph sees the connections, and confirms on day
  one-point-six-six. Seventeen days before the planned theft."
- **[CAPTION]** confirmed day 1.66 · C2 severed <1s

#### H · Evidence  (2:04–2:19)
- **[SCREEN]** Scroll to "Every claim drills to evidence." On the **Graph** tab
  click a red spine edge → the drawer shows event id, technique, anomaly score,
  reasons. Switch to the **ATT&CK** tab.
- **[VO]** "Every claim drills to raw evidence — the event, the technique, the
  exact reasons it fired. Attribution maps the chain to MITRE ATT&CK at
  ninety-two-point-three percent, with zero false attributions."
- **[CAPTION]** 92.3% ATT&CK · 0 false attributions

#### I · Response + trust  (2:19–2:36)
- **[SCREEN]** **Response** section — click **Approve** on *isolate DB-EXAMS* (the
  audit chip ticks up). Then **Audit** — click **⚠ Simulate tamper** (the chain
  breaks and cascades).
- **[VO]** "Seventy-five percent of the response runs itself; the crown-jewel
  actions wait for a human. One click, and that decision lands in a hash-chained
  ledger — rewrite one row and the whole chain breaks. You can prove why the
  system acted."
- **[CAPTION]** 75% auto · tamper-evident ledger

#### Close  (2:36–2:44)
- **[SCREEN]** Scroll back to the console verdict (or the landing hero).
- **[VO]** "Behavioural detection. Graph fusion. Auditable autonomy. PRAHARÍ —
  detection in hours, not months."
- **[CAPTION]** github.com/Kartik-99999/prahari · detection in hours, not months

---

## If you use an all-in-one "script → video" tool (Descript / Pictory / InVideo AI)

Paste this as the master brief, then replace its stock B-roll with your own
screen recording of the console (the tool's stock footage won't show your product):

> Create a ~2.5-minute product demo for "PRAHARÍ", an AI cyber-resilience platform
> for critical infrastructure. It walks the real website: first the landing page
> (which tells the story), then the live console (which proves it). Calm,
> confident SOC-briefing voiceover (~145 wpm), clean light aesthetic (near-white,
> a warm saffron accent, a serif headline feel). Use the scene-by-scene voiceover
> lines provided. All visuals are a real screen recording of the site — do not
> generate synthetic UI. Add minimal lower-third captions per scene. End on
> "detection in hours, not months."

---

## Shot-list notes
- **Landing → console cut (Transition):** end Act 1 by actually clicking "Open the
  live console" — the on-screen navigation from the marketing page into the live
  product is the pivot of the whole video ("claims → proof").
- The **Run fresh attack → auto-replay** beat (scene F) is the strongest moment —
  it proves the loop is live. If you only cut one clip for social, cut F–G.
- The **Approve** click writes to the real append-only ledger, so re-record takes
  it to the next entry — fine, or `make audit-build` to reset the base chain.
- Keep the cursor slow; Screen Studio's auto-zoom does the drama for you.
- If the header ever reads OFFLINE, the backend isn't up — fix before recording.
- Keep background music under -20 dB; the voiceover carries it.
