# PRAHARÍ — Deck Style Kit

Everything you need to build the pitch deck in PRAHARÍ's look — the same
sovereign‑platform aesthetic as the site & console. Copy the hexes, match the
type, follow the slide recipes.

> **The one rule:** light paper, a calm **serif** headline, **one** bold accent
> per slide, and a lot of air. Numbers get the hero treatment. Every slide makes
> one argument; nothing is cramped.

---

## 1 · Palette

A near‑white ground with ink text. The saffron→peach warmth and the gold serif
numerals are the signature; indigo is the interactive accent; green/red are
reserved for **meaning** (safe / threat), never decoration.

### Ground & ink
| Role | Hex |
|---|---|
| Paper (slide background — never pure white) | `#F8F8FA` |
| Card / panel | `#FFFFFF` |
| Ink (headings) | `#16161D` |
| Navy (primary CTA fill) | `#111827` |
| Body text | `#4B5563` |
| Muted / captions | `#9CA3AF` |
| Hairline / divider | `#E7E7EC` |

### Signature accents
| Role | Hex |
|---|---|
| Saffron (band) | `#E87040` |
| Peach (band, soft) | `#F5A060` |
| Gold (big numerals — gradient) | `#8A6A3E` → `#C8A878` → `#9C7C4E` |
| Lavender (hero wash) | `#C8C8F0` |
| Indigo (interactive accent) | `#4F46B8` (soft bg `#EEF1FF`) |
| Sage (bullet markers) | `#6BBF7A` |

### Semantic — meaning only, never decoration
| Role | Hex |
|---|---|
| Good / contained / prevented | `#059669` |
| Threat / critical | `#DC2626` |
| Elevated / flagged | `#B45309` |

---

## 2 · Type

Three families do everything: a calm **serif** carries every headline and every
big number, a clean **sans** handles body & UI, and a **mono** is reserved for
data (IDs, hashes, timestamps, scores — it signals "real evidence").

| Family | Install (free, Google Fonts) | PowerPoint‑safe fallback |
|---|---|---|
| Serif (display) | Source Serif 4 | Georgia |
| Sans (body/UI) | Inter | Calibri / Arial |
| Mono (data) | JetBrains Mono | Consolas |

**Sizes** (points, for a standard 13.33″ × 7.5″ 16:9 slide — double for a 1920‑px design):

| Role | Family | Size | Weight |
|---|---|---|---|
| Title slide H1 | Serif | 44–54 pt | 400 |
| Section heading H2 | Serif | 30–38 pt | 400 |
| Big stat number | Serif | 60–96 pt | 400 |
| Body / bullet | Sans | 16–18 pt | 400 |
| UI label / button | Sans | 13–15 pt | 600 |
| Eyebrow / kicker | Sans caps | 11–12 pt · tracking +0.16em | 650 |
| data · IDs · hashes | Mono | 12–14 pt | 400 |

> The serif is **weight 400, never bold, never stretched.** Install the three
> fonts on the machine that will *present*, or embed them
> (PowerPoint → File → Options → Save → "Embed fonts in the file").

---

## 3 · The signature moves

Four recurring devices carry the identity. Use them and the deck reads as
PRAHARÍ; skip them and it drifts generic.

1. **Saffron stats band** — a warm gradient strip that fades to transparent at
   top & bottom, with white serif numerals on top. One band per deck (the
   "proof at a glance" slide).
2. **Gold serif numerals** (on white) — a gold gradient fill on the serif
   number. Reserve for the money metrics; scale is the story.
3. **Pill controls & tags** — everything interactive or labelled is
   fully‑rounded (999px). Dark navy = primary, white/outline = secondary,
   indigo‑tint = a small status tag. A floating white pill "nav bar" sits across
   the top of content slides with a soft shadow.
4. **Soft rounded cards** — content lives in generous white cards (radius
   20–44px, a soft low shadow, never a hard border). One idea per card.

---

## 4 · Slide recipes

Four repeatable layouts cover most of a pitch. Keep the floating pill nav on
content slides; drop it on the full‑bleed title & the stats band.

- **Title** — centered serif over a soft lavender wash, indigo eyebrow, one
  green accent word.
- **Proof band** — the saffron gradient full‑bleed, 3–4 gold serif numbers with
  tiny labels. The "numbers" slide.
- **Section + card** — centered serif heading, one supporting line, content in a
  big white card or a 3‑up of soft cards.
- **Evidence** — a soft card holding a light table; sans names lead, mono facts
  + colour‑chips follow.

---

## 5 · Doing it in PowerPoint / Keynote / Slides

The look is achievable with native shapes — no plugins.

- **Saffron band** — a full‑width rectangle → Format Shape → **Gradient fill**,
  top‑to‑bottom, 4 stops: `#F8F8FA 0%` → `#E87040 30%` → `#ECA862 70%` →
  `#F8F8FA 100%`. The transparent ends make it float.
- **Gold numbers** — type in the serif, then Text Fill → **Gradient**:
  `#8A6A3E` → `#C8A878` → `#9C7C4E` at ~160°. On the saffron band use solid
  `#FFFDF9` instead.
- **Pills & the nav** — Rounded Rectangle → drag the corner handle to **full
  radius**. Nav = a white pill across the top with a soft shadow; primary button
  fill `#111827`, ghost = white with a `#D8DBE2` 1.5 pt outline.
- **Soft cards & shadows** — rounded rectangle, corner radius ≈ `0.25″`, white
  fill, no line. Shadow: outer, blur ~30, distance ~12, transparency ~86%,
  colour navy. Subtle — you should barely see it.

---

## 6 · Do & don't

**Do**
- Keep slides light & airy — one argument each.
- Let the serif headline + one big number carry the slide.
- Use the real console screenshots (`docs/replay_2.png`, `docs/console_graph.png`,
  `docs/console_attack.png`, or `console/public/shots/lens_*.png`) inside soft
  white cards.
- Reserve green for "contained/prevented," red for "threat."
- Lead with the honest evidence order: external benchmark → frozen transfer →
  in‑domain.

**Don't**
- No dark "hacker" slides, neon, or matrix rain — this brand is calm daylight.
- Don't bold the serif or stretch it — weight 400, real letterforms.
- Don't use green/red/indigo as decoration — they mean things.
- No hard borders or drop‑shadowed clip‑art; soft cards only.
- Don't crowd — if a slide has two ideas, it's two slides.

---

*प्रहरी — the sentinel who keeps the watch. Palette & type match the live site
and console exactly. A visual version is at [`docs/DECK_STYLE_GUIDE.html`](DECK_STYLE_GUIDE.html)
(open in any browser) / [`docs/DECK_STYLE_GUIDE.pdf`](DECK_STYLE_GUIDE.pdf).*
