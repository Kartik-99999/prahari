"use client";
/* PRAHARÍ — the front door, in the sarvam school: light, centered, serif-led,
   soft dawn gradients, restrained Indian motifs. Every number is a measured
   result from the repo's own evaluation suites (docs/RESULTS.md). */

import React, { useEffect, useRef, useState } from "react";
import Image from "next/image";
import Link from "next/link";
import s from "./landing.module.css";

const REPO = "https://github.com/Kartik-99999/prahari";

const LENSES = [
  { k: "story", glyph: "◉", label: "Story", img: "/shots/lens_story.png", w: 2576, h: 712, tall: false, cap: "The kill chain as a spine — stations ignite as the replay clock crosses them." },
  { k: "graph", glyph: "◈", label: "Graph", img: "/shots/lens_graph.png", w: 2576, h: 1526, tall: true, cap: "The provenance graph, coloured only by the system's own anomaly scores." },
  { k: "attack", glyph: "▦", label: "ATT&CK", img: "/shots/lens_attack.png", w: 2576, h: 792, tall: false, cap: "Observed techniques on their tactics — and the adversary's predicted next moves." },
  { k: "response", glyph: "⇄", label: "Response", img: "/shots/lens_response.png", w: 2576, h: 1630, tall: true, cap: "Six actions executed autonomously; the crown-jewel actions wait for one human click." },
  { k: "audit", glyph: "⛓", label: "Audit", img: "/shots/lens_audit.png", w: 2576, h: 1396, tall: true, cap: "Every decision in a SHA-256 hash chain — rewrite one row and the break is caught." },
] as const;

const STATS = [
  { val: "1.66", suffix: " days", name: "Mean time to detect" },
  { val: "100", suffix: "%", name: "Recall @ 1% FPR" },
  { val: "92.3", suffix: "%", name: "ATT&CK accuracy" },
  { val: "<1", suffix: " s", name: "Auto-containment" },
];

export default function Landing() {
  const root = useRef<HTMLDivElement>(null);
  const [lens, setLens] = useState(0);

  useEffect(() => {
    const el = root.current;
    if (!el) return;
    const rm = window.matchMedia("(prefers-reduced-motion: reduce)").matches;
    if (rm) return;
    // progressive enhancement: content ships visible; hide-then-reveal only
    // when the animation will actually run.
    const revealed = el.querySelectorAll("[data-reveal]");
    const io = new IntersectionObserver(
      (entries) => {
        for (const e of entries)
          if (e.isIntersecting) {
            e.target.classList.add(s.in);
            io.unobserve(e.target);
          }
      },
      { threshold: 0.12 },
    );
    revealed.forEach((n) => {
      n.classList.add(s.reveal);
      io.observe(n);
    });
    return () => io.disconnect();
  }, []);

  const L = LENSES[lens];

  return (
    <div ref={root} className={s.page}>
      {/* ---- floating pill nav ---- */}
      <div className={s.navShell}>
        <nav className={s.nav}>
          <Link className={s.wordmark} href="/">
            PRAHAR<span className={s.tick}>Í<i /></span>
          </Link>
          <div className={s.navLinks}>
            <a className={s.navLink} href="#platform">Platform</a>
            <a className={s.navLink} href="#evidence">Evidence</a>
            <a className={s.navLink} href="#trust">Trust</a>
            <a className={s.navLink} href={REPO}>GitHub</a>
          </div>
          <div className={s.navCtas}>
            <Link className={`${s.pill} ${s.pillDark} ${s.pillSm}`} href="/console">
              Open live console
            </Link>
            <Link className={`${s.pill} ${s.pillGhost} ${s.pillSm}`} href="/console?lens=story&day=2.9">
              Watch replay
            </Link>
          </div>
        </nav>
      </div>

      {/* ---- hero ---- */}
      <header className={s.hero}>
        <div className={s.heroWash} />
        <div className={`${s.wrap} ${s.heroIn}`}>
          <svg className={s.flourish} viewBox="0 0 96 22" fill="none" aria-hidden>
            <path d="M8 11c10-9 22-9 30 0M88 11c-10-9-22-9-30 0" stroke="currentColor" strokeWidth="1.4" strokeLinecap="round" />
            <path d="M14 11c7-5 15-5 21 0M82 11c-7-5-15-5-21 0" stroke="currentColor" strokeWidth="1.1" strokeLinecap="round" opacity="0.7" />
            <rect x="45" y="8" width="6" height="6" rx="1" transform="rotate(45 48 11)" fill="currentColor" />
          </svg>
          <div className={s.kicker}>India&rsquo;s Sovereign Cyber-Resilience Platform</div>
          <h1 className={s.h1}>The breach that never happened</h1>
          <p className={s.lede}>
            PRAHARÍ watches behaviour, not signatures. It confirmed a 21-day nation-state intrusion
            in 1.66 days, severed the attacker&rsquo;s channel in under a second, and wrote every
            decision to a tamper-evident ledger. The exam records never left the building.
          </p>
          <div className={s.heroCtas}>
            <Link className={`${s.pill} ${s.pillDark}`} href="/console">Open the live console</Link>
            <Link className={`${s.pill} ${s.pillGhost}`} href="/console?lens=story&day=2.9">Watch the attack replay</Link>
          </div>
          <div className={s.etym}>
            <b>प्रहरी</b>
            <span>prahari — the sentinel who keeps the watch</span>
          </div>

          <div className={s.builds} data-reveal="">
            <div className={s.buildsLabel}>Runs entirely on sovereign, on-prem infrastructure</div>
            <div className={s.logoRow}>
              <span>neo4j</span>
              <span>redis</span>
              <span>Postgre<i>SQL</i></span>
              <span>FastAPI</span>
              <span><i>scikit-</i>learn</span>
              <span>NEXT<i>.js</i></span>
              <span>docker</span>
            </div>
          </div>
        </div>
      </header>

      {/* ---- demo widget ---- */}
      <section className={s.section} id="platform">
        <div className={s.wrap}>
          <h2 className={s.h2} data-reveal="">The console India&rsquo;s SOCs deserve</h2>
          <p className={s.sub} data-reveal="">
            One incident, seven lenses, one replay clock. This is the running product —
            hydrated live from the backend, honest about it when it isn&rsquo;t.
          </p>
          <div className={s.demoCard} data-reveal="">
            <div className={s.tabsBar} role="tablist" aria-label="Console lenses">
              {LENSES.map((t, i) => (
                <button
                  key={t.k}
                  role="tab"
                  aria-selected={i === lens}
                  className={`${s.tab} ${i === lens ? s.tabOn : ""}`}
                  onClick={() => setLens(i)}
                >
                  <span className={s.tabGlyph} aria-hidden>{t.glyph}</span>
                  {t.label}
                </button>
              ))}
            </div>
            <div className={s.demoPanel}>
              <Image
                src={L.img}
                alt={`PRAHARÍ console — ${L.label} lens. ${L.cap}`}
                width={L.w}
                height={L.h}
                style={{ width: "100%", height: "auto" }}
                priority
              />
              {L.tall && (
                <div className={s.demoFade}>
                  <Link className={`${s.pill} ${s.pillGhost} ${s.pillSm}`} href={`/console?lens=${L.k}`}>
                    Continue in the console →
                  </Link>
                </div>
              )}
            </div>
            <div className={s.demoFoot}>
              <div className={s.demoNote}>
                {L.cap} &nbsp;·&nbsp; header badge reads <b>● LIVE · BFF</b> when the stack is up — and{" "}
                <code>◌ OFFLINE</code> when it isn&rsquo;t. It never pretends.
              </div>
              <Link className={`${s.pill} ${s.pillDark} ${s.pillSm}`} href={`/console?lens=${L.k}`}>
                Open this lens
              </Link>
            </div>
          </div>
        </div>
      </section>

      {/* ---- gold stats ---- */}
      <section className={s.stats} id="evidence">
        <div className={s.wrap}>
          <svg className={s.flourish} viewBox="0 0 96 22" fill="none" aria-hidden>
            <path d="M8 11c10-9 22-9 30 0M88 11c-10-9-22-9-30 0" stroke="currentColor" strokeWidth="1.4" strokeLinecap="round" />
            <rect x="45" y="8" width="6" height="6" rx="1" transform="rotate(45 48 11)" fill="currentColor" />
          </svg>
          <div className={s.statRow}>
            {STATS.map((m, i) => (
              <React.Fragment key={m.name}>
                {i > 0 && <span className={s.statDot} aria-hidden />}
                <div className={s.statCell} data-reveal="">
                  <span className={s.statVal}>
                    {m.val}
                    {m.suffix}
                  </span>
                  <span className={s.statName}>{m.name}</span>
                </div>
              </React.Fragment>
            ))}
          </div>
          <p className={s.statsFoot} data-reveal="">
            Measured, not promised — reproduce every number from{" "}
            <a href={`${REPO}/blob/main/docs/RESULTS.md`}>docs/RESULTS.md</a>. External benchmark
            first (CIC-IDS-2017 macro ROC 0.845), frozen-threshold transfer second (0.9987),
            in-domain last (0.9988) — with an honest limitations section alongside.
          </p>
        </div>
      </section>

      {/* ---- 3-up gradient category cards ---- */}
      <section className={s.section}>
        <div className={s.wrap}>
          <h2 className={s.h2} data-reveal="">One closed, auditable loop</h2>
          <p className={s.sub} data-reveal="">
            Six stages from raw telemetry to a ledgered decision — no signatures anywhere in the path.
          </p>
          <div className={s.trio}>
            <div className={s.trioCard} data-reveal="">
              <div className={`${s.trioArt} ${s.artIndigo}`}>
                <svg viewBox="0 0 104 104" fill="none" aria-hidden>
                  <circle cx="52" cy="52" r="34" stroke="currentColor" strokeWidth="2" />
                  <circle cx="52" cy="52" r="5" fill="currentColor" />
                  <circle cx="52" cy="14" r="4" fill="currentColor" />
                  <circle cx="86" cy="66" r="4" fill="currentColor" />
                  <circle cx="20" cy="70" r="4" fill="currentColor" />
                  <path d="M52 47V18M56 55l27 9M48 55l-25 12" stroke="currentColor" strokeWidth="2" />
                </svg>
              </div>
              <div className={s.trioName}>Behavioural detection</div>
              <div className={s.trioBody}>
                Unsupervised UEBA scores every event against each entity&rsquo;s own learned baseline.
                Labels are never an input — a hard assertion enforces it.
              </div>
              <div className={s.trioList}>
                <span className={s.trioItem}>Streaming novelty features <em>O(1)/event</em></span>
                <span className={s.trioItem}>IsolationForest + ECOD ensemble <em>unsupervised</em></span>
                <span className={s.trioItem}>IT and OT in one contract <em>OCSF</em></span>
              </div>
            </div>
            <div className={s.trioCard} data-reveal="">
              <div className={`${s.trioArt} ${s.artPeach}`}>
                <svg viewBox="0 0 104 104" fill="none" aria-hidden>
                  <path d="M52 16c8 12 26 14 26 34s-12 38-26 38S26 70 26 50s18-22 26-34z" stroke="currentColor" strokeWidth="2" />
                  <path d="M52 30c5 8 15 9 15 21s-7 24-15 24-15-12-15-24 10-13 15-21z" stroke="currentColor" strokeWidth="1.6" opacity="0.8" />
                  <circle cx="52" cy="56" r="4" fill="currentColor" />
                </svg>
              </div>
              <div className={s.trioName}>Graph correlation</div>
              <div className={s.trioBody}>
                A provenance graph lets weak signals reinforce each other: anomaly-lift fusion raises
                scores of 0.68–0.75 to ≥0.90 and assembles one ranked incident — 4× the next.
              </div>
              <div className={s.trioList}>
                <Link className={s.trioItem} href="/console?lens=graph">Provenance graph <em>28n / 71e →</em></Link>
                <Link className={s.trioItem} href="/console?lens=attack">ATT&amp;CK attribution <em>92.3% →</em></Link>
                <Link className={s.trioItem} href="/console?lens=path">Lateral path to the crown jewel <em>→</em></Link>
              </div>
            </div>
            <div className={s.trioCard} data-reveal="">
              <div className={`${s.trioArt} ${s.artSage}`}>
                <svg viewBox="0 0 104 104" fill="none" aria-hidden>
                  <path d="M52 14l30 11v22c0 20-13 34-30 43-17-9-30-23-30-43V25l30-11z" stroke="currentColor" strokeWidth="2" />
                  <path d="M38 52l10 10 20-22" stroke="currentColor" strokeWidth="2.4" strokeLinecap="round" strokeLinejoin="round" />
                </svg>
              </div>
              <div className={s.trioName}>Auditable autonomy</div>
              <div className={s.trioBody}>
                75% of the playbook runs itself in milliseconds. The two actions that could hurt wait
                for a human — and every decision lands in an append-only hash chain.
              </div>
              <div className={s.trioList}>
                <Link className={s.trioItem} href="/console?lens=response">SOAR queue, live gates <em>6 + 2 →</em></Link>
                <Link className={s.trioItem} href="/console?lens=audit">Tamper-evident ledger <em>SHA-256 →</em></Link>
                <span className={s.trioItem}>The AI cannot open a gate <em>platform-enforced</em></span>
              </div>
            </div>
          </div>
        </div>
      </section>

      {/* ---- value props ---- */}
      <section className={s.section} id="trust">
        <div className={s.wrap}>
          <h2 className={s.h2} data-reveal="">Built for the watch, not the demo</h2>
          <div className={s.valueCard} data-reveal="">
            <div className={s.valueArt} aria-hidden>
              <svg viewBox="0 0 300 240" fill="none">
                <path d="M150 26c14 22 46 25 46 60 0 26-20 46-46 46s-46-20-46-46c0-35 32-38 46-60z" stroke="currentColor" strokeWidth="2.4" />
                <circle cx="150" cy="92" r="16" stroke="currentColor" strokeWidth="2" />
                <circle cx="150" cy="92" r="4" fill="currentColor" />
                <path d="M30 214c34-38 74-58 120-58s86 20 120 58" stroke="currentColor" strokeWidth="2.4" strokeLinecap="round" />
                <path d="M60 214c26-26 55-40 90-40s64 14 90 40" stroke="currentColor" strokeWidth="1.6" strokeLinecap="round" opacity="0.75" />
              </svg>
            </div>
            <div className={s.valueList}>
              <div className={s.valueItem}>
                <svg className={s.star} viewBox="0 0 20 20" fill="currentColor" aria-hidden>
                  <path d="M10 1c1.2 4.2 4.8 7.8 9 9-4.2 1.2-7.8 4.8-9 9-1.2-4.2-4.8-7.8-9-9 4.2-1.2 7.8-4.8 9-9z" />
                </svg>
                <div>
                  <div className={s.valueName}>Sovereign by design</div>
                  <div className={s.valueBody}>
                    <code>PRAHARI_OFFLINE=1</code> runs the entire loop with the network hard-blocked —
                    local retrieval, cached ATT&CK, deterministic fallbacks. Proven by test, not by slide.
                  </div>
                </div>
              </div>
              <div className={s.valueItem}>
                <svg className={s.star} viewBox="0 0 20 20" fill="currentColor" aria-hidden>
                  <path d="M10 1c1.2 4.2 4.8 7.8 9 9-4.2 1.2-7.8 4.8-9 9-1.2-4.2-4.8-7.8-9-9 4.2-1.2 7.8-4.8 9-9z" />
                </svg>
                <div>
                  <div className={s.valueName}>Human at the core</div>
                  <div className={s.valueBody}>
                    Agents only propose. The platform computes blast radius and holds the gate — a
                    one-click human approval that itself becomes a ledger entry.
                  </div>
                </div>
              </div>
              <div className={s.valueItem}>
                <svg className={s.star} viewBox="0 0 20 20" fill="currentColor" aria-hidden>
                  <path d="M10 1c1.2 4.2 4.8 7.8 9 9-4.2 1.2-7.8 4.8-9 9-1.2-4.2-4.8-7.8-9-9 4.2-1.2 7.8-4.8 9-9z" />
                </svg>
                <div>
                  <div className={s.valueName}>Honest to a fault</div>
                  <div className={s.valueBody}>
                    Ground truth exists only to score the system — <code>assert_no_leakage</code> guards
                    every model input, and the API strips every <code>gt_*</code> field (verified 0/8).
                  </div>
                </div>
              </div>
            </div>
          </div>
          <div className={s.valueCta} data-reveal="">
            <Link className={`${s.pill} ${s.pillDark}`} href="/console">Get started — open the console</Link>
          </div>
        </div>
      </section>

      {/* ---- cinematic verdict ---- */}
      <section className={s.cinema}>
        <div className={s.wrap}>
          <svg className={s.cinemaMotif} viewBox="0 0 54 54" fill="none" aria-hidden>
            <circle cx="27" cy="27" r="9" stroke="currentColor" strokeWidth="1.4" />
            {Array.from({ length: 8 }).map((_, i) => (
              <ellipse
                key={i}
                cx="27"
                cy="10.5"
                rx="4.6"
                ry="8.5"
                stroke="currentColor"
                strokeWidth="1.2"
                transform={`rotate(${i * 45} 27 27)`}
              />
            ))}
          </svg>
          <div className={s.cinemaKicker}>The sentinel&rsquo;s verdict</div>
          <div className={s.cinemaHead}>Breach prevented</div>
          <p className={s.cinemaSub}>
            Confirmed on day 1.66 — seventeen days before the scheduled exfiltration. When the theft
            finally ran, it failed against a wall that had been up since day two.
          </p>
          <Link className={s.cinemaScroll} href="/console?lens=story&day=2.9">
            ▶&nbsp; Watch the moment of confirmation
          </Link>
        </div>
      </section>

      {/* ---- closing ---- */}
      <section className={s.closing}>
        <div className={s.wrap}>
          <p className={s.closingSmall} data-reveal="">
            Built for Hackathon PS#7 — AI-driven cyber resilience for critical national infrastructure.
          </p>
          <h2 className={s.closingHead} data-reveal="">The watch never ends</h2>
          <div className={s.closingCtas} data-reveal="">
            <Link className={`${s.pill} ${s.pillDark}`} href="/console">Open the live console</Link>
            <a className={`${s.pill} ${s.pillGhost}`} href={REPO}>Read the source</a>
          </div>
        </div>
      </section>

      {/* ---- footer ---- */}
      <footer className={s.footer}>
        <div className={s.wrap}>
          <div className={s.footGrid}>
            <div>
              <div className={s.footBrand}>
                PRAHAR<span className={s.tick}>Í<i /></span>
              </div>
              <div className={s.footTag}>Detection in hours, not months.</div>
              <div className={s.footChips}>
                <span className={s.footChip}>MIT LICENSE</span>
                <span className={s.footChip}>ZERO-EGRESS · VERIFIED</span>
              </div>
            </div>
            <div className={s.footCol}>
              <h4>Platform</h4>
              <Link href="/console">Live console</Link>
              <Link href="/console?lens=graph">Provenance graph</Link>
              <Link href="/console?lens=response">Response queue</Link>
              <Link href="/console?lens=audit">Audit ledger</Link>
            </div>
            <div className={s.footCol}>
              <h4>Evidence</h4>
              <a href={`${REPO}/blob/main/docs/RESULTS.md`}>Results &amp; methodology</a>
              <a href={`${REPO}/blob/main/VERIFICATION_REPORT.md`}>Verification report</a>
              <a href={`${REPO}/blob/main/docs/LIVE_AGENT_RUN.md`}>Live agent run</a>
              <a href={`${REPO}/blob/main/docs/AIR_GAPPED.md`}>Air-gap mode</a>
            </div>
            <div className={s.footCol}>
              <h4>Developers</h4>
              <a href={REPO}>GitHub</a>
              <a href={`${REPO}/blob/main/docs/SETUP.md`}>Setup guide</a>
              <a href={`${REPO}/blob/main/docs/API.md`}>API reference</a>
              <a href={`${REPO}/blob/main/docs/ARCHITECTURE.md`}>Architecture</a>
            </div>
            <div className={s.footCol}>
              <h4>Team</h4>
              <span>Kartik Bhardwaj</span>
              <span>Harshita</span>
              <span>Raghav Sharma</span>
            </div>
          </div>
          <div className={s.footWash} />
          <div className={s.footBar}>
            <span>© 2026 the PRAHARÍ team. Built for PS#7.</span>
            <span>प्रहरी — the sentinel who keeps the watch.</span>
          </div>
        </div>
      </footer>
    </div>
  );
}
