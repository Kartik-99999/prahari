"use client";
/* PRAHARÍ — the front door. Editorial, calm, evidence-first.
   Every number on this page is a measured result from the repo's own
   evaluation suites (docs/RESULTS.md); nothing here is aspirational copy. */

import React, { useEffect, useRef } from "react";
import Image from "next/image";
import Link from "next/link";
import s from "./landing.module.css";

const REPO = "https://github.com/Kartik-99999/prahari";

// The real 21-day intrusion, as fractions of the replay window (day / 19.74).
const STATIONS: {
  d: number;
  tech: string;
  name: string;
  kind?: "good" | "bad";
  chip?: string;
}[] = [
  { d: 1.05, tech: "T1566", name: "phish" },
  { d: 2.71, tech: "T1078", name: "confirmed ✓", kind: "good", chip: "CONFIRMED · day 1.66 after foothold" },
  { d: 4.0, tech: "T1003", name: "cred dump" },
  { d: 8.0, tech: "T1021", name: "lateral → DC01" },
  { d: 17.9, tech: "T1560", name: "staging" },
  { d: 19.74, tech: "T1041", name: "exfil", kind: "bad", chip: "PREVENTED — C2 severed 17 days earlier" },
];
const DMAX = 19.74;
const SWEEP_S = 8.4; // the beam crosses the track in 70% of a 12 s cycle

const METRICS = [
  { val: 1.66, dec: 2, suffix: " d", name: "Mean time to detect", sub: "vs ~200 days industry dwell" },
  { val: 100, dec: 0, suffix: "%", name: "Recall @ 1% FPR", sub: "weak-signal behavioural detection" },
  { val: 92.3, dec: 1, suffix: "%", name: "ATT&CK technique accuracy", sub: "deterministic mapper · 0 false attributions" },
  { val: 75, dec: 0, suffix: "%", name: "Playbook automation", sub: "6 auto-executed / 2 human-gated" },
  { val: null, text: "<1 s", name: "Auto-containment", sub: "C2 severed at confirmation" },
  { val: 0, dec: 0, suffix: "", name: "Ground truth exposed", sub: "0/8 API endpoints leak — enforced in code" },
] as const;

export default function Landing() {
  const root = useRef<HTMLDivElement>(null);

  useEffect(() => {
    const el = root.current;
    if (!el) return;
    const rm = window.matchMedia("(prefers-reduced-motion: reduce)").matches;

    // reveal-on-scroll — progressive enhancement: content is visible by
    // default (SSR, print, screenshots); we hide-then-reveal only when the
    // animation will actually run.
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
    if (!rm) {
      revealed.forEach((n) => {
        n.classList.add(s.reveal);
        io.observe(n);
      });
    }

    // metric count-up (settles on the exact value; instant under reduced motion)
    const counters = el.querySelectorAll<HTMLElement>("[data-target]");
    const done = new WeakSet<Element>();
    const run = (n: HTMLElement) => {
      const target = parseFloat(n.dataset.target || "0");
      const dec = parseInt(n.dataset.decimals || "0", 10);
      const suffix = n.dataset.suffix || "";
      const fmt = (v: number) => v.toFixed(dec) + suffix;
      if (rm) {
        n.textContent = fmt(target); // already the SSR text; keep it exact
        return;
      }
      const t0 = performance.now();
      const tick = (t: number) => {
        const p = Math.min(1, (t - t0) / 1100);
        const eased = 1 - Math.pow(1 - p, 3);
        n.textContent = fmt(target * eased);
        if (p < 1) requestAnimationFrame(tick);
        else n.textContent = fmt(target);
      };
      requestAnimationFrame(tick);
    };
    const cio = new IntersectionObserver(
      (entries) => {
        for (const e of entries)
          if (e.isIntersecting && !done.has(e.target)) {
            done.add(e.target);
            run(e.target as HTMLElement);
            cio.unobserve(e.target);
          }
      },
      { threshold: 0.4 },
    );
    counters.forEach((n) => cio.observe(n));
    return () => {
      io.disconnect();
      cio.disconnect();
    };
  }, []);

  return (
    <div ref={root} className={s.page}>
      {/* ---- nav ---- */}
      <nav className={s.nav}>
        <div className={`${s.wrap} ${s.navIn}`}>
          <Link className={s.wordmark} href="/">
            PRAHAR<span className={s.tick}>Í<i /></span>
          </Link>
          <div className={s.navLinks}>
            <a className={s.navLink} href="#story">The intrusion</a>
            <a className={s.navLink} href="#system">The system</a>
            <a className={s.navLink} href="#trust">Trust</a>
            <a className={s.navLink} href="#results">Results</a>
            <Link className={`${s.btn} ${s.btnPrimary} ${s.btnSmall} ${s.navCta}`} href="/console">
              Open the live console
            </Link>
          </div>
        </div>
      </nav>

      {/* ---- hero ---- */}
      <header className={s.hero}>
        <div className={`${s.wrap} ${s.heroIn}`}>
          <div className={s.eyebrow}>AI cyber-resilience · critical national infrastructure</div>
          <h1 className={s.h1}>
            The breach that <em>never happened.</em>
          </h1>
          <p className={s.lede}>
            PRAHARÍ watches <strong>behaviour, not signatures</strong>. In a 21-day nation-state
            intrusion against an examination authority it confirmed the campaign in{" "}
            <strong>1.66 days</strong> — seventeen days before the planned exfiltration — severed the
            C2 channel in under a second, and wrote every decision to a tamper-evident ledger.{" "}
            <strong>The exam records never left the building.</strong>
          </p>
          <div className={s.heroCtas}>
            <Link className={`${s.btn} ${s.btnPrimary}`} href="/console">
              Open the live console <span aria-hidden>→</span>
            </Link>
            <Link className={`${s.btn} ${s.btnGhost}`} href="/console?lens=story&day=2.9">
              Watch the attack replay
            </Link>
          </div>
          <div className={s.etym}>
            <b>प्रहरी</b>
            <span>prahari — Sanskrit: the sentinel who keeps the watch.</span>
          </div>

          {/* signature: the intrusion replaying itself */}
          <div className={s.spine} aria-label="The 21-day intrusion timeline, as the system reconstructed it">
            <div className={s.spineHead}>
              <span>INC-001 · low-and-slow APT</span>
              <span>21-day window · replay</span>
            </div>
            <div className={s.track}>
              <div className={s.fill} />
              <div className={s.beam} />
              {STATIONS.map((st, i) => {
                const frac = st.d / DMAX;
                const delay = `${(frac * SWEEP_S).toFixed(2)}s`;
                return (
                  <div
                    key={st.tech}
                    className={`${s.station} ${i % 2 ? s.stAlt : ""} ${st.kind === "good" ? s.stGood : ""} ${st.kind === "bad" ? s.stBad : ""}`}
                    style={{ left: `${(frac * 100).toFixed(1)}%` }}
                  >
                    <div className={s.dot} style={{ animationDelay: delay }} />
                    <div className={s.stLabel} style={{ animationDelay: delay }}>
                      <b>{st.name}</b>
                      {st.tech} · d {st.d.toFixed(1)}
                    </div>
                    {st.chip && (
                      <div
                        className={`${s.chip} ${st.kind === "bad" ? s.chipBad : s.chipGood}`}
                        style={{ animationDelay: delay }}
                      >
                        {st.chip}
                      </div>
                    )}
                  </div>
                );
              })}
            </div>
            <div className={s.spineFoot}>
              <span>reconstructed by the system’s own scores — ground truth is never an input</span>
              <Link href="/console?lens=story&day=2.9">scrub it yourself in the console →</Link>
            </div>
          </div>
        </div>
      </header>

      {/* ---- metric band ---- */}
      <section className={`${s.section} ${s.sectionWhite}`} id="results-band">
        <div className={s.wrap}>
          <div className={s.metrics}>
            {METRICS.map((m) => (
              <div className={s.metric} data-reveal="" key={m.name}>
                {m.val === null ? (
                  <div className={s.metricVal}>{m.text}</div>
                ) : (
                  <div
                    className={s.metricVal}
                    data-target={m.val}
                    data-decimals={m.dec}
                    data-suffix={m.suffix}
                  >
                    {m.val.toFixed(m.dec)}
                    {m.suffix}
                  </div>
                )}
                <div className={s.metricName}>{m.name}</div>
                <div className={s.metricSub}>{m.sub}</div>
              </div>
            ))}
          </div>
          <p className={s.metricsFoot} data-reveal="">
            Measured on the repo’s own evaluation suites — reproduce every number with{" "}
            <a href={`${REPO}/blob/main/docs/RESULTS.md`}>docs/RESULTS.md</a>.
          </p>
        </div>
      </section>

      {/* ---- the story ---- */}
      <section className={s.section} id="story">
        <div className={s.wrap}>
          <div className={s.kicker} data-reveal="">the intrusion</div>
          <h2 className={s.h2} data-reveal="">Three whispers, three nights apart.</h2>
          <p className={s.sectionLede} data-reveal="">
            Modern intrusions don’t announce themselves. They arrive as events a tired SOC has
            learned to ignore — which is why the industry’s mean time to detect is around 200 days.
          </p>

          <div className={s.act}>
            <div data-reveal="">
              <div className={s.actNo}>ACT I</div>
              <h3 className={s.h3}>Weak signals, each one ignorable.</h3>
              <p className={s.actBody}>
                A macro-enabled email on a clerk’s workstation. A <strong>valid</strong> admin
                credential used at 2 a.m. A process quietly reading login secrets from memory.
                Signature tools stay silent — nothing here matches a known indicator. PRAHARÍ’s
                unsupervised UEBA scores every event against each entity’s own learned baseline,
                <strong> without ever seeing a label</strong>.
              </p>
              <div className={s.evRows}>
                <div className={s.evRow}>
                  <span className={s.evTech}>T1566</span>
                  <span>macro spawns rundll32.exe · WS03</span>
                  <span className={s.evScore}>0.87</span>
                </div>
                <div className={s.evRow}>
                  <span className={s.evTech}>T1078</span>
                  <span>admin.it logs in at 02:13 · from WS03</span>
                  <span className={s.evScore}>0.70</span>
                </div>
                <div className={s.evRow}>
                  <span className={s.evTech}>T1003</span>
                  <span>lsass memory read → out.dmp</span>
                  <span className={s.evScore}>0.90</span>
                </div>
              </div>
            </div>
            <figure className={s.shot} data-reveal="">
              <div className={s.shotBar}>
                <i /><i /><i />
                <span>console · graph lens — coloured only by the system’s own scores</span>
              </div>
              <Image src="/shots/console_graph.png" alt="Provenance graph: the WS03 → DC01 → DB-EXAMS attack spine reads as one bold line while benign context recedes" width={1424} height={837} style={{ width: "100%", height: "auto" }} priority />
            </figure>
          </div>

          <div className={`${s.act} ${s.actFlip}`}>
            <div data-reveal="">
              <div className={s.actNo}>ACT II</div>
              <h3 className={s.h3}>The graph refuses to forget.</h3>
              <p className={s.actBody}>
                Alone, each signal dies in a queue. PRAHARÍ builds a provenance graph of every
                entity and lets anomalies <strong>reinforce each other</strong>: personalized-
                PageRank “anomaly lift” divides out benign-hub bias, so weak scores of 0.68–0.75
                fuse to <strong>≥ 0.90</strong> and assemble into one ranked incident —{" "}
                <strong>4× the score of the next</strong> — tracing{" "}
                <strong>WS03 → DC01 → DB-EXAMS</strong>, straight toward the crown jewel.
              </p>
              <Link className={s.actLink} href="/console?lens=graph">
                open the graph lens →
              </Link>
            </div>
            <figure className={s.shot} data-reveal="">
              <div className={s.shotBar}>
                <i /><i /><i />
                <span>console · story lens — the moment of confirmation</span>
              </div>
              <Image src="/shots/replay_2.png" alt="Kill-chain story lens at the confirmation beat: green Confirmed banner, day 1.66 after foothold" width={1424} height={593} style={{ width: "100%", height: "auto" }} priority />
            </figure>
          </div>

          <div className={s.act}>
            <div data-reveal="">
              <div className={s.actNo}>ACT III</div>
              <h3 className={s.h3}>Confirmed on day 1.66. Contained in under a second.</h3>
              <p className={s.actBody}>
                At confirmation the playbook fires: the C2 channel is severed in milliseconds and
                six low-blast-radius actions execute themselves. The two actions that could hurt —
                isolating the exam-records database, disabling a domain admin — <strong>wait for a
                human</strong>. Seventeen days later the scheduled exfiltration attempts to run,
                and fails against a wall that has been up since day two.
              </p>
              <Link className={s.actLink} href="/console?lens=attack">
                see the ATT&CK attribution →
              </Link>
            </div>
            <figure className={s.shot} data-reveal="">
              <div className={s.shotBar}>
                <i /><i /><i />
                <span>console · ATT&CK lens — observed techniques, predicted next moves</span>
              </div>
              <Image src="/shots/console_attack.png" alt="ATT&CK matrix: observed techniques on their tactics with predicted next moves" width={1424} height={397} style={{ width: "100%", height: "auto" }} priority />
            </figure>
          </div>
        </div>
      </section>

      {/* ---- the system ---- */}
      <section className={`${s.section} ${s.sectionWhite}`} id="system">
        <div className={s.wrap}>
          <div className={s.kicker} data-reveal="">the system</div>
          <h2 className={s.h2} data-reveal="">One closed loop, six stages, no signatures.</h2>
          <p className={s.sectionLede} data-reveal="">
            Everything below runs on commodity hardware in Docker Compose — and in a fully
            air-gapped, zero-egress mode when the network itself can’t be trusted.
          </p>
          <div className={s.loop}>
            {[
              ["01 · INGEST", "Normalise everything", <>OCSF-style events over Redis Streams — IT and OT telemetry in one contract, <code>~52k events/s</code> on a single core.</>],
              ["02 · DETECT", "Behavioural UEBA", <>Unsupervised ensembles (<code>IsolationForest + ECOD</code>) with streaming novelty features. Labels are never an input — enforced by <code>assert_no_leakage</code>.</>],
              ["03 · CORRELATE", "Graph fusion", <>A Neo4j provenance graph with personalized-PageRank <em>anomaly lift</em>. Auto-selects external-C2 vs insider correlation from measured evidence.</>],
              ["04 · ATTRIBUTE", "Name the adversary’s play", <>Deterministic ATT&CK mapper (<code>92.3%</code>, 0 false attributions) plus an optional cite-or-abstain Claude agent over a local RAG of 697 techniques.</>],
              ["05 · RESPOND", "Autonomy with a leash", <>The planner only proposes. The <strong>platform</strong> computes blast radius and decides the gate — the AI cannot approve its own action.</>],
              ["06 · AUDIT", "Prove it, forever", <>Every decision lands in a SHA-256 hash-chained, append-only Postgres ledger. Rewrite one row and the chain breaks at that exact entry.</>],
            ].map(([no, name, body]) => (
              <div className={s.stage} data-reveal="" key={no as string}>
                <div className={s.stageNo}>{no}</div>
                <div className={s.stageName}>{name}</div>
                <div className={s.stageBody}>{body}</div>
              </div>
            ))}
          </div>
        </div>
      </section>

      {/* ---- trust ---- */}
      <section className={s.night} id="trust">
        <div className={s.wrap}>
          <div className={s.kicker} data-reveal="">trust, engineered</div>
          <h2 className={s.h2} data-reveal="">Autonomy you can audit.</h2>
          <p className={s.sectionLede} data-reveal="">
            For critical infrastructure, “trust the AI” is not an answer. PRAHARÍ is built so you
            don’t have to.
          </p>
          <div className={s.trustGrid}>
            <div className={s.trustCard} data-reveal="">
              <div className={s.trustName}><i />Tamper-evident ledger</div>
              <p className={s.trustBody}>
                Append-only, SHA-256 hash-chained, protected by database triggers. Even a
                privileged insider who rewrites a row is caught by <code>verify_chain()</code> at
                the exact sequence number — demonstrated live in the console.
              </p>
              <div className={s.hashStrip}>
                <span>seq 09</span><b>e0c1a4…</b><span>→</span>
                <span>seq 10</span><b>2f3236d953f6…</b><span>→</span>
                <span>verify_chain()</span><b>ok</b>
              </div>
            </div>
            <div className={s.trustCard} data-reveal="">
              <div className={s.trustName}><i />The AI cannot open a gate</div>
              <p className={s.trustBody}>
                Response agents propose <code>{"{action, target, rationale}"}</code> — nothing
                else. Blast radius and gating are computed by the platform, so high-impact actions
                always require a one-click human approval that itself lands in the ledger.
              </p>
            </div>
            <div className={s.trustCard} data-reveal="">
              <div className={s.trustName}><i />Zero-egress, air-gap ready</div>
              <p className={s.trustBody}>
                <code>PRAHARI_OFFLINE=1</code> runs the full loop with the network hard-blocked —
                local TF-IDF retrieval, cached ATT&CK, deterministic fallbacks. Proven by test,
                not promised by slide.
              </p>
            </div>
            <div className={s.trustCard} data-reveal="">
              <div className={s.trustName}><i />Ground truth is never an input</div>
              <p className={s.trustBody}>
                Scenario labels exist only to score the system. <code>assert_no_leakage</code>{" "}
                guards every model input, the API strips every <code>gt_*</code> field (verified
                0/8 endpoints), and the console colours purely from the system’s own scores.
              </p>
            </div>
          </div>
        </div>
      </section>

      {/* ---- results ---- */}
      <section className={s.section} id="results">
        <div className={s.wrap}>
          <div className={s.kicker} data-reveal="">results, in the honest order</div>
          <h2 className={s.h2} data-reveal="">Hard numbers first. Caveats attached.</h2>
          <div className={s.evidence} data-reveal="">
            <div className={s.evidenceRow}>
              <div className={s.evidenceVal}>0.845</div>
              <div className={s.evidenceWhat}>
                <b>External benchmark — CIC-IDS-2017</b>
                Macro ROC-AUC on a public dataset the system never trained on. The only number
                that follows us out of our own scenario.
              </div>
              <div className={s.evidenceTag}>held-out · public</div>
            </div>
            <div className={s.evidenceRow}>
              <div className={s.evidenceVal}>0.9987</div>
              <div className={s.evidenceWhat}>
                <b>Cross-attack generalisation</b>
                An unseen insider-theft campaign, scored with <em>frozen</em> thresholds — no
                refitting, no peeking. 100% recall at 1% FPR.
              </div>
              <div className={s.evidenceTag}>held-out · frozen</div>
            </div>
            <div className={`${s.evidenceRow} ${s.evidenceStrong}`}>
              <div className={s.evidenceVal}>0.9988</div>
              <div className={s.evidenceWhat}>
                <b>The 21-day APT you just watched</b>
                ROC-AUC on the controlled scenario: 13/13 malicious events in one ranked incident,
                MTTD 1.66 days, breach prevented.
              </div>
              <div className={s.evidenceTag}>in-domain</div>
            </div>
          </div>
          <p className={s.caveat} data-reveal="">
            Near-perfect in-domain numbers reflect a clean, controlled scenario — which is exactly
            why we report the external benchmark and frozen-threshold transfer first, and publish
            an honest limitations section alongside every result:{" "}
            adversarial evasion, OT feature gaps, attribution generalisation — all measured, all in{" "}
            <a href={`${REPO}/blob/main/docs/RESULTS.md`} style={{ color: "var(--teal-ink, #115e59)", fontWeight: 600 }}>docs/RESULTS.md</a>.
          </p>
        </div>
      </section>

      {/* ---- finale ---- */}
      <section className={`${s.finale} ${s.sectionWhite}`}>
        <div className={s.wrap}>
          <h2 className={s.h2} data-reveal="">Watch it catch the next one.</h2>
          <div className={s.finaleCtas} data-reveal="">
            <Link className={`${s.btn} ${s.btnPrimary}`} href="/console">
              Open the live console <span aria-hidden>→</span>
            </Link>
            <a className={`${s.btn} ${s.btnGhost}`} href={REPO}>
              Read the source on GitHub
            </a>
          </div>
          <p className={s.finaleHint} data-reveal="">
            or replay a fresh intrusion through the whole loop: <code>make attack</code> — ~20
            seconds, no API key.
          </p>
        </div>
      </section>

      {/* ---- footer ---- */}
      <footer className={s.footer}>
        <div className={`${s.wrap} ${s.footIn}`}>
          <span className={s.footBrand}>
            PRAHAR<span className={s.tick}>Í<i /></span>
          </span>
          <span>Built for Hackathon PS#7 · Kartik Bhardwaj, Harshita &amp; Raghav Sharma</span>
          <span>
            <a href={REPO}>GitHub</a> · MIT License · detection in hours, not months
          </span>
        </div>
      </footer>
    </div>
  );
}
