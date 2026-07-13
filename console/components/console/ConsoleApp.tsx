"use client";
// The console as a PRODUCT PAGE, not a dashboard: one idea per section,
// centered serif headings, one huge soft card each, a saffron stats band.
// Data stays generic — whatever incidents the BFF ranks, this renders.
import Link from "next/link";
import React, { useEffect, useRef, useState } from "react";
import { briefUrl } from "@/lib/api";
import s from "./console.module.css";
import { useConsole } from "./useConsole";
import type { ConsoleModel } from "./derive";
import { GraphLens } from "./GraphLens";
import { AttckLens, EventsLens, PathLens, StoryLens } from "./lenses";
import { AuditLens, ResponseLens } from "./ops";

const EV_TABS = [
  { k: "graph", label: "Graph", title: "The provenance graph" },
  { k: "attack", label: "ATT&CK", title: "Techniques on the matrix" },
  { k: "path", label: "Path", title: "The lateral walk" },
  { k: "events", label: "Events", title: "Ranked raw evidence" },
] as const;
type EvKey = (typeof EV_TABS)[number]["k"];

export type Sel = { kind: "edge" | "node"; id: string } | null;

const RATE = 2.4; // replay days per second at 1×

export default function ConsoleApp() {
  // deep links: ?incident=INC-002&lens=story|graph|attack|path|events|response|audit&day=2.9
  const q = typeof window !== "undefined" ? new URLSearchParams(window.location.search) : null;
  const qLens = q?.get("lens") ?? null;
  const { st, version, attack, deciding, selectIncident, decide, runAttack } = useConsole(
    q?.get("incident") ?? null,
  );
  const attackPending = useRef(false);
  const [evTab, setEvTab] = useState<EvKey>(
    EV_TABS.some((t) => t.k === qLens) ? (qLens as EvKey) : "graph",
  );
  const [sel, setSel] = useState<Sel>(null);
  const [overlayGT, setOverlayGT] = useState(false);

  // ---- replay clock ---------------------------------------------------------
  const [playDay, setPlayDay] = useState(0);
  const [playing, setPlaying] = useState(false);
  const [speed, setSpeed] = useState(4);
  const wantDay = useRef<number | null>(q?.get("day") ? parseFloat(q.get("day")!) : null);
  const wantScroll = useRef<string | null>(qLens);
  const raf = useRef(0);
  const last = useRef<number | null>(null);
  const M = st.model;
  const dmax = M?.dmax ?? 20;

  // Every successful (re)load bumps `version`. A fresh attack finishing rewinds
  // to day 0 and auto-plays — you watch the new intrusion build from scratch.
  // A normal load / incident switch parks at the end (or the deep-linked day).
  useEffect(() => {
    if (!M) return;
    // defer one frame: the fresh model has already rendered, we just re-park
    // the playhead — keeps this out of the synchronous render cascade.
    const r = requestAnimationFrame(() => {
      setSel(null);
      if (attackPending.current) {
        attackPending.current = false;
        setSpeed(1); // the deliberate "watch it build" moment — real-time pacing
        setPlayDay(0);
        setPlaying(true);
        document.getElementById("story")?.scrollIntoView({ behavior: "smooth", block: "start" });
        return;
      }
      setPlayDay(wantDay.current != null ? Math.min(dmax, Math.max(0, wantDay.current)) : dmax);
      wantDay.current = null;
      const target = wantScroll.current;
      wantScroll.current = null;
      if (target) {
        const id = ["graph", "attack", "path", "events"].includes(target) ? "evidence" : target;
        setTimeout(() => document.getElementById(id)?.scrollIntoView({ behavior: "smooth", block: "start" }), 80);
      }
    });
    return () => cancelAnimationFrame(r);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [version]);

  const onAttack = () => {
    // rewind + jump to the timeline so the rebuild is watched from the top;
    // the completion effect above then plays it from day 0.
    attackPending.current = true;
    setPlaying(false);
    setPlayDay(0);
    document.getElementById("story")?.scrollIntoView({ behavior: "smooth", block: "start" });
    runAttack();
  };

  useEffect(() => {
    if (!playing) {
      last.current = null;
      return;
    }
    const step = (t: number) => {
      if (last.current != null) {
        const dt = (t - last.current) / 1000;
        setPlayDay((d) => {
          const nd = d + RATE * speed * dt;
          if (nd >= dmax) {
            setPlaying(false);
            return dmax;
          }
          return nd;
        });
      }
      last.current = t;
      raf.current = requestAnimationFrame(step);
    };
    raf.current = requestAnimationFrame(step);
    return () => cancelAnimationFrame(raf.current);
  }, [playing, speed, dmax]);

  const togglePlay = () => {
    setPlaying((p) => {
      if (!p && playDay >= dmax - 0.02) setPlayDay(0);
      return !p;
    });
  };
  const replayFromStart = () => {
    document.getElementById("story")?.scrollIntoView({ behavior: "smooth", block: "start" });
    setPlayDay(0);
    setSpeed(4);
    setPlaying(true);
  };
  const openEdge = (id: string) => {
    setEvTab("graph");
    setSel({ kind: "edge", id });
    document.getElementById("evidence")?.scrollIntoView({ behavior: "smooth", block: "start" });
  };

  const live = st.status === "live";

  return (
    <div className={s.page}>
      <Nav
        live={live}
        model={M}
        incidents={st.incidents}
        onPick={selectIncident}
        attack={attack}
        onAttack={onAttack}
      />

      {st.status === "offline" ? (
        <div className={s.wrap}>
          <div className={s.stateCard}>
            <div className={s.kicker}>◌ backend offline</div>
            <h1>The sentinel is not reporting.</h1>
            <p>
              This console renders the live system only — no fixtures, no pretending. Start the
              stack and refresh: <code>make up && make api</code>, then <code>make attack</code>{" "}
              for a fresh intrusion — or visit the <Link href="/">landing page</Link> meanwhile.
            </p>
          </div>
        </div>
      ) : !M ? (
        <div className={s.wrap}>
          <div className={s.stateCard}>
            <div className={s.kicker}>· connecting</div>
            <h1>Waking the sentinel…</h1>
          </div>
        </div>
      ) : (
        <>
          {/* ================= hero ================= */}
          <header className={s.hero}>
            <div className={s.heroWash} />
            <div className={`${s.wrap} ${s.heroIn}`}>
              <svg className={s.flourish} viewBox="0 0 96 22" fill="none" aria-hidden>
                <path d="M8 11c10-9 22-9 30 0M88 11c-10-9-22-9-30 0" stroke="currentColor" strokeWidth="1.4" strokeLinecap="round" />
                <rect x="45" y="8" width="6" height="6" rx="1" transform="rotate(45 48 11)" fill="currentColor" />
              </svg>
              <div className={s.heroChips}>
                <span className={s.heroChip}>
                  <span className={s.statusDot} style={{ background: live ? "#059669" : "#CBD5E1" }} />
                  {M.id} · {M.hero.status}
                </span>
                <span className={s.heroChip}>{M.hero.nEvents} correlated events</span>
                <span className={s.heroChip}>{M.hero.spanDays}-day window</span>
                {M.fusion && (
                  <span className={s.heroChip} title={`external-anchor ${M.fusion.fracText} ${M.fusion.insider ? "<" : "≥"} ${M.fusion.thrText} · pivots ${M.fusion.pivots.join(", ")}`}>
                    {M.fusion.label} correlation{M.fusion.auto ? " · auto" : ""}
                  </span>
                )}
              </div>
              <h1 className={s.h1}>
                {M.hero.mttd ? (
                  <>
                    Detected in <span className={s.indigoWord}>{M.hero.mttd} days</span>.
                    {M.hero.prevented ? (
                      <>
                        {" "}
                        The breach <span className={s.goodWord}>never happened</span>.
                      </>
                    ) : M.hero.status === "contained" ? (
                      <>
                        {" "}
                        <span className={s.goodWord}>Contained</span> in under a second.
                      </>
                    ) : null}
                  </>
                ) : (
                  <>
                    {M.id} is <span style={{ color: "var(--amber)" }}>{M.hero.status}</span> — under
                    the sentinel&rsquo;s watch.
                  </>
                )}
              </h1>
              <p className={s.heroSub}>
                {M.hero.confirmedDate ? (
                  <>
                    Confirmed on {M.hero.confirmedDate}
                    {M.hero.dwell ? ` — ${M.hero.dwell} days before the planned exfiltration` : ""}
                    {M.hero.exfilMD ? `; the ${M.hero.exfilMD} exfiltration never completed` : ""}. Every
                    claim on this page is the running system&rsquo;s own output — and every claim
                    drills to raw evidence.
                  </>
                ) : (
                  <>
                    The correlator is still assembling this campaign
                    {M.hero.hostsText ? ` across ${M.hero.hostsText}` : ""}. Every claim on this page
                    drills to raw evidence.
                  </>
                )}
              </p>
              <div className={s.heroCtas}>
                <button className={`${s.pillDark} ${s.focusable}`} onClick={replayFromStart}>
                  ▶ Replay the attack
                </button>
                <a className={`${s.pillGhost} ${s.focusable}`} href={briefUrl(M.id)} target="_blank" rel="noreferrer">
                  Analyst brief ↗
                </a>
              </div>
            </div>
          </header>

          {/* ================= saffron stats band ================= */}
          <div className={s.band}>
            <div className={s.wrap}>
              <div className={s.bandRow}>
                {[
                  { v: `${Number(M.metrics.find((x) => x.key === "mttd")?.display.replace(" d", "") ?? "—")}d`, n: "Mean time to detect" },
                  { v: M.metrics.find((x) => x.key === "recall")?.display ?? "—", n: "Recall @ 1% FPR" },
                  { v: M.metrics.find((x) => x.key === "tech")?.display ?? "—", n: "ATT&CK accuracy" },
                  { v: M.metrics.find((x) => x.key === "mttr")?.display.replace(" ", "") ?? "—", n: "Auto-containment" },
                ].map((c) => (
                  <div key={c.n} className={s.bandCell}>
                    <span className={s.bandVal}>{c.v}</span>
                    <span className={s.bandName}>{c.n}</span>
                  </div>
                ))}
              </div>
            </div>
          </div>

          {/* ================= story ================= */}
          <section className={s.section} id="story">
            <div className={s.wrap}>
              <h2 className={s.h2}>Watch it happen</h2>
              <p className={s.sub}>
                {Math.round(M.dmax)} days of telemetry on one clock — every station ignites the
                moment the system first saw it.
              </p>
              <div className={s.bigCard}>
                <div className={s.playRow}>
                  <div style={{ display: "flex", alignItems: "center", gap: 12, flexWrap: "wrap" }}>
                    <button className={`${s.pillDark} ${s.focusable}`} onClick={togglePlay}>
                      {playing ? "❚❚ Pause" : playDay >= dmax - 0.02 ? "▶ Replay attack" : "▶ Play"}
                    </button>
                    <div className={s.speedTrack}>
                      {[1, 4, 12].map((v) => (
                        <button key={v} className={`${s.speedBtn} ${speed === v ? s.speedOn : ""}`} onClick={() => setSpeed(v)}>
                          {v}×
                        </button>
                      ))}
                    </div>
                    <span className={s.clockText}>
                      <b style={{ color: "var(--ink)" }}>{fmtClock(M.t0, playDay, dmax)}</b>
                      <span style={{ color: "var(--mut)" }}> · day {playDay.toFixed(1)}</span>
                    </span>
                  </div>
                  <span className={s.clockText} style={{ fontSize: 11, letterSpacing: "0.08em", color: "var(--mut)" }}>
                    {windowLabel(M.t0, dmax)}
                  </span>
                </div>
                <ConfirmBanner model={M} playDay={playDay} attack={attack} />
                <StoryLens
                  model={M}
                  playDay={playDay}
                  onScrub={(d) => { setPlaying(false); setPlayDay(d); }}
                  onTech={() => { setEvTab("attack"); document.getElementById("evidence")?.scrollIntoView({ behavior: "smooth" }); }}
                />
              </div>
            </div>
          </section>

          {/* ================= evidence ================= */}
          <section className={s.section} id="evidence">
            <div className={s.wrap}>
              <h2 className={s.h2}>Every claim drills to evidence</h2>
              <p className={s.sub}>
                Real event ids, real timestamps, the system&rsquo;s own scores — never the
                ground-truth label.
              </p>
              <div className={s.bigCard}>
                <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between", gap: 16, flexWrap: "wrap" }}>
                  <div className={s.serif} style={{ fontSize: 24, fontWeight: 500 }}>
                    {EV_TABS.find((t) => t.k === evTab)?.title}
                  </div>
                  <div className={s.segTrack} role="tablist">
                    {EV_TABS.map((t) => (
                      <button key={t.k} role="tab" aria-selected={evTab === t.k} className={`${s.seg} ${evTab === t.k ? s.segOn : ""}`} onClick={() => setEvTab(t.k)}>
                        {t.label}
                      </button>
                    ))}
                  </div>
                </div>
                <div style={{ marginTop: 8 }}>
                  {evTab === "graph" && (
                    <GraphLens model={M} playDay={playDay} sel={sel} setSel={setSel} overlayGT={overlayGT} setOverlayGT={setOverlayGT} />
                  )}
                  {evTab === "attack" && <AttckLens model={M} playDay={playDay} />}
                  {evTab === "path" && <PathLens model={M} />}
                  {evTab === "events" && <EventsLens model={M} onOpen={openEdge} />}
                </div>
              </div>
            </div>
          </section>

          {/* ================= response ================= */}
          <section className={s.section} id="response">
            <div className={s.wrap}>
              <h2 className={s.h2}>
                Autonomy, with a <em>human</em> at the core
              </h2>
              <p className={s.sub}>
                The planner proposes; the platform holds the gate. Approvals land in the same
                append-only ledger as everything else.
              </p>
              <div className={s.bigCard}>
                <ResponseLens model={M} live={live} deciding={deciding} onDecide={decide} />
              </div>
            </div>
          </section>

          {/* ================= audit ================= */}
          <section className={s.section} id="audit">
            <div className={s.wrap}>
              <h2 className={s.h2}>Provable, forever</h2>
              <p className={s.sub}>
                Every decision in a SHA-256 hash chain — rewrite one row and the break is caught at
                that exact entry.
              </p>
              <div className={s.bigCard}>
                <AuditLens model={M} />
              </div>
            </div>
          </section>

          <div className={s.footer}>
            {live
              ? "PRAHARÍ · live data from the PRAHARI BFF — detection, correlation, attribution, response and audit are the running system's own output."
              : "PRAHARÍ · backend offline."}
            <br />
            Graph coloring is the system&apos;s own computed anomaly score — never the ground-truth
            label. Respects reduced-motion.
          </div>
        </>
      )}
    </div>
  );
}

/* ================= nav ================= */
function Nav(props: {
  live: boolean;
  model: ConsoleModel | null;
  incidents: { id: string; score: number; status: string }[];
  onPick: (id: string) => void;
  attack: { state: string; label: string };
  onAttack: () => void;
}) {
  const { live, model, incidents, onPick, attack, onAttack } = props;
  return (
    <div className={s.navShell}>
      <nav className={s.nav}>
        <Link href="/" className={`${s.wordmark} ${s.focusable}`} title="PRAHARÍ home">
          PRAHAR<span className={s.tick}>Í<i /></span>
        </Link>
        <div className={s.navRight}>
          {incidents.length > 0 && model && (
            <select className={`${s.select} ${s.focusable}`} value={model.id} onChange={(e) => onPick(e.target.value)} aria-label="Select incident">
              {incidents.map((i) => (
                <option key={i.id} value={i.id}>
                  {i.id} · {i.score.toFixed(1)} · {i.status}
                </option>
              ))}
            </select>
          )}
          {live && (
            <button
              className={`${attack.state === "error" ? s.pillGhost + " " + s.pillErr : s.pillDark} ${s.focusable}`}
              disabled={attack.state === "running"}
              onClick={onAttack}
              title="Replay a fresh seeded intrusion through the whole live loop — window anchored to today"
            >
              {attack.state === "running" ? (
                <>
                  <span className={s.statusDot} style={{ background: "#9CA3AF", animation: "softPulse 1.2s ease-in-out infinite" }} />
                  {attack.label}
                </>
              ) : attack.state === "error" ? (
                <>⟳ {attack.label}</>
              ) : (
                <>Run fresh attack</>
              )}
            </button>
          )}
          <span className={live ? s.liveChip : s.offChip}>
            <span className={s.statusDot} style={{ background: live ? "#059669" : "#CBD5E1" }} />
            {live ? "LIVE" : "OFFLINE"}
          </span>
        </div>
      </nav>
    </div>
  );
}

/* ================= confirmation callout ================= */
function ConfirmBanner({ model: M, playDay, attack }: { model: ConsoleModel; playDay: number; attack: { state: string; label: string } }) {
  const confirm = M.beats.find((x) => x.key === "confirmed");
  const showConfirm = confirm && (playDay >= confirm.day || playDay >= M.dmax - 0.02);
  if (attack.state === "running")
    return (
      <div style={{ minHeight: 40, margin: "24px 0 4px" }}>
        <div style={{ display: "flex", alignItems: "center", gap: 11, background: "var(--indigo-bg)", borderRadius: 999, padding: "11px 20px" }}>
          <span style={{ flex: "0 0 auto", width: 8, height: 8, borderRadius: "50%", background: "var(--indigo)", animation: "softPulse 1.1s ease-in-out infinite" }} />
          <span style={{ fontSize: 13, color: "var(--indigo)", fontWeight: 600 }}>
            Running a fresh intrusion through the whole loop — {attack.label || "starting…"}
          </span>
        </div>
      </div>
    );
  return (
    <div style={{ minHeight: 40, margin: "24px 0 4px" }}>
      {showConfirm ? (
        <div style={{ display: "flex", alignItems: "center", gap: 11, background: "rgba(5,150,105,0.07)", borderRadius: 999, padding: "11px 20px", animation: "confirmPulse 0.9s ease-out" }}>
          <span style={{ flex: "0 0 auto", width: 22, height: 22, borderRadius: "50%", background: "var(--good)", color: "#fff", display: "flex", alignItems: "center", justifyContent: "center", fontSize: 12, fontWeight: 700 }}>✓</span>
          <span style={{ fontSize: 13, color: "#065F46", lineHeight: 1.45 }}>
            <b>
              Confirmed {M.hero.confirmedDate ?? ""}
              {M.hero.mttd ? ` · MTTD ${M.hero.mttd} d` : ""}
            </b>
            {" — C2 severed at confirmation"}
            {M.pathMeta.exfilDate !== "—" && <>; the {M.pathMeta.exfilDate} exfiltration <b>never completed</b></>}
            .
          </span>
        </div>
      ) : (
        <div style={{ display: "flex", alignItems: "center", gap: 11, background: "#F7F7F9", borderRadius: 999, padding: "11px 20px" }}>
          <span style={{ flex: "0 0 auto", width: 22, height: 22, borderRadius: "50%", background: "#ECECF0", color: "var(--mut)", display: "flex", alignItems: "center", justifyContent: "center", fontSize: 13 }}>⋯</span>
          <span style={{ fontSize: 13, color: "var(--mut)" }}>Correlating weak signals — awaiting confirmation…</span>
        </div>
      )}
    </div>
  );
}

const MONTHS = ["Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"];
function fmtClock(t0: number, day: number, dmax: number) {
  const d = new Date(t0 + Math.min(day, dmax) * 86400e3);
  return `${MONTHS[d.getUTCMonth()]} ${String(d.getUTCDate()).padStart(2, "0")}`;
}
function windowLabel(t0: number, dmax: number) {
  const a = new Date(t0);
  const b = new Date(t0 + dmax * 86400e3);
  return `${MONTHS[a.getUTCMonth()]} ${a.getUTCDate()} → ${MONTHS[b.getUTCMonth()]} ${b.getUTCDate()}, ${b.getUTCFullYear()}`.toUpperCase();
}
