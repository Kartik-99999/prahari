"use client";
// The analyst console, rebuilt clean: one data hook (useConsole), one pure
// model (derive.ts), presentational lenses. Generic across incidents — the
// picker lists whatever the backend ranked; nothing is scenario-hardcoded.
import Link from "next/link";
import React, { useEffect, useRef, useState } from "react";
import { briefUrl } from "@/lib/api";
import s from "./console.module.css";
import { useConsole } from "./useConsole";
import type { ConsoleModel } from "./derive";
import { GraphLens } from "./GraphLens";
import { AttckLens, EventsLens, PathLens, StoryLens } from "./lenses";
import { AuditLens, ResponseLens } from "./ops";

const LENSES = [
  { k: "story", label: "Story", sub: "kill-chain spine" },
  { k: "graph", label: "Graph", sub: "provenance" },
  { k: "attack", label: "ATT&CK", sub: "technique matrix" },
  { k: "path", label: "Path", sub: "lateral walk" },
  { k: "events", label: "Events", sub: "ranked evidence" },
  { k: "response", label: "Response", sub: "SOAR queue" },
  { k: "audit", label: "Audit", sub: "hash chain" },
] as const;
type LensKey = (typeof LENSES)[number]["k"];

export type Sel = { kind: "edge" | "node"; id: string } | null;

const RATE = 2.4; // replay days per second at 1×

export default function ConsoleApp() {
  // deep links: ?incident=INC-002&lens=graph&day=2.9
  const q = typeof window !== "undefined" ? new URLSearchParams(window.location.search) : null;
  const qLens = q?.get("lens") as LensKey | null;
  const { st, attack, deciding, selectIncident, decide, runAttack } = useConsole(
    q?.get("incident") ?? null,
  );
  const [lens, setLens] = useState<LensKey>(
    qLens && LENSES.some((l) => l.k === qLens) ? qLens : "story",
  );
  const [sel, setSel] = useState<Sel>(null);
  const [overlayGT, setOverlayGT] = useState(false);

  // ---- replay clock -------------------------------------------------------
  const [playDay, setPlayDay] = useState(0);
  const [playing, setPlaying] = useState(false);
  const [speed, setSpeed] = useState(1);
  const wantDay = useRef<number | null>(q?.get("day") ? parseFloat(q.get("day")!) : null);
  const raf = useRef(0);
  const last = useRef<number | null>(null);
  const M = st.model;
  const dmax = M?.dmax ?? 20;

  useEffect(() => {
    if (!M) return;
    // when a model lands (first load / re-select / fresh attack) park the
    // playhead: deep-linked day if given, else the end of the window
    setPlayDay(wantDay.current != null ? Math.min(dmax, Math.max(0, wantDay.current)) : dmax);
    wantDay.current = null;
    setSel(null);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [M?.id, M?.t0]);

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

  const openEdge = (id: string) => {
    setLens("graph");
    setSel({ kind: "edge", id });
  };

  // ---- offline ---------------------------------------------------------------
  if (st.status === "offline")
    return (
      <div className={s.page}>
        <div className={s.wrap}>
          <Bar
            live={false}
            model={null}
            incidents={[]}
            onPick={() => {}}
            attack={attack}
            onAttack={() => {}}
          />
          <div className={`${s.card} ${s.offline}`}>
            <div className={s.kicker}>◌ backend offline</div>
            <h1>The sentinel is not reporting.</h1>
            <p>
              This console renders the live system only — no fixtures, no pretending. Start the
              stack and refresh: <code>make up && make api</code>, then <code>make attack</code> for
              a fresh intrusion, or open the <Link href="/">landing page</Link> meanwhile.
            </p>
          </div>
          <FootNote live={false} />
        </div>
      </div>
    );

  return (
    <div className={s.page}>
      <div className={s.wrap}>
        <Bar
          live={st.status === "live"}
          model={M}
          incidents={st.incidents}
          onPick={selectIncident}
          attack={attack}
          onAttack={runAttack}
        />
        {st.status === "loading" || !M ? (
          <div className={`${s.card} ${s.offline}`}>
            <div className={s.kicker}>· connecting</div>
            <h1>Waking the sentinel…</h1>
          </div>
        ) : (
          <>
            <Verdict model={M} />
            {M.fusion && <Correlator f={M.fusion} />}
            <Replay
              model={M}
              playDay={playDay}
              playing={playing}
              speed={speed}
              onScrub={(d) => {
                setPlaying(false);
                setPlayDay(d);
              }}
              onPlay={togglePlay}
              onSpeed={setSpeed}
            />
            <section className={s.card} style={{ overflow: "hidden" }}>
              <div style={{ display: "flex", alignItems: "flex-end", justifyContent: "space-between", gap: 16, padding: "22px 26px 0", flexWrap: "wrap" }}>
                <div>
                  <div className={s.kicker} style={{ display: "flex", alignItems: "center", gap: 7 }}>
                    <span style={{ color: "#B9977A" }}>★</span> The instrument
                  </div>
                  <div className={s.serifH} style={{ fontSize: 24, marginTop: 6 }}>
                    Provenance graph &amp; ATT&amp;CK kill chain
                  </div>
                  <div style={{ fontSize: 12.5, color: "var(--mut)", marginTop: 3 }}>
                    One incident — every lens is driven by the replay clock above.
                  </div>
                </div>
                <div className={s.tabs}>
                  {LENSES.map((l) => (
                    <button
                      key={l.k}
                      className={`${s.tab} ${lens === l.k ? s.tabOn : ""}`}
                      onClick={() => setLens(l.k)}
                    >
                      <b>{l.label}</b>
                      <i>{l.sub}</i>
                    </button>
                  ))}
                </div>
              </div>
              <div style={{ height: 1, background: "var(--line2)", margin: "18px 0 0" }} />
              <div style={{ padding: "8px 26px 26px" }}>
                {lens === "story" && <StoryLens model={M} playDay={playDay} onTech={() => setLens("attack")} />}
                {lens === "graph" && (
                  <GraphLens
                    model={M}
                    playDay={playDay}
                    sel={sel}
                    setSel={setSel}
                    overlayGT={overlayGT}
                    setOverlayGT={setOverlayGT}
                  />
                )}
                {lens === "attack" && <AttckLens model={M} playDay={playDay} />}
                {lens === "path" && <PathLens model={M} />}
                {lens === "events" && <EventsLens model={M} onOpen={openEdge} />}
                {lens === "response" && (
                  <ResponseLens model={M} live={st.status === "live"} deciding={deciding} onDecide={decide} />
                )}
                {lens === "audit" && <AuditLens model={M} />}
              </div>
            </section>
            <FootNote live />
          </>
        )}
      </div>
    </div>
  );
}

/* ================= header bar ================= */
function Bar(props: {
  live: boolean;
  model: ConsoleModel | null;
  incidents: { id: string; score: number; status: string }[];
  onPick: (id: string) => void;
  attack: { state: string; label: string };
  onAttack: () => void;
}) {
  const { live, model, incidents, onPick, attack, onAttack } = props;
  return (
    <header className={s.bar}>
      <div className={s.brand}>
        <Link href="/" className={`${s.wordmark} ${s.focusable}`} title="PRAHARÍ home">
          PRAHAR<span className={s.tick}>Í<i /></span>
        </Link>
        <span className={s.tagline}>AI cyber-resilience console</span>
      </div>
      <div className={s.chips}>
        {live && (
          <button
            className={`${s.attackBtn} ${attack.state === "error" ? s.attackErr : ""}`}
            disabled={attack.state === "running"}
            onClick={onAttack}
            title="Replay a fresh seeded intrusion through the whole live loop — window anchored to today"
          >
            {attack.state === "running" ? (
              <>
                <span className={s.dot} style={{ background: "#6B7280", animation: "softPulse 1.2s ease-in-out infinite" }} />
                {attack.label}
              </>
            ) : attack.state === "error" ? (
              <>⟳ {attack.label}</>
            ) : (
              <>⟳ run fresh attack</>
            )}
          </button>
        )}
        {incidents.length > 0 && model && (
          <select
            className={s.select}
            value={model.id}
            onChange={(e) => onPick(e.target.value)}
            aria-label="Select incident"
          >
            {incidents.map((i) => (
              <option key={i.id} value={i.id}>
                {i.id} · {i.score.toFixed(1)} · {i.status}
              </option>
            ))}
          </select>
        )}
        <span className={`${s.chip} ${live ? s.chipLive : s.chipOff}`}>
          <span className={s.dot} style={{ background: live ? "#0D9488" : "#CBD5E1", boxShadow: live ? "0 0 0 3px rgba(13,148,136,0.15)" : "none" }} />
          {live ? "LIVE · BFF" : "BFF OFFLINE"}
        </span>
        {model && (
          <span className={`${s.chip} ${model.auditMeta.ok ? s.chipGood : s.chipBad}`}>
            <span className={s.dot} style={{ background: model.auditMeta.ok ? "#059669" : "#DC2626" }} />
            {model.auditMeta.ok ? "AUDIT VERIFIED" : "AUDIT BROKEN"} · {model.auditMeta.entries}
          </span>
        )}
      </div>
    </header>
  );
}

/* ================= verdict ================= */
function Verdict({ model: M }: { model: ConsoleModel }) {
  const h = M.hero;
  return (
    <section className={s.card} style={{ padding: "30px 34px 24px" }}>
      <div style={{ display: "flex", gap: 34, alignItems: "flex-start", flexWrap: "wrap" }}>
        <div style={{ flex: "1 1 560px", minWidth: 340 }}>
          <div className={s.kicker} style={{ marginBottom: 12 }}>
            The verdict · {M.id}
          </div>
          <h1 className={s.serifH} style={{ margin: 0, fontSize: 28, lineHeight: 1.3, fontWeight: 480, maxWidth: "36ch", textWrap: "balance" }}>
            {h.mttd ? (
              <>
                An intrusion campaign was detected in{" "}
                <span style={{ color: "var(--indigo)" }}>{h.mttd} days</span>
                {h.status === "contained" && (
                  <>
                    , <span style={{ color: "var(--good)", fontWeight: 700 }}>contained</span> in
                    under a second
                  </>
                )}
                {h.prevented && (
                  <>
                    , and the planned exfiltration was{" "}
                    <span style={{ color: "var(--good)", fontWeight: 700 }}>prevented</span>
                  </>
                )}
                .
              </>
            ) : (
              <>
                {M.id} — <span style={{ color: "var(--amber)" }}>{h.status}</span>: {h.nEvents}{" "}
                correlated events under watch.
              </>
            )}
          </h1>
          <p style={{ margin: "10px 0 0", fontSize: 13, lineHeight: 1.6, color: "var(--mut)", maxWidth: "66ch" }}>
            {h.confirmedDate ? (
              <>
                Confirmed <span className={s.mono} style={{ color: "var(--ink2)" }}>{h.confirmedDate}</span>
                {h.dwell && (
                  <>
                    {" "}
                    — <span className={s.mono} style={{ color: "var(--ink2)" }}>{h.dwell} days</span> before the
                    planned exfiltration
                  </>
                )}
                {h.exfilMD && (
                  <>
                    ; the {h.exfilMD} exfiltration{" "}
                    <span style={{ color: "var(--good)", fontWeight: 600 }}>never completed</span>
                  </>
                )}
                . Every step below is provable.
              </>
            ) : (
              <>Awaiting confirmation — the correlator is still assembling this campaign. Every claim below drills to raw evidence.</>
            )}
          </p>
          <div style={{ display: "flex", gap: 7, flexWrap: "wrap", marginTop: 14 }}>
            {[
              `${h.nEvents} correlated events`,
              `${h.spanDays}-day window`,
              h.hostsText ? `hosts ${h.hostsText}` : null,
              `${h.usersCount} identities`,
            ]
              .filter(Boolean)
              .map((c, i) => (
                <span key={i} className={s.mono} style={{ fontSize: 10, color: "#64748B", background: "#F6F8FA", border: "1px solid var(--line2)", borderRadius: 6, padding: "3px 9px", letterSpacing: "0.02em" }}>
                  {c}
                </span>
              ))}
          </div>
        </div>
        <div style={{ flex: "0 0 auto", display: "flex", flexDirection: "column", alignItems: "flex-end", gap: 2, padding: "2px 4px 0" }}>
          <div className={s.kicker} style={{ fontSize: 10.5 }}>Incident score</div>
          <div className={s.gold} style={{ fontSize: 44, lineHeight: 1 }}>{h.score}</div>
          {h.ratio && (
            <div style={{ fontSize: 11.5, color: "var(--mut)", marginTop: 2 }}>
              <span style={{ color: "var(--bad)", fontWeight: 600 }}>{h.ratio}</span> the next incident
            </div>
          )}
          <a
            href={briefUrl(M.id)}
            target="_blank"
            rel="noreferrer"
            className={`${s.mono} ${s.focusable}`}
            style={{ display: "inline-flex", alignItems: "center", gap: 6, marginTop: 10, fontSize: 11, fontWeight: 600, color: "var(--indigo)", borderRadius: 999, padding: "6px 13px", background: "var(--indigo-bg)", textDecoration: "none" }}
          >
            analyst brief ↗
          </a>
        </div>
      </div>
      <div style={{ display: "flex", flexWrap: "wrap", marginTop: 20, borderTop: "1px solid var(--line2)", paddingTop: 16 }}>
        {M.metrics.map((m, i) => (
          <div key={m.key} style={{ flex: "1 1 0", minWidth: 118, padding: i ? "0 18px" : "0 18px 0 2px", borderLeft: i ? "1px solid var(--line2)" : "none", display: "flex", flexDirection: "column", gap: 2 }}>
            <div className={s.mono} style={{ fontSize: 19, fontWeight: 700, letterSpacing: "-0.02em", lineHeight: 1.1, color: m.color }}>
              {m.display}
            </div>
            <div style={{ fontSize: 10.5, fontWeight: 600, color: "var(--ink2)", lineHeight: 1.25 }}>{m.label}</div>
            <div style={{ fontSize: 9.5, color: "var(--faint)", lineHeight: 1.3 }}>{m.sub}</div>
          </div>
        ))}
      </div>
    </section>
  );
}

/* ================= correlator line ================= */
function Correlator({ f }: { f: NonNullable<ConsoleModel["fusion"]> }) {
  return (
    <div
      title={
        f.insider
          ? "External-anchor fraction fell below the threshold — the correlator added the user pivot on its own."
          : "External-anchor fraction crossed the decision threshold — the system chose this mode without a human."
      }
      style={{ display: "flex", alignItems: "center", gap: 14, flexWrap: "wrap", padding: "0 10px 16px", marginBottom: 2 }}
    >
      <span className={s.mono} style={{ fontSize: 10, letterSpacing: "0.12em", color: "var(--faint)", fontWeight: 600 }}>CORRELATOR</span>
      <span style={{ display: "flex", alignItems: "center", gap: 7 }}>
        <span className={s.mono} style={{ fontSize: 12.5, fontWeight: 700, color: "var(--indigo)" }}>{f.label}</span>
        {f.auto && (
          <span style={{ fontSize: 9, fontWeight: 700, letterSpacing: "0.06em", color: "var(--indigo)", background: "var(--indigo-bg)", borderRadius: 999, padding: "2px 8px" }}>AUTO</span>
        )}
      </span>
      <span style={{ display: "inline-flex", alignItems: "center", gap: 8 }}>
        <span style={{ position: "relative", width: 130, height: 5, background: "#EEF2F6", borderRadius: 4, display: "inline-block" }}>
          <span style={{ position: "absolute", left: 0, top: 0, bottom: 0, background: "var(--indigo2)", borderRadius: 4, width: `${f.fracPct}%` }} />
          <span style={{ position: "absolute", top: -3, bottom: -3, width: 1.5, background: "var(--faint)", left: `${f.thrPct}%` }} />
        </span>
        <span className={s.mono} style={{ fontSize: 11, color: "var(--mut)" }}>
          anchor <b style={{ color: "var(--indigo)" }}>{f.fracText}</b> {f.insider ? "<" : "≥"} {f.thrText}
        </span>
      </span>
      <span style={{ display: "flex", alignItems: "center", gap: 6 }}>
        <span style={{ fontSize: 10, letterSpacing: "0.08em", textTransform: "uppercase", color: "var(--faint)", fontWeight: 600 }}>pivots</span>
        <span className={s.mono} style={{ fontSize: 10.5, color: "#64748B" }}>
          {(f.insider ? [...f.pivots, "user"] : f.pivots).join(" · ")}
        </span>
      </span>
    </div>
  );
}

/* ================= replay ================= */
function Replay(props: {
  model: ConsoleModel;
  playDay: number;
  playing: boolean;
  speed: number;
  onScrub: (d: number) => void;
  onPlay: () => void;
  onSpeed: (v: number) => void;
}) {
  const { model: M, playDay, playing, speed, onScrub, onPlay, onSpeed } = props;
  const dmax = M.dmax;
  const pct = `${(playDay / dmax) * 100}%`;
  const clock = new Date(M.t0 + Math.min(playDay, dmax) * 86400e3);
  const MONTHS = ["Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"];
  const curDate = `${MONTHS[clock.getUTCMonth()]} ${String(clock.getUTCDate()).padStart(2, "0")}`;
  const a = new Date(M.t0);
  const b = new Date(M.t0 + dmax * 86400e3);
  const windowLabel = `${MONTHS[a.getUTCMonth()]} ${a.getUTCDate()} → ${MONTHS[b.getUTCMonth()]} ${b.getUTCDate()}, ${b.getUTCFullYear()}`.toUpperCase();
  const confirm = M.beats.find((x) => x.key === "confirmed");
  const showConfirm = confirm && (playDay >= confirm.day || playDay >= dmax - 0.02);
  const atEnd = playDay >= dmax - 0.02;
  return (
    <section className={s.card} style={{ padding: "20px 24px 22px" }}>
      <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between", gap: 16, marginBottom: 16, flexWrap: "wrap" }}>
        <div style={{ display: "flex", alignItems: "center", gap: 12 }}>
          <button
            className={`${s.pillBtn} ${s.focusable}`}
            onClick={onPlay}
            style={{ display: "inline-flex", alignItems: "center", gap: 7, padding: "10px 20px", fontSize: 13, background: playing ? "#F3F4F6" : "var(--navy)", color: playing ? "var(--navy)" : "#fff", boxShadow: playing ? "none" : "0 4px 14px -4px rgba(17,24,39,0.4)" }}
          >
            {playing ? "❚❚ Pause" : atEnd ? "▶ Replay attack" : "▶ Play"}
          </button>
          <div style={{ display: "flex", background: "#F3F4F6", borderRadius: 999, padding: 3 }}>
            {[1, 4, 12].map((v) => (
              <button
                key={v}
                className={`${s.pillBtn} ${s.focusable} ${s.mono}`}
                onClick={() => onSpeed(v)}
                style={{ padding: "5px 13px", fontSize: 12, fontWeight: 700, background: speed === v ? "var(--navy)" : "transparent", color: speed === v ? "#fff" : "var(--ink2)" }}
              >
                {v}×
              </button>
            ))}
          </div>
          <div className={s.mono} style={{ fontSize: 12, color: "var(--ink2)", whiteSpace: "nowrap" }}>
            clock <b style={{ color: "var(--ink)" }}>{curDate}</b> ·{" "}
            <span style={{ color: "var(--mut)" }}>day {playDay.toFixed(1)}</span>
          </div>
        </div>
        <div className={s.mono} style={{ fontSize: 10.5, letterSpacing: "0.08em", color: "var(--mut)" }}>
          MASTER CLOCK · {windowLabel}
        </div>
      </div>
      <div style={{ minHeight: 36, margin: "2px 44px 16px" }}>
        {showConfirm ? (
          <div style={{ display: "flex", alignItems: "center", gap: 11, background: "rgba(5,150,105,0.08)", border: "1px solid rgba(5,150,105,0.28)", borderRadius: 11, padding: "9px 14px", animation: "confirmPulse 0.9s ease-out" }}>
            <span style={{ flex: "0 0 auto", width: 22, height: 22, borderRadius: "50%", background: "var(--good)", color: "#fff", display: "flex", alignItems: "center", justifyContent: "center", fontSize: 12, fontWeight: 700 }}>✓</span>
            <span style={{ fontSize: 12.5, color: "#065F46", lineHeight: 1.45 }}>
              <b>
                Confirmed {M.hero.confirmedDate ?? ""}
                {M.hero.mttd ? ` · MTTD ${M.hero.mttd} d` : ""}
              </b>{" "}
              — C2 channel severed at confirmation
              {M.pathMeta.exfilDate !== "—" && (
                <>
                  , so the exfiltration on {M.pathMeta.exfilDate} <b>never completed</b>
                </>
              )}
              .
            </span>
          </div>
        ) : (
          <div style={{ display: "flex", alignItems: "center", gap: 11, background: "#F8FAFC", border: "1px dashed #D8E0E8", borderRadius: 11, padding: "9px 14px" }}>
            <span style={{ flex: "0 0 auto", width: 22, height: 22, borderRadius: "50%", background: "#EEF2F6", color: "var(--mut)", display: "flex", alignItems: "center", justifyContent: "center", fontSize: 13 }}>⋯</span>
            <span style={{ fontSize: 12.5, color: "var(--mut)" }}>Correlating weak signals — awaiting confirmation…</span>
          </div>
        )}
      </div>
      <div style={{ position: "relative", height: 58, margin: "0 44px" }}>
        <div style={{ position: "absolute", left: 0, right: 0, top: 20, height: 6, background: "#EEF2F6", borderRadius: 4 }} />
        <div style={{ position: "absolute", left: 0, top: 20, height: 6, background: "linear-gradient(90deg,var(--indigo2),var(--indigo))", borderRadius: 4, width: pct }} />
        {M.beats.map((bt, i) => {
          const lit = atEnd || playDay >= bt.day;
          const dc = lit ? (bt.key === "confirmed" ? "var(--good)" : bt.key === "prevented" ? "var(--bad)" : "var(--indigo2)") : "#CBD5E1";
          return (
            <div key={i} style={{ position: "absolute", top: 0, transform: "translateX(-50%)", display: "flex", flexDirection: "column", alignItems: "center", left: `${(bt.day / dmax) * 100}%` }}>
              <div style={{ width: bt.key ? 13 : 10, height: bt.key ? 13 : 10, borderRadius: "50%", background: dc, border: "2px solid #fff", boxShadow: `0 0 0 1px ${lit ? dc : "var(--line)"}`, marginTop: bt.key ? 1 : 2 }} />
              <div style={{ fontSize: 9.5, fontWeight: bt.key ? 700 : 600, color: lit ? (bt.key === "confirmed" ? "var(--good-deep)" : bt.key === "prevented" ? "var(--bad-deep)" : "var(--ink)") : "var(--mut)", marginTop: 7, whiteSpace: "nowrap" }}>
                {bt.label}
              </div>
              <div className={s.mono} style={{ fontSize: 9, color: "var(--mut)", marginTop: 1 }}>{bt.date}</div>
            </div>
          );
        })}
        <div style={{ position: "absolute", top: 11, transform: "translateX(-50%)", pointerEvents: "none", left: pct }}>
          <div style={{ width: 16, height: 16, borderRadius: "50%", background: "var(--navy)", border: "3px solid #fff", boxShadow: "0 2px 6px rgba(16,24,40,0.28)" }} />
        </div>
        <input
          type="range"
          min={0}
          max={dmax}
          step={0.02}
          value={playDay}
          onChange={(e) => onScrub(parseFloat(e.target.value))}
          aria-label="Replay timeline"
          className="rc-range"
          style={{ position: "absolute", left: -4, right: -4, top: 12, width: "calc(100% + 8px)", height: 20, margin: 0 }}
        />
      </div>
    </section>
  );
}

function FootNote({ live }: { live: boolean }) {
  return (
    <div className={s.footNote}>
      {live
        ? "PRAHARÍ · live data from the PRAHARI BFF — detection, correlation, attribution, response and audit are the running system's own output."
        : "PRAHARÍ · the backend is offline — nothing is rendered from fixtures; start the stack to see the live system."}
      <br />
      Graph coloring is the system&apos;s own computed anomaly score — never the ground-truth label. Respects reduced-motion.
    </div>
  );
}
