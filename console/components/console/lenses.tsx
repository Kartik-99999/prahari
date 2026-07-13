"use client";
// Presentational lenses: Story, ATT&CK, Path, Events. Pure render over the
// derived model; the replay clock and selection live in ConsoleApp.
import React, { useState } from "react";
import s from "./console.module.css";
import { heat, type ConsoleModel } from "./derive";

/* ================= Story — the one unified timeline ================= */
export function StoryLens({
  model: M,
  playDay,
  onScrub,
  onTech,
}: {
  model: ConsoleModel;
  playDay: number;
  onScrub?: (d: number) => void;
  onTech: () => void;
}) {
  const atEnd = playDay >= M.dmax - 0.02;
  if (!M.stations.length)
    return <Empty note="No kill chain attributed for this incident yet — run attribution, or inspect the raw evidence in the Events lens." />;

  // Stations sit at even visual slots (reads clean); the playhead maps real
  // time onto those slots by piecewise interpolation, so one line carries both
  // "what happened" and "when" — no second rail needed.
  const n = M.stations.length;
  const pts: { d: number; x: number }[] = [
    { d: 0, x: 0 },
    ...M.stations.map((st, i) => ({ d: st.day, x: (i + 0.5) / n })),
    { d: M.dmax, x: 1 },
  ];
  for (let i = 1; i < pts.length; i++) if (pts[i].d < pts[i - 1].d) pts[i].d = pts[i - 1].d;
  const dayToX = (day: number) => {
    const d = Math.max(0, Math.min(M.dmax, day));
    for (let i = 1; i < pts.length; i++)
      if (d <= pts[i].d) {
        const span = pts[i].d - pts[i - 1].d;
        const f = span <= 0 ? 0 : (d - pts[i - 1].d) / span;
        return pts[i - 1].x + f * (pts[i].x - pts[i - 1].x);
      }
    return 1;
  };
  const xToDay = (x: number) => {
    const xc = Math.max(0, Math.min(1, x));
    for (let i = 1; i < pts.length; i++)
      if (xc <= pts[i].x) {
        const span = pts[i].x - pts[i - 1].x;
        const f = span <= 0 ? 0 : (xc - pts[i - 1].x) / span;
        return pts[i - 1].d + f * (pts[i].d - pts[i - 1].d);
      }
    return M.dmax;
  };
  const headX = dayToX(playDay) * 100;

  return (
    <div style={{ padding: "18px 6px 8px" }}>
      <div style={{ position: "relative", height: 168, margin: "0 10px" }}>
        {/* the single spine line + real-time fill */}
        <div style={{ position: "absolute", left: 0, right: 0, top: 15, height: 5, background: "#EEF1F5", borderRadius: 4 }} />
        <div style={{ position: "absolute", left: 0, top: 15, height: 5, background: "linear-gradient(90deg,#E8A34A,#DC2626)", borderRadius: 4, width: `${headX}%` }} />
        {/* stations at even slots */}
        {M.stations.map((st, i) => {
          const x = ((i + 0.5) / n) * 100;
          const lit = atEnd || playDay >= st.day;
          const hc = st.verdict === "confirmed · contained" ? "#059669" : st.prevented ? "#DC2626" : heat(st.score).fill;
          return (
            <div key={st.id} style={{ position: "absolute", left: `${x}%`, top: 8, transform: "translateX(-50%)", width: `${(100 / n) * 0.94}%`, display: "flex", flexDirection: "column", alignItems: "center", textAlign: "center", opacity: lit ? 1 : 0.62, transition: "opacity .35s" }}>
              <div style={{ width: 19, height: 19, borderRadius: "50%", background: lit ? hc : "#fff", border: `3px solid ${lit ? hc : "#D8E0E8"}`, boxShadow: lit ? `0 0 0 4px ${hc === "#059669" ? "rgba(5,150,105,0.14)" : hc === "#DC2626" ? "rgba(220,38,38,0.12)" : "rgba(217,119,6,0.12)"}` : "none", transition: "all .35s ease" }} />
              <div className={s.mono} style={{ fontSize: 12.5, fontWeight: 700, marginTop: 12, color: lit ? "var(--ink)" : "var(--mut)", transition: "color .35s" }}>{st.id}</div>
              <div style={{ fontSize: 10.5, fontWeight: 600, marginTop: 3, lineHeight: 1.25, color: lit ? "var(--ink)" : "var(--mut)", textDecoration: st.prevented ? "line-through" : "none", textDecorationColor: "#DC2626", textDecorationThickness: 1.5 }}>
                {st.name}
              </div>
              <div className={s.mono} style={{ fontSize: 9, color: "var(--mut)", marginTop: 4 }}>{st.date}</div>
              {st.verdict && lit && (
                <div style={{ marginTop: 7, fontSize: 9, fontWeight: 700, letterSpacing: "0.03em", color: st.prevented ? "#991B1B" : "#065F46", background: st.prevented ? "rgba(220,38,38,0.07)" : "rgba(5,150,105,0.1)", border: `1px solid ${st.prevented ? "rgba(220,38,38,0.28)" : "rgba(5,150,105,0.3)"}`, borderRadius: 999, padding: "3px 9px", whiteSpace: "nowrap" }}>
                  {st.prevented ? "✕ prevented" : "✓ contained"}
                </div>
              )}
            </div>
          );
        })}
        {/* playhead + scrubber on the same line */}
        <div style={{ position: "absolute", top: 8, left: `${headX}%`, transform: "translateX(-50%)", pointerEvents: "none" }}>
          <div style={{ width: 18, height: 18, borderRadius: "50%", background: "var(--navy)", border: "3px solid #fff", boxShadow: "0 2px 8px rgba(16,24,40,0.3)" }} />
        </div>
        {onScrub && (
          <input
            type="range"
            min={0}
            max={1}
            step={0.001}
            value={dayToX(playDay)}
            onChange={(e) => onScrub(xToDay(parseFloat(e.target.value)))}
            aria-label="Replay timeline"
            className="rc-range"
            style={{ position: "absolute", left: -4, right: -4, top: 7, width: "calc(100% + 8px)", height: 20, margin: 0 }}
          />
        )}
      </div>
      <div style={{ fontSize: 11.5, color: "var(--mut)", textAlign: "center", marginTop: 6 }}>
        Drag anywhere on the spine — each station ignites the moment the playhead crosses its first-observed time.
      </div>
      <div style={{ marginTop: 22, borderTop: "1px solid var(--line)", paddingTop: 6 }}>
        {M.stations.map((st) => (
          <button key={st.id} className={`${s.rowBtn}`} onClick={onTech} title="open in the ATT&CK lens" style={{ display: "flex", alignItems: "center", gap: 13, padding: "11px 10px" }}>
            <span className={s.mono} style={{ fontSize: 11, fontWeight: 700, color: "var(--faint)", flex: "0 0 16px" }}>{st.n}</span>
            <span style={{ width: 9, height: 9, borderRadius: "50%", flex: "0 0 auto", background: st.prevented ? "#DC2626" : st.verdict ? "#059669" : heat(st.score).fill }} />
            <span className={s.mono} style={{ flex: "0 0 60px", fontSize: 12, fontWeight: 700, color: "var(--ink)" }}>{st.id}</span>
            <span style={{ flex: "1 1 auto", minWidth: 0, fontSize: 12.5, color: "var(--ink2)", lineHeight: 1.5 }}>
              <span style={{ fontWeight: 600, color: "var(--ink)", textDecoration: st.prevented ? "line-through" : "none", textDecorationColor: "#DC2626" }}>{st.name}</span>
              {st.evidence ? <span style={{ color: "#64748B" }}> — {st.evidence}</span> : null}
            </span>
            <span className={s.mono} style={{ flex: "0 0 auto", fontSize: 10.5, color: "var(--mut)" }}>
              {st.host} · {st.date}
            </span>
            <span className={s.scoreChip} style={{ flex: "0 0 auto", background: heat(st.score).fill }}>{st.score.toFixed(2)}</span>
          </button>
        ))}
      </div>
    </div>
  );
}

/* ================= ATT&CK ================= */
export function AttckLens({ model: M, playDay }: { model: ConsoleModel; playDay: number }) {
  const atEnd = playDay >= M.dmax - 0.02;
  const dayFor = (tid: string) => M.stations.find((x) => x.id === tid)?.day ?? 0;
  const cols = M.attck.filter((c) => c.cells.length > 0);
  if (!cols.length) return <Empty note="No techniques attributed yet for this incident." />;
  return (
    <div style={{ paddingTop: 18 }}>
      <div style={{ display: "flex", gap: 18, alignItems: "center", marginBottom: 14, fontSize: 11, color: "var(--ink2)", flexWrap: "wrap" }}>
        <span style={{ display: "flex", alignItems: "center", gap: 6 }}><span style={{ width: 11, height: 11, borderRadius: 3, background: "#0D9488" }} /> observed</span>
        <span style={{ display: "flex", alignItems: "center", gap: 6 }}><span style={{ width: 11, height: 11, borderRadius: 3, background: "#059669" }} /> confirmed · contained</span>
        <span style={{ display: "flex", alignItems: "center", gap: 6 }}><span style={{ width: 11, height: 11, borderRadius: 3, border: "1.5px dashed #D97706", animation: "softPulse 2s ease-in-out infinite" }} /> predicted next move</span>
        <span className={s.mono} style={{ marginLeft: "auto", fontSize: 10.5, color: "var(--mut)" }}>
          {M.stations.length} observed · {M.predicted.length} predicted · {cols.length} tactics
        </span>
      </div>
      <div style={{ display: "grid", gridTemplateColumns: `repeat(${cols.length}, 1fr)`, gap: 10, alignItems: "start" }}>
        {cols.map((c) => (
          <div key={c.col}>
            <div style={{ fontSize: 9.5, fontWeight: 700, letterSpacing: "0.06em", textTransform: "uppercase", color: "var(--mut)", padding: "0 2px 8px", lineHeight: 1.3, minHeight: 30 }}>{c.col}</div>
            <div style={{ display: "flex", flexDirection: "column", gap: 7 }}>
              {c.cells.map((cell, i) => {
                const lit = cell.k === "pred" || atEnd || playDay >= dayFor(cell.tid);
                const bg = cell.k === "con" ? "#059669" : cell.k === "obs" ? "#0D9488" : "transparent";
                return (
                  <div key={i} style={{ borderRadius: 10, padding: "9px 10px", background: cell.k === "pred" ? "rgba(217,119,6,0.05)" : lit ? bg : "#F1F5F9", border: cell.k === "pred" ? "1.5px dashed #D97706" : "1px solid transparent", opacity: lit ? 1 : 0.55, transition: "all .3s", animation: cell.k === "pred" ? "softPulse 2.4s ease-in-out infinite" : undefined }}>
                    <div className={s.mono} style={{ fontSize: 11, fontWeight: 700, color: cell.k === "pred" ? "#B45309" : lit ? "#fff" : "var(--mut)" }}>{cell.tid}</div>
                    <div style={{ fontSize: 9.5, marginTop: 2, lineHeight: 1.25, color: cell.k === "pred" ? "#92400E" : lit ? "rgba(255,255,255,0.85)" : "var(--mut)" }}>{cell.name}</div>
                  </div>
                );
              })}
            </div>
          </div>
        ))}
      </div>
    </div>
  );
}

/* ================= Path ================= */
export function PathLens({ model: M }: { model: ConsoleModel }) {
  if (!M.pathMeta.present || !M.hops.length)
    return <Empty note="No confirmed lateral movement in this incident — the walk to a crown jewel never happened (or never needed to)." />;
  return (
    <div style={{ paddingTop: 22, display: "flex", flexDirection: "column", gap: 10, maxWidth: 860, margin: "0 auto" }}>
      <div style={{ display: "flex", alignItems: "center", gap: 12, background: "#FBFCFD", border: "1px solid var(--line)", borderRadius: 13, padding: "13px 16px" }}>
        <span style={{ width: 30, height: 30, borderRadius: 9, background: "#101828", color: "#fff", display: "flex", alignItems: "center", justifyContent: "center", fontSize: 13, fontWeight: 700 }}>◈</span>
        <div>
          <div style={{ fontSize: 13, fontWeight: 700 }}>{M.pathMeta.start} — patient zero</div>
          <div style={{ fontSize: 11.5, color: "var(--mut)", marginTop: 2 }}>{M.pathMeta.startDetail}</div>
        </div>
      </div>
      {M.hops.map((h, i) => (
        <div key={i} style={{ display: "flex", alignItems: "stretch", gap: 12, marginLeft: 15 }}>
          <div style={{ display: "flex", flexDirection: "column", alignItems: "center" }}>
            <div style={{ width: 2, flex: 1, background: "linear-gradient(180deg,#E11D48,#DC2626)" }} />
            <div style={{ width: 10, height: 10, borderRadius: "50%", background: "#DC2626", margin: "2px 0" }} />
            <div style={{ width: 2, flex: 1, background: "linear-gradient(180deg,#DC2626,#E11D48)" }} />
          </div>
          <div style={{ flex: 1, background: "#fff", border: "1px solid var(--line)", borderRadius: 13, padding: "12px 16px", display: "flex", alignItems: "center", gap: 16, flexWrap: "wrap" }}>
            <span className={s.mono} style={{ fontSize: 13, fontWeight: 700 }}>
              {h.from} <span style={{ color: "#DC2626" }}>→</span> {h.to}
            </span>
            <span className={s.mono} style={{ fontSize: 10.5, color: "var(--mut)" }}>
              {h.tech} · {h.date} · credential: <b style={{ color: "var(--ink2)" }}>{h.cred}</b>
            </span>
            <span style={{ flexBasis: "100%", fontSize: 11.5, color: "#64748B", lineHeight: 1.5 }}>{h.detail}</span>
          </div>
        </div>
      ))}
      <div style={{ display: "flex", alignItems: "center", gap: 12, background: "rgba(220,38,38,0.04)", border: "1px solid rgba(220,38,38,0.22)", borderRadius: 13, padding: "13px 16px" }}>
        <span style={{ width: 30, height: 30, borderRadius: 9, background: "#DC2626", color: "#fff", display: "flex", alignItems: "center", justifyContent: "center", fontSize: 14, fontWeight: 700 }}>✕</span>
        <div>
          <div style={{ fontSize: 13, fontWeight: 700 }}>
            EXFIL · <span className={s.mono}>{M.pathMeta.exfilIp}</span>{" "}
            <span className={s.mono} style={{ fontSize: 11, color: "#DC2626" }}>· {M.pathMeta.exfilDate}</span>
          </div>
          <div style={{ fontSize: 11.5, color: "var(--mut)", marginTop: 2 }}>{M.pathMeta.exfilDetail}</div>
        </div>
      </div>
    </div>
  );
}

/* ================= Events ================= */
export function EventsLens({ model: M, onOpen }: { model: ConsoleModel; onOpen: (id: string) => void }) {
  const [filter, setFilter] = useState<"all" | "hot" | "beats">("all");
  const verd = (e: ConsoleModel["edges"][number]) =>
    e.prevented
      ? { t: "PREVENTED", c: "#059669", bg: "rgba(5,150,105,0.10)" }
      : e.confirmed
        ? { t: "CONFIRMED", c: "#059669", bg: "rgba(5,150,105,0.10)" }
        : e.score >= 0.85
          ? { t: "CRITICAL", c: "#B91C1C", bg: "rgba(220,38,38,0.07)" }
          : { t: "FLAGGED", c: "#B45309", bg: "rgba(217,119,6,0.08)" };
  const ranked = M.edges.filter((e) => e.evt).sort((a, b) => b.score - a.score);
  const filtered =
    filter === "hot"
      ? ranked.filter((e) => e.score >= 0.72)
      : filter === "beats"
        ? ranked.filter((e) => e.confirmed || e.prevented)
        : ranked;
  const shown = filter === "all" ? filtered.slice(0, 18) : filtered;
  const F: { k: typeof filter; label: string }[] = [
    { k: "all", label: `all (${ranked.length})` },
    { k: "hot", label: "high anomaly ≥ 0.72" },
    { k: "beats", label: "confirmed · prevented" },
  ];
  const grid = "44px 96px 74px 1.4fr 1.5fr 108px 96px";
  return (
    <div style={{ paddingTop: 14 }}>
      <div className={s.segTrack} style={{ marginBottom: 16 }}>
        {F.map((f) => (
          <button key={f.k} className={`${s.seg} ${filter === f.k ? s.segOn : ""}`} onClick={() => setFilter(f.k)}>
            {f.label}
          </button>
        ))}
      </div>
      <div className={s.thead} style={{ display: "grid", gridTemplateColumns: grid, padding: "0 14px 12px" }}>
        <div>#</div>
        <div>Event</div>
        <div style={{ textAlign: "right" }}>Score</div>
        <div style={{ paddingLeft: 16 }}>Technique</div>
        <div>Route</div>
        <div>Timestamp</div>
        <div style={{ textAlign: "right" }}>Verdict</div>
      </div>
      {shown.map((e, i) => {
        const v = verd(e);
        return (
          <button key={e.id} className={s.rowBtn} onClick={() => onOpen(e.id)} style={{ display: "grid", gridTemplateColumns: grid, alignItems: "center", padding: "15px 14px", borderBottom: "1px solid #f4f5f7" }}>
            <div className={s.mono} style={{ fontSize: 12, color: "var(--faint)", fontWeight: 600 }}>{String(i + 1).padStart(2, "0")}</div>
            <div className={s.mono} style={{ fontSize: 12 }}>{e.evt}</div>
            <div style={{ textAlign: "right" }}>
              <span className={s.scoreChip} style={{ background: heat(e.score).fill }}>{e.score.toFixed(2)}</span>
            </div>
            <div style={{ paddingLeft: 16, display: "flex", flexDirection: "column", gap: 2 }}>
              <span style={{ fontSize: 13, fontWeight: 600, color: "var(--ink)" }}>{e.techName}</span>
              <span className={s.mono} style={{ fontSize: 10.5, color: "var(--mut)" }}>{e.tech ?? e.type}</span>
            </div>
            <div className={s.mono} style={{ fontSize: 11, color: "var(--ink2)", overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>
              {e.s} → {e.t}
            </div>
            <div className={s.mono} style={{ fontSize: 11, color: "var(--ink2)" }}>{e.ts}</div>
            <div style={{ textAlign: "right" }}>
              <span style={{ fontSize: 9.5, fontWeight: 700, letterSpacing: "0.03em", color: v.c, background: v.bg, borderRadius: 999, padding: "3px 9px" }}>{v.t}</span>
            </div>
          </button>
        );
      })}
      <div style={{ fontSize: 11, color: "var(--mut)", marginTop: 14, padding: "0 12px" }}>
        {M.hero.nEvents} correlated events in {M.id} · showing {shown.length} of {ranked.length} evidence-bearing edges
        {filter === "all" ? " (highest-scored first)" : ""}. Click a row to jump to its edge in the graph.
      </div>
    </div>
  );
}

export function Empty({ note }: { note: string }) {
  return (
    <div style={{ padding: "60px 20px", textAlign: "center", color: "var(--mut)", fontSize: 13, lineHeight: 1.6 }}>
      {note}
    </div>
  );
}
