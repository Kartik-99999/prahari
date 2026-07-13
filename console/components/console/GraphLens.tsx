"use client";
// Provenance graph on the replay clock: x = first-seen time, y = entity band.
// The graph and the story share one axis, so the attack literally reads
// left-to-right as it happened. Honest-viz: colour/weight only from the
// system's own anomaly scores; gt overlay is eval-only and off by default.
import React, { useMemo, useState } from "react";
import s from "./console.module.css";
import { base, heat, type ConsoleModel, type EdgeM, type NodeM } from "./derive";
import type { Sel } from "./ConsoleApp";

const BAND_LABELS: { y: number; label: string }[] = [
  { y: 92, label: "USERS" },
  { y: 236, label: "HOSTS" },
  { y: 388, label: "PROCESSES" },
  { y: 500, label: "FILES" },
  { y: 588, label: "NETWORK" },
];

export function GraphLens(props: {
  model: ConsoleModel;
  playDay: number;
  sel: Sel;
  setSel: (s: Sel) => void;
  overlayGT: boolean;
  setOverlayGT: (b: boolean) => void;
}) {
  const { model: M, playDay, sel, setSel, overlayGT, setOverlayGT } = props;
  const [hover, setHover] = useState<string | null>(null);
  const atEnd = playDay >= M.dmax - 0.02;

  const nmap = useMemo(() => {
    const m: Record<string, NodeM> = {};
    for (const n of M.nodes) m[n.id] = n;
    return m;
  }, [M.nodes]);

  const visEdges = M.edges.filter((e) => atEnd || e.day <= playDay);
  const visIds = new Set<string>();
  for (const e of visEdges) {
    visIds.add(e.s);
    visIds.add(e.t);
  }
  const neighbours = useMemo(() => {
    if (!hover) return null;
    const set = new Set<string>([hover]);
    for (const e of M.edges) {
      if (e.s === hover) set.add(e.t);
      if (e.t === hover) set.add(e.s);
    }
    return set;
  }, [hover, M.edges]);

  const selEdge = sel?.kind === "edge" ? M.edges.find((e) => e.id === sel.id) : null;
  const selNode = sel?.kind === "node" ? nmap[sel.id] : null;

  const topSignals = useMemo(
    () =>
      M.edges
        .filter((e) => e.evt)
        .sort((a, b) => b.score - a.score)
        .slice(0, 5),
    [M.edges],
  );

  const edgePath = (e: EdgeM) => {
    const a = nmap[e.s];
    const b = nmap[e.t];
    if (!a || !b) return "";
    const mx = (a.x + b.x) / 2;
    const my = (a.y + b.y) / 2 - Math.min(70, Math.abs(a.x - b.x) * 0.18) - 8;
    return `M ${a.x} ${a.y} Q ${mx} ${my} ${b.x} ${b.y}`;
  };

  return (
    <div style={{ display: "flex", gap: 18, paddingTop: 16, flexWrap: "wrap" }}>
      <div style={{ flex: "1 1 640px", minWidth: 420 }}>
        <div style={{ borderRadius: 22, overflow: "hidden", padding: 8, background: "linear-gradient(160deg,#f3f4fb 0%,#f8f8fa 46%,#fbfaf7 100%)", boxShadow: "inset 0 1px 3px rgba(17,24,39,0.04)" }}>
          <svg viewBox="0 0 1040 640" style={{ display: "block", width: "100%", height: "auto" }} onClick={() => setSel(null)}>
            {/* band guides */}
            {BAND_LABELS.map((b) => (
              <g key={b.label}>
                <line x1={24} x2={1016} y1={b.y} y2={b.y} stroke="rgba(148,163,184,0.16)" strokeWidth={1} strokeDasharray="1 7" />
                <text x={26} y={b.y - 9} fontSize={8.5} letterSpacing={1.4} fill="#B6C2CE" fontFamily="var(--font-jetbrains)">
                  {b.label}
                </text>
              </g>
            ))}
            {/* edges */}
            {visEdges.map((e) => {
              const hot = e.score >= 0.72;
              const col = e.spine ? "#DC2626" : heat(e.score).fill;
              const inHover = !neighbours || (neighbours.has(e.s) && neighbours.has(e.t));
              const selected = selEdge?.id === e.id;
              const w = e.spine ? 3 : hot ? 2.2 : 1.1;
              return (
                <g key={e.id} opacity={inHover ? (hot || e.spine ? 0.95 : 0.4) : 0.08} style={{ transition: "opacity .2s" }}>
                  <path
                    d={edgePath(e)}
                    fill="none"
                    stroke={col}
                    strokeWidth={selected ? w + 1.4 : w}
                    strokeDasharray={e.spine ? "8 6" : undefined}
                    className={e.spine ? "march" : undefined}
                    strokeLinecap="round"
                  />
                  {overlayGT && e.mal && <path d={edgePath(e)} fill="none" stroke="#fff" strokeWidth={0.8} strokeDasharray="1 5" />}
                  <path
                    d={edgePath(e)}
                    fill="none"
                    stroke="transparent"
                    strokeWidth={11}
                    style={{ cursor: "pointer" }}
                    onClick={(ev) => {
                      ev.stopPropagation();
                      setSel({ kind: "edge", id: e.id });
                    }}
                  />
                </g>
              );
            })}
            {/* nodes */}
            {M.nodes.filter((n) => visIds.has(n.id)).map((n) => {
              const h = heat(n.score);
              const faint = n.score < 0.55;
              const inHover = !neighbours || neighbours.has(n.id);
              const selected = selNode?.id === n.id;
              const r = n.crown ? 15 : n.type === "host" ? 13 : 9 + n.score * 4;
              return (
                <g
                  key={n.id}
                  opacity={inHover ? (faint ? 0.55 : 1) : 0.12}
                  style={{ cursor: "pointer", transition: "opacity .2s" }}
                  onMouseEnter={() => setHover(n.id)}
                  onMouseLeave={() => setHover(null)}
                  onClick={(ev) => {
                    ev.stopPropagation();
                    setSel({ kind: "node", id: n.id });
                  }}
                >
                  {n.ext ? (
                    <polygon
                      points={hexPoints(n.x, n.y, r + 2)}
                      fill={h.fill}
                      stroke={selected ? "#111827" : "#fff"}
                      strokeWidth={selected ? 2.5 : 1.5}
                    />
                  ) : n.type === "user" ? (
                    <rect x={n.x - r} y={n.y - r} width={r * 2} height={r * 2} rx={5} fill={h.fill} stroke={selected ? "#111827" : "#fff"} strokeWidth={selected ? 2.5 : 1.5} transform={`rotate(45 ${n.x} ${n.y})`} />
                  ) : n.type === "file" ? (
                    <rect x={n.x - r} y={n.y - r * 0.82} width={r * 2} height={r * 1.64} rx={4} fill={h.fill} stroke={selected ? "#111827" : "#fff"} strokeWidth={selected ? 2.5 : 1.5} />
                  ) : (
                    <circle cx={n.x} cy={n.y} r={r} fill={h.fill} stroke={selected ? "#111827" : "#fff"} strokeWidth={selected ? 2.5 : 1.5} />
                  )}
                  {n.crown && <text x={n.x} y={n.y - r - 7} textAnchor="middle" fontSize={12} fill="#B45309">★</text>}
                  {(n.type === "host" || n.crown || n.ext || n.score >= 0.72 || hover === n.id) && (
                    <g>
                      <rect x={n.x - n.label.length * 3.4 - 5} y={n.y + r + 4} width={n.label.length * 6.8 + 10} height={15} rx={4} fill="#ffffff" opacity={0.92} />
                      <text x={n.x} y={n.y + r + 15} textAnchor="middle" fontSize={10.5} fontWeight={faint ? 500 : 700} fill={faint ? "#94A3B8" : "#101828"} fontFamily="var(--font-jetbrains)">
                        {n.label}
                      </text>
                    </g>
                  )}
                </g>
              );
            })}
          </svg>
        </div>
        <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between", gap: 14, marginTop: 14, flexWrap: "wrap", background: "#fff", border: "1px solid var(--line)", borderRadius: 999, padding: "9px 18px" }}>
          <div style={{ display: "flex", alignItems: "center", gap: 16, flexWrap: "wrap" }}>
            <span style={{ display: "flex", alignItems: "center", gap: 6, fontSize: 10.5, color: "var(--ink2)" }}>
              <svg width="30" height="10"><line x1="1" y1="5" x2="29" y2="5" stroke="#DC2626" strokeWidth="2.5" strokeDasharray="6 5" /></svg> attack spine
            </span>
            <Legend color="#DC2626" label="high anomaly" />
            <Legend color="#D9A441" label="elevated" />
            <Legend color="#C3CDD8" label="benign" />
          </div>
          <label style={{ display: "flex", alignItems: "center", gap: 7, fontSize: 10.5, color: "var(--ink2)", cursor: "pointer" }}>
            <input type="checkbox" checked={overlayGT} onChange={(e) => setOverlayGT(e.target.checked)} style={{ accentColor: "#4F46B8", width: 14, height: 14 }} />
            ground-truth <span style={{ color: "var(--faint)" }}>(eval only)</span>
          </label>
        </div>
      </div>

      {/* rail: drawer or top signals */}
      <div style={{ flex: "1 1 300px", minWidth: 280, maxWidth: 380 }}>
        {selEdge ? (
          <Drawer
            title={`${base(selEdge.s)} → ${base(selEdge.t)}`}
            onClose={() => setSel(null)}
            meta={[
              ["event id", selEdge.evtFull ? selEdge.evtFull.slice(0, 13) + "…" : "—"],
              ["technique", selEdge.tech ? `${selEdge.tech} · ${selEdge.techName}` : selEdge.type],
              ["anomaly score", selEdge.score.toFixed(3)],
              ["observed", selEdge.ts || "—"],
            ]}
            chip={selEdge.prevented ? { t: "✕ exfil prevented", bad: true } : selEdge.confirmed ? { t: "✓ confirmation beat", bad: false } : null}
            reasons={selEdge.reasons}
            reasonsTitle="Why it fired — the system's own reasons"
            score={selEdge.score}
          />
        ) : selNode ? (
          <Drawer
            title={selNode.label}
            onClose={() => setSel(null)}
            meta={[
              ["entity type", selNode.type + (selNode.crown ? " · crown jewel" : "") + (selNode.ext ? " · external" : "")],
              ["first seen", `day ${selNode.day.toFixed(1)}`],
              ["heat (top-2 mean)", selNode.score.toFixed(3)],
              ["touching edges", String(M.edges.filter((e) => e.s === selNode.id || e.t === selNode.id).length)],
            ]}
            chip={null}
            reasons={M.edges
              .filter((e) => (e.s === selNode.id || e.t === selNode.id) && e.score >= 0.72)
              .sort((a, b) => b.score - a.score)
              .slice(0, 4)
              .map((e) => `${e.score.toFixed(2)} · ${e.tech ?? e.type} · ${base(e.s)} → ${base(e.t)}`)}
            reasonsTitle="Loudest touching edges"
            score={selNode.score}
          />
        ) : (
          <div style={{ border: "1px solid var(--line)", borderRadius: 20, padding: "22px 18px", background: "linear-gradient(160deg,#f6f7fd,#fdfdfe)", height: "100%", minHeight: 260, display: "flex", flexDirection: "column" }}>
            <div style={{ textAlign: "center", padding: "6px 0 14px" }}>
              <div style={{ fontSize: 13, fontWeight: 600, color: "var(--ink2)" }}>Inspect any node or edge</div>
              <div style={{ fontSize: 11.5, color: "var(--mut)", marginTop: 4, lineHeight: 1.5 }}>
                The graph shares the replay clock — x is first-seen time. Hover to spotlight; click for evidence.
              </div>
            </div>
            <div style={{ borderTop: "1px solid var(--line)", paddingTop: 12 }}>
              <div className={s.kicker} style={{ fontSize: 10, marginBottom: 8, color: "var(--faint)" }}>Top signals</div>
              {topSignals.map((e) => (
                <button key={e.id} className={s.rowBtn} onClick={() => setSel({ kind: "edge", id: e.id })} style={{ display: "flex", alignItems: "center", gap: 9, padding: "8px 2px" }}>
                  <span className={s.scoreChip} style={{ fontSize: 10, background: heat(e.score).fill, flex: "0 0 auto" }}>{e.score.toFixed(2)}</span>
                  <span className={s.mono} style={{ fontSize: 11, fontWeight: 700, flex: "0 0 46px" }}>{e.tech ?? e.type}</span>
                  <span className={s.mono} style={{ fontSize: 10.5, color: "#64748B", minWidth: 0, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>
                    {base(e.s)} → {base(e.t)}
                  </span>
                </button>
              ))}
            </div>
          </div>
        )}
      </div>
    </div>
  );
}

function Legend({ color, label }: { color: string; label: string }) {
  return (
    <span style={{ display: "flex", alignItems: "center", gap: 6, fontSize: 10.5, color: "var(--ink2)" }}>
      <span style={{ width: 11, height: 11, borderRadius: 3, background: color }} /> {label}
    </span>
  );
}

function hexPoints(cx: number, cy: number, r: number): string {
  const pts: string[] = [];
  for (let i = 0; i < 6; i++) {
    const a = (Math.PI / 3) * i - Math.PI / 6;
    pts.push(`${(cx + r * Math.cos(a)).toFixed(1)},${(cy + r * Math.sin(a)).toFixed(1)}`);
  }
  return pts.join(" ");
}

function Drawer(props: {
  title: string;
  onClose: () => void;
  meta: [string, string][];
  chip: { t: string; bad: boolean } | null;
  reasons: string[];
  reasonsTitle: string;
  score: number;
}) {
  const { title, onClose, meta, chip, reasons, reasonsTitle, score } = props;
  return (
    <div style={{ border: "1px solid var(--line)", borderRadius: 14, padding: "18px 18px 20px", background: "#fff" }}>
      <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between", gap: 10 }}>
        <div className={s.mono} style={{ fontSize: 13.5, fontWeight: 700 }}>{title}</div>
        <div style={{ display: "flex", alignItems: "center", gap: 8 }}>
          <span className={s.scoreChip} style={{ background: heat(score).fill }}>{score.toFixed(2)}</span>
          <button onClick={onClose} className={s.focusable} style={{ border: 0, borderRadius: 999, cursor: "pointer", background: "#F3F4F6", color: "var(--ink2)", padding: "5px 11px", fontSize: 11, fontWeight: 700 }}>✕</button>
        </div>
      </div>
      {chip && (
        <div style={{ marginTop: 10, display: "inline-block", fontSize: 10, fontWeight: 700, letterSpacing: "0.04em", color: chip.bad ? "#991B1B" : "#065F46", background: chip.bad ? "rgba(220,38,38,0.07)" : "rgba(5,150,105,0.1)", border: `1px solid ${chip.bad ? "rgba(220,38,38,0.28)" : "rgba(5,150,105,0.3)"}`, borderRadius: 7, padding: "3px 9px" }}>
          {chip.t}
        </div>
      )}
      <div style={{ display: "flex", flexDirection: "column", gap: 7, marginTop: 14 }}>
        {meta.map(([k, v]) => (
          <div key={k} style={{ display: "flex", justifyContent: "space-between", gap: 12, borderBottom: "1px solid #F4F7FA", paddingBottom: 7 }}>
            <span style={{ fontSize: 11, color: "var(--mut)" }}>{k}</span>
            <span className={s.mono} style={{ fontSize: 11.5, color: "var(--ink)", textAlign: "right" }}>{v}</span>
          </div>
        ))}
      </div>
      {reasons.length > 0 && (
        <>
          <div className={s.kicker} style={{ fontSize: 10.5, marginTop: 14 }}>{reasonsTitle}</div>
          <div style={{ display: "flex", flexDirection: "column", gap: 7, marginTop: 8 }}>
            {reasons.map((r, i) => (
              <div key={i} style={{ display: "flex", gap: 8, fontSize: 12, color: "var(--ink2)", lineHeight: 1.45 }}>
                <span style={{ color: "#4F46B8", flex: "0 0 auto" }}>›</span>
                <span>{r}</span>
              </div>
            ))}
          </div>
        </>
      )}
    </div>
  );
}
