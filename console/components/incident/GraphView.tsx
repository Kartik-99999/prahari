"use client";

import { useEffect, useRef, useState } from "react";
import cytoscape from "cytoscape";
import fcose from "cytoscape-fcose";
import type { GraphData, GraphEdge } from "@/lib/api";
import { parseTs } from "@/lib/replay";

let registered = false;
if (!registered) {
  cytoscape.use(fcose);
  registered = true;
}

// --- honest-viz heat ramp: driven by the SYSTEM's fused_score, not ground truth.
// Daylight semantics: benign world = quiet grays that recede into the paper;
// threat = the amber→red ramp only. (Teal is reserved for the system's voice.)
function heat(score: number): string {
  if (score >= 0.9) return "#dc2626"; // critical
  if (score >= 0.75) return "#ef4444"; // red
  if (score >= 0.6) return "#f97316"; // orange
  if (score >= 0.45) return "#f59e0b"; // amber
  if (score >= 0.3) return "#94a3b8"; // cool slate (mild)
  return "#cbd5e1"; // pale slate — benign context recedes
}

const SHAPE: Record<string, string> = {
  Host: "round-rectangle",
  User: "ellipse",
  Process: "diamond",
  File: "rectangle",
  IP: "hexagon",
};

// deterministic initial position from id (seeds fcose for stable layouts)
function seedPos(id: string, i: number): { x: number; y: number } {
  let h = 0;
  for (let k = 0; k < id.length; k++) h = (h * 31 + id.charCodeAt(k)) >>> 0;
  const ang = ((h % 360) / 360) * 2 * Math.PI + i * 0.3;
  const rad = 120 + (h % 240);
  return { x: 500 + Math.cos(ang) * rad, y: 360 + Math.sin(ang) * rad };
}

function isExternalIP(id: string, type: string): boolean {
  return type === "IP" && !id.startsWith("10.");
}

export function GraphView({ graph, t }: { graph: GraphData; t: number }) {
  const boxRef = useRef<HTMLDivElement>(null);
  const cyRef = useRef<cytoscape.Core | null>(null);
  const prevT = useRef<number | null>(null);
  const [gtOverlay, setGtOverlay] = useState(false);
  const [sel, setSel] = useState<GraphEdge | null>(null);
  const [tip, setTip] = useState<{ x: number; y: number; text: string } | null>(null);

  useEffect(() => {
    if (!boxRef.current) return;

    // per-node max ANOMALY heat. Within an incident every member has high
    // fused_score (that's why it was grouped), so we colour by the per-event
    // anomaly_score: the high-anomaly malicious actions light up while the
    // low-anomaly benign events fusion pulled in as context recede.
    const HEAT = (e: GraphEdge) => e.anomaly_score ?? 0;
    const maxHeat: Record<string, number> = {};
    const nodeReveal: Record<string, number> = {};
    for (const e of graph.edges) {
      const f = HEAT(e);
      maxHeat[e.source] = Math.max(maxHeat[e.source] ?? 0, f);
      maxHeat[e.target] = Math.max(maxHeat[e.target] ?? 0, f);
      const ms = parseTs(e.ts);
      nodeReveal[e.source] = Math.min(nodeReveal[e.source] ?? Infinity, ms);
      nodeReveal[e.target] = Math.min(nodeReveal[e.target] ?? Infinity, ms);
    }

    const nodeEls = graph.nodes.map((n, i) => {
      const mf = maxHeat[n.id] ?? 0;
      const ext = isExternalIP(n.id, n.type);
      const crown = n.id === "DB-EXAMS";
      const hostBase = n.type === "Host" ? 8 : 0; // hosts are the backbone
      const classes: string[] = [];
      if (ext) classes.push("external");
      if (crown) classes.push("crown");
      return {
        data: {
          id: n.id,
          label: crown ? `${n.id} ★` : n.id,
          shape: SHAPE[n.type] ?? "ellipse",
          color: heat(mf),
          size: 20 + hostBase + mf * 30,
          glow: mf >= 0.6 ? 0.16 : 0,
          glowpad: Math.round(mf * 12),
          revealMs: nodeReveal[n.id] ?? 0,
        },
        position: seedPos(n.id, i),
        classes: classes.join(" "),
      };
    });

    const edgeEls = graph.edges.map((e, i) => {
      const f = HEAT(e);
      const reached = e.type === "REACHED";
      return {
        data: {
          id: `e${i}`,
          source: e.source,
          target: e.target,
          color: heat(f),
          // lateral-movement (REACHED) edges get a thicker floor so the path reads
          width: (reached ? 3 : 1.2) + f * 6,
          opacity: 0.18 + f * 0.78,
          edge: e,
          tsMs: parseTs(e.ts),
        },
        classes: [reached ? "reached" : "", e.malicious ? "mal" : ""]
          .filter(Boolean)
          .join(" "),
      };
    });

    const cy = cytoscape({
      container: boxRef.current,
      elements: [...nodeEls, ...edgeEls] as cytoscape.ElementDefinition[],
      wheelSensitivity: 0.2,
      style: [
        {
          selector: "node",
          style: {
            shape: "data(shape)",
            "background-color": "data(color)",
            width: "data(size)",
            height: "data(size)",
            label: "data(label)",
            color: "#475569",
            "font-size": 9,
            "font-family": "var(--font-jetbrains), monospace",
            "text-valign": "bottom",
            "text-margin-y": 4,
            "border-width": 1,
            "border-color": "#aab6c4",
            "underlay-color": "data(color)",
            "underlay-opacity": "data(glow)",
            "underlay-padding": "data(glowpad)",
          },
        },
        {
          selector: "node.external",
          style: { "border-width": 3, "border-color": "#ef4444" },
        },
        {
          selector: "node.crown",
          style: { "border-width": 3, "border-color": "#d97706", color: "#b45309" },
        },
        {
          selector: "edge",
          style: {
            width: "data(width)",
            "line-color": "data(color)",
            "line-opacity": "data(opacity)",
            "curve-style": "bezier",
            "target-arrow-shape": "triangle",
            "target-arrow-color": "data(color)",
            "arrow-scale": 0.7,
          },
        },
        {
          selector: "edge.reached",
          style: {
            "line-style": "dashed",
            "line-dash-pattern": [9, 5],
            "z-index": 20,
            "arrow-scale": 1,
          },
        },
        {
          selector: "edge.gt-on",
          style: { "line-outline-width": 2, "line-outline-color": "#0f172a" },
        },
        { selector: ".faded", style: { opacity: 0.1 } },
        { selector: ".pre", style: { opacity: 0.04, "text-opacity": 0 } },
        {
          selector: "edge.flare",
          style: { "line-color": "#ef4444", "line-opacity": 1, width: 6, "z-index": 99 },
        },
        {
          selector: "node.flare",
          style: { "underlay-color": "#ef4444", "underlay-opacity": 0.6, "underlay-padding": 16 },
        },
      ] as unknown as cytoscape.StylesheetCSS[],
      layout: {
        name: "fcose",
        randomize: false,
        animate: false,
        quality: "proof",
        nodeRepulsion: 7000,
        idealEdgeLength: 95,
        nodeSeparation: 90,
        padding: 30,
      } as unknown as cytoscape.LayoutOptions,
    });
    cyRef.current = cy;

    // hover: highlight neighbourhood + tooltip
    cy.on("mouseover", "node", (evt) => {
      const n = evt.target;
      const keep = n.closedNeighborhood();
      cy.elements().not(keep).addClass("faded");
      const rp = n.renderedPosition();
      const mf = (maxHeat[n.id()] ?? 0).toFixed(3);
      setTip({ x: rp.x, y: rp.y, text: `${n.id()} · ${n.data("shape")} · max heat ${mf}` });
    });
    cy.on("mouseout", "node", () => {
      cy.elements().removeClass("faded");
      setTip(null);
    });
    cy.on("tap", "edge", (evt) => setSel(evt.target.data("edge") as GraphEdge));
    cy.on("tap", (evt) => {
      if (evt.target === cy) setSel(null);
    });

    // marching-ants flow on the hot lateral-movement (REACHED) edges
    let raf = 0;
    let off = 0;
    const hot = cy.edges(".reached").filter((e) => (e.data("edge").anomaly_score ?? 0) >= 0.7);
    const flow = () => {
      off = (off - 0.7) % 14;
      hot.style("line-dash-offset", off);
      raf = requestAnimationFrame(flow);
    };
    if (hot.length) flow();

    return () => {
      cancelAnimationFrame(raf);
      cy.destroy();
      cyRef.current = null;
    };
  }, [graph]);

  // playhead reveal: only show elements with ts <= t; flare malicious ones as
  // the playhead crosses them (forward playback).
  useEffect(() => {
    const cy = cyRef.current;
    if (!cy) return;
    const pT = prevT.current;
    cy.batch(() => {
      cy.edges().forEach((e) => {
        const ms = e.data("tsMs") as number;
        const show = !Number.isFinite(ms) || ms <= t;
        e.toggleClass("pre", !show);
        if (
          show &&
          pT != null &&
          ms > pT &&
          ms <= t &&
          ((e.data("edge") as GraphEdge).anomaly_score ?? 0) >= 0.6
        ) {
          e.addClass("flare");
          window.setTimeout(() => {
            if (cyRef.current) e.removeClass("flare");
          }, 700);
        }
      });
      cy.nodes().forEach((n) => {
        const ms = n.data("revealMs") as number;
        n.toggleClass("pre", !(!Number.isFinite(ms) || ms <= t));
      });
    });
    prevT.current = t;
  }, [t]);

  // ground-truth overlay toggle (eval-only) — never the default coloring
  useEffect(() => {
    const cy = cyRef.current;
    if (!cy) return;
    cy.batch(() => {
      cy.edges(".mal").toggleClass("gt-on", gtOverlay);
    });
  }, [gtOverlay]);

  return (
    <div className="relative h-full w-full">
      <div ref={boxRef} className="h-full w-full rounded-md" />

      {/* legend */}
      <div className="pointer-events-none absolute left-3 top-3 space-y-2 rounded-md border border-border bg-bg/80 p-2.5 text-[10px] backdrop-blur">
        <div>
          <div className="mb-1 uppercase tracking-wider text-faint">anomaly-score heat</div>
          <div className="flex items-center gap-1">
            <span className="h-2 w-16 rounded" style={{ background: "linear-gradient(90deg,#cbd5e1,#94a3b8,#f59e0b,#f97316,#ef4444,#dc2626)" }} />
            <span className="font-mono text-faint">0 → 1</span>
          </div>
        </div>
        <div className="flex flex-wrap gap-x-3 gap-y-1 text-muted">
          <span>▢ Host</span>
          <span>◯ User</span>
          <span>◇ Process</span>
          <span>▭ File</span>
          <span>⬡ IP</span>
        </div>
        <div className="flex items-center gap-2 text-muted">
          <span className="text-red">⬡ ext-IP ring</span>
          <span className="text-amber">★ crown jewel</span>
          <span className="text-red">- - lateral path</span>
        </div>
      </div>

      {/* ground-truth overlay toggle */}
      <label className="pointer-events-auto absolute right-3 top-3 flex cursor-pointer items-center gap-2 rounded-md border border-border bg-bg/80 px-2.5 py-1.5 text-[11px] backdrop-blur">
        <input
          type="checkbox"
          checked={gtOverlay}
          onChange={(e) => setGtOverlay(e.target.checked)}
          className="accent-slate-400"
        />
        <span className={gtOverlay ? "text-text" : "text-faint"}>
          Ground-truth overlay <span className="text-faint">(eval only)</span>
        </span>
      </label>

      {/* hover tooltip */}
      {tip && (
        <div
          className="pointer-events-none absolute z-30 -translate-x-1/2 -translate-y-[140%] whitespace-nowrap rounded border border-border bg-panel px-2 py-1 font-mono text-[10px] text-text shadow"
          style={{ left: tip.x, top: tip.y }}
        >
          {tip.text}
        </div>
      )}

      {/* edge detail drawer */}
      {sel && (
        <div className="absolute bottom-3 right-3 w-72 rounded-md border border-border bg-panel/95 p-3 text-xs backdrop-blur">
          <div className="mb-2 flex items-center justify-between">
            <span className="font-mono text-sm text-text">{sel.type}</span>
            <button
              type="button"
              onClick={() => setSel(null)}
              className="text-faint hover:text-text"
            >
              ✕
            </button>
          </div>
          <dl className="space-y-1 font-mono text-[11px]">
            <Row k="event_id" v={sel.event_id ?? "—"} />
            <Row k="technique" v={sel.technique ?? "—"} accent />
            <Row k="anomaly" v={sel.anomaly_score?.toFixed(3) ?? "—"} />
            <Row k="fused" v={sel.fused_score?.toFixed(3) ?? "—"} />
            <Row k="ts" v={sel.ts ? sel.ts.slice(0, 19) : "—"} />
          </dl>
          {sel.reasons.length > 0 && (
            <div className="mt-2">
              <div className="text-[10px] uppercase tracking-wider text-faint">reasons</div>
              <ul className="mt-1 space-y-0.5 text-[11px] text-muted">
                {sel.reasons.map((r, i) => (
                  <li key={i}>• {r}</li>
                ))}
              </ul>
            </div>
          )}
        </div>
      )}
    </div>
  );
}

function Row({ k, v, accent = false }: { k: string; v: string; accent?: boolean }) {
  return (
    <div className="flex justify-between gap-2">
      <dt className="text-faint">{k}</dt>
      <dd className={`truncate ${accent ? "text-accent" : "text-text"}`}>{v}</dd>
    </div>
  );
}
