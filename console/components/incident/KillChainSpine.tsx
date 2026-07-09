"use client";

import { useMemo } from "react";
import type { GraphData, IncidentDetail } from "@/lib/api";
import { graphWindow, parseTs, techniqueOnsets } from "@/lib/replay";

const TECH_NAMES: Record<string, string> = {
  T1566: "Phishing",
  T1059: "Command & Scripting",
  T1078: "Valid Accounts",
  T1003: "Credential Dumping",
  T1021: "Remote Services",
  T1560: "Archive Collected Data",
  T1005: "Data from Local System",
  T1071: "App Layer Protocol",
  T1041: "Exfil over C2",
};

// amber -> red threat ramp across the chain (daylight); confirmed = success,
// prevented = the system's teal voice.
const RAMP = ["#d97706", "#ea580c", "#ea580c", "#dc2626", "#dc2626", "#dc2626", "#dc2626"];

type Station = {
  code: string;
  tactic: string;
  name: string;
  host: string | null;
  onset: number; // ms of first observation
  color: string;
  confirmed: boolean;
  prevented: boolean;
};

/**
 * The "Story" lens — the kill chain as a left-to-right spine. Stations are the
 * incident's own reconstructed techniques in order; each ignites when the replay
 * playhead (t) crosses its first-observed time, so scrubbing lights the chain in
 * true temporal order. The confirmation + prevention flags carry the counterfactual.
 */
export function KillChainSpine({
  incident,
  graph,
  t,
}: {
  incident: IncidentDetail;
  graph: GraphData;
  t: number;
}) {
  const { t0, t1 } = useMemo(() => graphWindow(graph), [graph]);
  const confirmedMs = useMemo(() => {
    const m = incident.mttd as { confirmed_at?: string };
    return parseTs(m.confirmed_at ?? "2026-05-04T02:13:58");
  }, [incident.mttd]);

  const stations = useMemo<Station[]>(() => {
    const onsets = techniqueOnsets(graph);
    // earliest malicious edge per technique -> the entity it acted on
    const hostFor: Record<string, string> = {};
    const best: Record<string, number> = {};
    for (const e of graph.edges) {
      if (!e.technique || !e.malicious) continue;
      const ms = parseTs(e.ts);
      if (Number.isNaN(ms)) continue;
      if (ms < (best[e.technique] ?? Infinity)) {
        best[e.technique] = ms;
        hostFor[e.technique] = e.target;
      }
    }
    const seen = new Set<string>();
    const steps = incident.kill_chain.filter((s) => {
      if (seen.has(s.technique_id)) return false;
      seen.add(s.technique_id);
      return true;
    });
    const lastIdx = steps.length - 1;
    return steps.map((s, i) => {
      const onset = onsets[s.technique_id] ?? t0 + ((t1 - t0) * i) / Math.max(1, lastIdx);
      return {
        code: s.technique_id,
        tactic: s.tactic,
        name: TECH_NAMES[s.technique_id] ?? "",
        host: hostFor[s.technique_id] ?? null,
        onset,
        color: RAMP[Math.min(i, RAMP.length - 1)],
        // the ~day-1.7 confirmed logon is the containment beat
        confirmed: Math.abs(onset - confirmedMs) < 36 * 3600 * 1000 && s.technique_id === "T1078",
        prevented: i === lastIdx,
      };
    });
  }, [graph, incident.kill_chain, t0, t1, confirmedMs]);

  const n = stations.length;

  // fill sweeps between evenly-spaced stations in TRUE time, so playback reads right
  const fillPct = useMemo(() => {
    const x = (i: number) => (n <= 1 ? 0 : (i / (n - 1)) * 100);
    if (t >= t1) return 100;
    let k = -1;
    for (let i = 0; i < n; i++) if (t >= stations[i].onset) k = i;
    if (k < 0) return 0;
    if (k >= n - 1) return 100;
    const seg = (t - stations[k].onset) / Math.max(1, stations[k + 1].onset - stations[k].onset);
    return x(k) + (x(k + 1) - x(k)) * Math.min(1, Math.max(0, seg));
  }, [t, t1, stations, n]);

  return (
    <div className="scroll-thin overflow-x-auto">
      <div className="relative min-w-[640px] px-2 pb-2 pt-11">
        {/* track */}
        <div className="absolute left-2 right-2 top-[64px] h-[3px] rounded-full bg-panel-2">
          <div
            className="absolute left-0 top-0 h-full rounded-full transition-[width] duration-300 ease-out"
            style={{
              width: `${fillPct}%`,
              background: "linear-gradient(90deg,#d97706,#dc2626)",
            }}
          />
        </div>

        {/* stations */}
        <div className="relative flex items-start justify-between">
          {stations.map((s, i) => {
            const on = t >= s.onset - 1;
            const c = s.confirmed ? "#059669" : s.color;
            return (
              <div key={`${s.code}-${i}`} className="relative w-[13%] text-center">
                {/* flag */}
                {(s.confirmed || s.prevented) && (
                  <span
                    className="absolute left-1/2 top-[-30px] -translate-x-1/2 whitespace-nowrap rounded-full border px-2 py-[2px] font-mono text-[9px] uppercase tracking-wide transition-opacity duration-300"
                    style={{
                      opacity: on ? 1 : 0,
                      color: s.confirmed ? "#059669" : "var(--color-accent)",
                      borderColor: s.confirmed
                        ? "color-mix(in srgb, #059669 40%, transparent)"
                        : "var(--color-accent)",
                      background: s.confirmed
                        ? "color-mix(in srgb, #059669 12%, transparent)"
                        : "var(--color-accent-soft, rgba(13,148,136,0.1))",
                    }}
                  >
                    {s.confirmed ? "✓ confirmed · contained" : "exfil prevented"}
                  </span>
                )}
                {/* dot */}
                <span
                  className="relative z-[2] mx-auto block h-[15px] w-[15px] rounded-full border-2 transition-all duration-300"
                  style={{
                    borderColor: on ? c : "var(--color-border)",
                    background: on && !s.prevented ? c : "var(--color-panel)",
                    borderStyle: s.prevented ? "dashed" : "solid",
                    transform: on ? "scale(1.32)" : "scale(1)",
                    boxShadow: on ? `0 0 0 4px color-mix(in srgb, ${c} 16%, transparent)` : "none",
                  }}
                />
                <div
                  className="mt-3 font-mono text-[11px] font-semibold transition-colors duration-300"
                  style={{
                    color: on ? c : "var(--color-faint)",
                    textDecoration: s.prevented && on ? "line-through" : "none",
                  }}
                >
                  {s.code}
                </div>
                <div className="mt-0.5 text-[10px] leading-tight text-muted">{s.name}</div>
                {s.host && (
                  <div className="mt-0.5 truncate font-mono text-[9.5px] text-faint">{s.host}</div>
                )}
                <div className="mt-0.5 font-mono text-[9px] text-faint">
                  {new Date(s.onset).toISOString().slice(5, 10)}
                </div>
              </div>
            );
          })}
        </div>
      </div>
    </div>
  );
}
