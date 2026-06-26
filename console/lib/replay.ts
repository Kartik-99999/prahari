// Replay time helpers for the cinematic scrubber.
import type { GraphData } from "@/lib/api";

// Neo4j datetime stringifies with nanosecond precision + offset
// (e.g. "2026-05-02T10:24:10.000000000+00:00"); JS Date can't parse that, so
// truncate to seconds and treat as UTC.
export function parseTs(s: string | null | undefined): number {
  if (!s) return NaN;
  const m = s.match(/^(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2})/);
  const t = Date.parse((m ? m[1] : s) + "Z");
  return Number.isNaN(t) ? Date.parse(s) : t;
}

export function graphWindow(graph: GraphData): { t0: number; t1: number } {
  let t0 = Infinity;
  let t1 = -Infinity;
  for (const e of graph.edges) {
    const ms = parseTs(e.ts);
    if (!Number.isNaN(ms)) {
      t0 = Math.min(t0, ms);
      t1 = Math.max(t1, ms);
    }
  }
  if (!Number.isFinite(t0)) {
    t0 = Date.parse("2026-05-01T00:00:00Z");
    t1 = Date.parse("2026-05-21T23:59:59Z");
  }
  return { t0, t1 };
}

export type Annotation = {
  ms: number;
  label: string;
  kind: "attack" | "confirm" | "prevented";
};

// deterministic scenario beats (the demo narrative spine)
export function keyEvents(): Annotation[] {
  const E = (iso: string, label: string, kind: Annotation["kind"]): Annotation => ({
    ms: parseTs(iso),
    label,
    kind,
  });
  return [
    E("2026-05-02T10:24:10", "Foothold", "attack"),
    E("2026-05-04T02:13:58", "CONFIRMED", "confirm"),
    E("2026-05-09T01:40:21", "Lateral →DC01", "attack"),
    E("2026-05-13T02:55:05", "Lateral →DB-EXAMS", "attack"),
    E("2026-05-19T01:30:00", "Staging", "attack"),
    E("2026-05-21T03:05:02", "Exfil — PREVENTED", "prevented"),
  ];
}

export function fmtDay(ms: number): string {
  return new Date(ms).toISOString().slice(0, 10);
}

export function fmtDateTime(ms: number): string {
  return new Date(ms).toISOString().slice(0, 16).replace("T", " ");
}

// technique -> earliest observed ms (from the system's own malicious edges)
export function techniqueOnsets(graph: GraphData): Record<string, number> {
  const onset: Record<string, number> = {};
  for (const e of graph.edges) {
    if (!e.technique) continue;
    const ms = parseTs(e.ts);
    if (Number.isNaN(ms)) continue;
    onset[e.technique] = Math.min(onset[e.technique] ?? Infinity, ms);
  }
  return onset;
}

// dedup edges to unique events for the running anomaly-score accumulator
export function scoreEvents(graph: GraphData): { ms: number; anomaly: number }[] {
  const seen = new Set<string>();
  const out: { ms: number; anomaly: number }[] = [];
  for (const e of graph.edges) {
    const id = e.event_id ?? `${e.source}-${e.target}-${e.ts}`;
    if (seen.has(id)) continue;
    seen.add(id);
    out.push({ ms: parseTs(e.ts), anomaly: e.anomaly_score ?? 0 });
  }
  return out.sort((a, b) => a.ms - b.ms);
}
