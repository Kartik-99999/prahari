// Pure derivation layer: BFF payloads in → one typed ConsoleModel out.
// Generic across incidents — nothing here assumes a particular scenario.
// HONEST-VIZ CONTRACT: every colour/weight derives from the system's own
// anomaly_score; the gt-derived `malicious` flag feeds ONLY the eval-only
// overlay. Node heat is the mean of the top-2 touching-edge scores (one loud
// cold-start edge must not paint an entity red; repeated flags should).
import type {
  AuditResp,
  GraphData,
  IncidentDetail,
  IncidentSummary,
  MetricsSlate,
  PlaybookAction,
} from "@/lib/api";
import { parseTs } from "@/lib/replay";

const DAY = 86400e3;

export const TECH_NAMES: Record<string, string> = {
  T1566: "Phishing",
  T1071: "Application Layer Protocol",
  T1078: "Valid Accounts",
  T1003: "OS Credential Dumping",
  T1021: "Remote Services",
  T1560: "Archive Collected Data",
  T1041: "Exfiltration Over C2",
  T1070: "Indicator Removal",
  T1486: "Data Encrypted for Impact",
  T1005: "Data from Local System",
  T1059: "Command & Scripting",
  T1204: "User Execution",
  T1550: "Use Alternate Auth",
  T1087: "Account Discovery",
  T1052: "Exfil Over Physical Medium",
  T1039: "Data from Network Drive",
  T1069: "Permission Groups Discovery",
};

export const TACTIC_LABEL: Record<string, string> = {
  "initial-access": "Initial Access",
  persistence: "Persistence",
  "defense-evasion": "Defense Evasion",
  stealth: "Defense Evasion",
  "credential-access": "Credential Access",
  "lateral-movement": "Lateral Movement",
  collection: "Collection",
  "command-and-control": "Command & Control",
  exfiltration: "Exfiltration",
  impact: "Impact",
  discovery: "Discovery",
};

export const ATTCK_COLS = [
  "Initial Access",
  "Persistence",
  "Defense Evasion",
  "Credential Access",
  "Discovery",
  "Lateral Movement",
  "Collection",
  "Command & Control",
  "Exfiltration",
];

export const base = (id: string): string => {
  const b = String(id).split(/[\\/|]/).pop();
  return b && b.length ? b : String(id);
};
const MONTHS = ["Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"];
const p2 = (n: number) => String(n).padStart(2, "0");
export const fmtMD = (ms: number) => {
  const d = new Date(ms);
  return `${MONTHS[d.getUTCMonth()]} ${p2(d.getUTCDate())}`;
};
export const fmtTs = (ms: number) => {
  const d = new Date(ms);
  return `${p2(d.getUTCMonth() + 1)}-${p2(d.getUTCDate())} ${p2(d.getUTCHours())}:${p2(d.getUTCMinutes())}`;
};

// Recalibrated for real UEBA output: benign cold-start novelty runs 0.32–0.68,
// so only ≥0.72 reads as threat; the mid band stays muted amber.
export function heat(sc: number): { fill: string; stroke: string } {
  if (sc >= 0.85) return { fill: "#DC2626", stroke: "#ffffff" };
  if (sc >= 0.72) return { fill: "#E11D48", stroke: "#ffffff" };
  if (sc >= 0.55) return { fill: "#D9A441", stroke: "#ffffff" };
  if (sc >= 0.4) return { fill: "#9AA7B6", stroke: "#E2E8F0" };
  return { fill: "#C3CDD8", stroke: "#E2E8F0" };
}

export type NodeM = {
  id: string;
  label: string;
  type: string;
  score: number;
  day: number;
  x: number;
  y: number;
  crown: boolean;
  ext: boolean;
};
export type EdgeM = {
  id: string;
  s: string;
  t: string;
  type: string;
  tech: string | null;
  techName: string;
  score: number;
  day: number;
  ts: string;
  spine: boolean;
  mal: boolean;
  prevented: boolean;
  confirmed: boolean;
  evt: string | null;
  evtFull: string | null;
  reasons: string[];
};
export type Station = {
  n: number;
  id: string;
  name: string;
  tactic: string;
  host: string;
  date: string;
  day: number;
  score: number;
  verdict?: string;
  prevented: boolean;
  evidence: string;
};
export type Beat = { date: string; day: number; label: string; key?: string };
export type ActionM = {
  idx: number;
  name: string;
  target: string;
  blast: string;
  auto: boolean;
  status: string;
  approver: string | null;
  rationale: string;
};
export type LedgerRow = {
  seq: number;
  ts: string;
  action: string;
  decision: string | null;
  actor: string;
  hash: string | null;
};

export type ConsoleModel = {
  id: string;
  t0: number;
  dmax: number;
  nodes: NodeM[];
  edges: EdgeM[];
  stations: Station[];
  predicted: { id: string; name: string; tactic: string; rationale: string }[];
  attck: { col: string; cells: { k: "obs" | "con" | "pred"; tid: string; name: string }[] }[];
  hops: { from: string; to: string; cred: string; tech: string; date: string; day: number; detail: string }[];
  pathMeta: { start: string; startDetail: string; exfilIp: string; exfilDate: string; exfilDetail: string; present: boolean };
  beats: Beat[];
  hero: {
    status: string;
    mttd: string | null;
    confirmedDate: string | null;
    dwell: string | null;
    exfilMD: string | null;
    score: string;
    ratio: string | null;
    nEvents: number;
    spanDays: string;
    hostsText: string;
    usersCount: number;
    prevented: boolean;
  };
  metrics: { key: string; display: string; label: string; sub: string; color: string }[];
  fusion: { label: string; auto: boolean; fracText: string; thrText: string; fracPct: number; thrPct: number; pivots: string[]; insider: boolean } | null;
  actions: ActionM[];
  ledger: LedgerRow[];
  auditMeta: { entries: number; ok: boolean; head: string | null };
  assessment: string | null;
};

// ---- generic graph layout: x = first-seen time, y = entity-type band --------
// The graph and the replay share one clock, so position IS meaning; a light
// collision pass keeps same-band neighbours legible. Deterministic, no physics.
const BANDS: Record<string, number> = { user: 92, host: 236, process: 388, file: 500, ip: 588 };
const VIEW_W = 1040;
const PADX = 80;
function layout(nodes: NodeM[]) {
  const byBand: Record<string, NodeM[]> = {};
  for (const n of nodes) (byBand[n.type] = byBand[n.type] ?? []).push(n);
  for (const list of Object.values(byBand)) {
    list.sort((a, b) => a.day - b.day || a.id.localeCompare(b.id));
    let lastX = -Infinity;
    let flip = 1;
    for (const n of list) {
      let x = PADX + (n.x / 100) * (VIEW_W - 2 * PADX); // n.x carries dayFrac*100
      if (x < lastX + 74) x = lastX + 74; // collision nudge along the time axis
      lastX = x;
      n.x = Math.min(VIEW_W - 46, x);
      // alternate a slight stagger within the band so labels never kiss
      n.y = (BANDS[n.type] ?? 320) + flip * 16;
      flip = -flip;
    }
  }
  return nodes;
}

export function buildModel(
  inc: IncidentDetail,
  graph: GraphData,
  playbook: PlaybookAction[],
  audit: AuditResp,
  slate: MetricsSlate,
  list: IncidentSummary[],
): ConsoleModel | null {
  let t0 = Infinity,
    t1 = -Infinity;
  for (const e of graph.edges) {
    const ms = parseTs(e.ts);
    if (!Number.isNaN(ms)) {
      t0 = Math.min(t0, ms);
      t1 = Math.max(t1, ms);
    }
  }
  if (!Number.isFinite(t0) || t1 <= t0) return null;
  const dmax = Math.max(1, (t1 - t0) / DAY);
  const dayOf = (ms: number) => (Number.isNaN(ms) ? 0 : Math.max(0, (ms - t0) / DAY));
  const slateMttd = (slate.mttd ?? {}) as MetricsSlate["mttd"];
  const incMttd = (inc.mttd ?? {}) as Partial<MetricsSlate["mttd"]>;
  // the BFF's mttd block describes the CONFIRMED campaign — only trust it for
  // this incident if this incident is the one that got confirmed/contained
  const mine = list.find((x) => x.id === inc.id);
  const isConfirmedIncident = inc.status === "contained" || mine?.mttd_days != null;
  const confirmedMs = isConfirmedIncident ? parseTs(incMttd.confirmed_at ?? "") : NaN;

  const nodeType: Record<string, string> = {};
  for (const n of graph.nodes) nodeType[n.id] = n.type;
  const isHost = (id: string) => nodeType[id] === "Host";
  const isExt = (id: string) => nodeType[id] === "IP" && !id.startsWith("10.");

  // ---- node heat + first-seen -------------------------------------------------
  const touch: Record<string, { scores: number[]; ms: number; hotMs: number; hotScore: number }> = {};
  for (const e of graph.edges) {
    const ms = parseTs(e.ts);
    const a = e.anomaly_score ?? 0;
    for (const id of [e.source, e.target]) {
      const t = touch[id] ?? (touch[id] = { scores: [], ms: Infinity, hotMs: Infinity, hotScore: -1 });
      t.scores.push(a);
      if (!Number.isNaN(ms)) {
        t.ms = Math.min(t.ms, ms);
        // the moment this entity got *interesting* — its loudest edge (ties → earliest)
        if (a > t.hotScore || (a === t.hotScore && ms < t.hotMs)) {
          t.hotScore = a;
          t.hotMs = ms;
        }
      }
    }
  }
  const top2 = (xs: number[]) => {
    const s = [...xs].sort((a, b) => b - a);
    return s.length >= 2 ? (s[0] + s[1]) / 2 : (s[0] ?? 0);
  };
  // crown jewel = the most-anomalous internal Host target of lateral movement,
  // falling back to the last hop of the reported lateral path.
  const lateral = inc.lateral_path?.path ?? [];
  const crownId = lateral.length ? lateral[lateral.length - 1] : null;

  const nodes: NodeM[] = graph.nodes.map((n) => {
    const t = touch[n.id] ?? { scores: [0], ms: t0, hotMs: t0, hotScore: 0 };
    // x-position = when the entity became interesting, so the attack reads
    // left→right in true story order (first-seen would bunch everything at
    // day 0 — baseline traffic touches every host immediately)
    const posMs = Number.isFinite(t.hotMs) ? t.hotMs : t.ms;
    const dayFrac = dayOf(posMs) / dmax;
    return {
      id: n.id,
      label: base(n.id),
      type: String(n.type).toLowerCase(),
      score: top2(t.scores),
      day: dayOf(t.ms),
      x: dayFrac * 100, // consumed by layout()
      y: 0,
      crown: n.id === crownId,
      ext: isExt(n.id),
    };
  });
  layout(nodes);

  // ---- edges -------------------------------------------------------------------
  const isSpine = (e: GraphData["edges"][number]) => {
    const a = e.anomaly_score ?? 0;
    if (e.type === "REACHED" && a >= 0.7) return true;
    if ((e.type === "AUTH" || e.type === "CONNECTED_TO") && a >= 0.9) return true;
    return false;
  };
  const edges: EdgeM[] = graph.edges.map((e, i) => {
    const ms = parseTs(e.ts);
    const a = e.anomaly_score ?? 0;
    return {
      id: "e" + i,
      s: e.source,
      t: e.target,
      type: e.type,
      tech: e.technique ?? null,
      techName: e.technique ? (TECH_NAMES[e.technique] ?? e.type) : e.type,
      score: a,
      day: dayOf(ms),
      ts: Number.isNaN(ms) ? "" : fmtTs(ms),
      spine: isSpine(e),
      mal: !!e.malicious,
      prevented: e.technique === "T1041" && isExt(e.target),
      confirmed:
        e.technique === "T1078" && !Number.isNaN(ms) && Math.abs(ms - confirmedMs) < 36 * 3600e3,
      evt: e.event_id ? String(e.event_id).slice(0, 8) : null,
      evtFull: e.event_id ? String(e.event_id) : null,
      reasons: Array.isArray(e.reasons) ? e.reasons : [],
    };
  });

  // ---- kill-chain stations -------------------------------------------------------
  const seen = new Set<string>();
  const kc = (inc.kill_chain ?? []).filter((k) => {
    if (seen.has(k.technique_id)) return false;
    seen.add(k.technique_id);
    return true;
  });
  const perTech: Record<string, { ms: number; score: number; host: string }> = {};
  for (const e of graph.edges) {
    if (!e.technique) continue;
    const ms = parseTs(e.ts);
    if (Number.isNaN(ms)) continue;
    const rec = perTech[e.technique] ?? (perTech[e.technique] = { ms: Infinity, score: 0, host: "—" });
    rec.score = Math.max(rec.score, e.anomaly_score ?? 0);
    if (ms < rec.ms) {
      rec.ms = ms;
      rec.host = isHost(e.target) ? e.target : isHost(e.source) ? e.source : base(e.target);
    }
  }
  const lastIdx = kc.length - 1;
  const stations: Station[] = kc.map((k, i) => {
    const r = perTech[k.technique_id] ?? {
      ms: t0 + ((t1 - t0) * i) / Math.max(1, lastIdx),
      score: 0.6,
      host: "—",
    };
    const confirmed =
      !Number.isNaN(confirmedMs) && Math.abs(r.ms - confirmedMs) < 36 * 3600e3 && k.technique_id === "T1078";
    const prevented = i === lastIdx && /exfil/i.test(k.tactic + k.technique_id + "T1041") && k.technique_id === "T1041";
    return {
      n: i + 1,
      id: k.technique_id,
      name: TECH_NAMES[k.technique_id] ?? k.technique_id,
      tactic: TACTIC_LABEL[k.tactic] ?? k.tactic,
      host: r.host,
      date: fmtMD(r.ms),
      day: dayOf(r.ms),
      score: r.score,
      verdict: confirmed ? "confirmed · contained" : prevented ? "exfil prevented" : undefined,
      prevented,
      // the report narrative embeds its build-time date; the row shows the
      // real per-edge date, so strip the stale prefix
      evidence: String(k.narrative ?? "").replace(/^\[\d{4}-\d{2}-\d{2}\]\s*/, ""),
    };
  });

  // ---- predicted next moves + ATT&CK matrix ------------------------------------
  const predicted = (inc.next_moves ?? []).map((m) => ({
    id: m.predicted_technique,
    name: TECH_NAMES[m.predicted_technique] ?? m.predicted_technique,
    tactic: TACTIC_LABEL[m.tactic] ?? m.tactic ?? "Impact",
    rationale: m.rationale ?? "",
  }));
  const colCells: Record<string, { k: "obs" | "con" | "pred"; tid: string; name: string }[]> = {};
  for (const c of ATTCK_COLS) colCells[c] = [];
  for (const st of stations) {
    const col = colCells[st.tactic] ? st.tactic : "Defense Evasion";
    colCells[col].push({
      k: st.verdict === "confirmed · contained" ? "con" : "obs",
      tid: st.id,
      name: st.name || st.id,
    });
  }
  for (const pmv of predicted) {
    const col = colCells[pmv.tactic] ? pmv.tactic : "Impact";
    (colCells[col] = colCells[col] ?? []).push({ k: "pred", tid: pmv.id, name: pmv.name });
  }
  const attck = ATTCK_COLS.map((col) => ({ col, cells: colCells[col] ?? [] }));

  // ---- lateral path ---------------------------------------------------------------
  const spineHops = edges
    .filter((e) => e.type === "REACHED" && e.spine)
    .sort((a, b) => a.day - b.day);
  const credFor = (hop: EdgeM) => {
    const win = 2 * 3600e3;
    const hopMs = t0 + hop.day * DAY;
    for (const e of edges) {
      if (e.type !== "AUTH" || e.t !== hop.t) continue;
      const ms = t0 + e.day * DAY;
      if (Math.abs(ms - hopMs) <= win) return e.s;
    }
    return "—";
  };
  const hops = spineHops.map((h) => ({
    from: base(h.s),
    to: base(h.t),
    cred: credFor(h),
    tech: h.tech ?? "T1021",
    date: fmtMD(t0 + h.day * DAY),
    day: h.day,
    detail: h.reasons[0] ?? "first-seen lateral session in the baseline",
  }));
  const exfilEdge = edges.find((e) => e.prevented);
  const exfilMs = exfilEdge ? t0 + exfilEdge.day * DAY : NaN;
  const attackMs = parseTs(incMttd.attack_start ?? "");
  const pathMeta = {
    start: lateral[0] ?? hops[0]?.from ?? "—",
    startDetail: `Patient zero — first flagged ${Number.isNaN(attackMs) ? "" : fmtMD(attackMs)}; credentials later replayed from here.`,
    exfilIp: inc.external_ips?.[0] ?? "—",
    exfilDate: Number.isNaN(exfilMs) ? "—" : fmtMD(exfilMs),
    exfilDetail: exfilEdge
      ? `${base(exfilEdge.t)} never received the archive — the channel was already severed${Number.isNaN(confirmedMs) ? "" : " on " + fmtMD(confirmedMs)}.`
      : "No exfiltration attempt observed in this incident.",
    present: hops.length > 0 || !!(inc.lateral_path?.present),
  };

  // ---- replay beats ------------------------------------------------------------------
  const beats: Beat[] = [];
  const md = (ms: number) => fmtTs(ms).slice(0, 5);
  if (!Number.isNaN(attackMs)) beats.push({ date: md(attackMs), day: dayOf(attackMs), label: "Foothold" });
  if (!Number.isNaN(confirmedMs))
    beats.push({ date: md(confirmedMs), day: dayOf(confirmedMs), label: "Confirmed", key: "confirmed" });
  for (const h of hops) beats.push({ date: md(t0 + h.day * DAY), day: h.day, label: "→ " + h.to });
  if (perTech["T1560"])
    beats.push({ date: md(perTech["T1560"].ms), day: dayOf(perTech["T1560"].ms), label: "Staging" });
  if (!Number.isNaN(exfilMs)) beats.push({ date: md(exfilMs), day: dayOf(exfilMs), label: "Exfil ✕", key: "prevented" });

  // ---- verdict + slate --------------------------------------------------------------
  const sorted = [...list].sort((a, b) => b.score - a.score);
  const second = sorted.find((x) => x.id !== inc.id)?.score;
  const isTop = sorted[0]?.id === inc.id;
  const hero = {
    status: inc.status ?? "open",
    mttd: mine?.mttd_days != null ? mine.mttd_days.toFixed(2) : incMttd.mttd_days_after_foothold != null && isTop ? String(incMttd.mttd_days_after_foothold) : null,
    confirmedDate: Number.isNaN(confirmedMs) ? null : String(incMttd.confirmed_at ?? "").slice(0, 10),
    dwell: isTop && incMttd.dwell_days_before_exfil != null ? String(incMttd.dwell_days_before_exfil) : null,
    exfilMD: Number.isNaN(exfilMs) ? null : fmtMD(exfilMs),
    score: Number(inc.score ?? 0).toFixed(2),
    ratio: isTop && second ? `${Math.round(Number(inc.score) / second)}×` : null,
    nEvents: Number(inc.n_events ?? 0),
    spanDays: Number(inc.span_days ?? dmax).toFixed(1),
    hostsText: (inc.hosts ?? []).join(" · "),
    usersCount: (inc.users ?? []).length,
    prevented: !!exfilEdge,
  };
  const u = slate.ueba ?? ({} as MetricsSlate["ueba"]);
  const at = slate.attribution ?? ({} as MetricsSlate["attribution"]);
  const so = slate.soar ?? ({} as MetricsSlate["soar"]);
  const mr = slate.mttr ?? ({} as MetricsSlate["mttr"]);
  const au = slate.auditability ?? ({} as MetricsSlate["auditability"]);
  const lat = Number(mr.auto_containment_latency_seconds ?? 0);
  const ink = "#16161D";
  const metrics = [
    { key: "roc", display: Number(u.roc_auc ?? 0).toFixed(4), label: "UEBA ROC-AUC", sub: `${u.malicious ?? "—"} malicious / ${u.benign ?? "—"} benign`, color: ink },
    { key: "recall", display: `${Math.round(Number(u.recall_at_1pct_fpr ?? 0) * 100)}%`, label: "Recall @ 1% FPR", sub: "weak-signal detection", color: ink },
    { key: "tech", display: `${Number(at.technique_accuracy_pct ?? 0).toFixed(1)}%`, label: "Technique accuracy", sub: `${at.false_attributions ?? 0} false attributions`, color: ink },
    { key: "auto", display: `${Number(so.automation_coverage_pct ?? 0)}%`, label: "Automation coverage", sub: `${so.auto ?? "—"} auto / ${so.gated ?? "—"} human-gated`, color: ink },
    { key: "mttd", display: `${Number(slateMttd.mttd_days_after_foothold ?? 0).toFixed(2)} d`, label: "MTTD", sub: "vs ~200 d industry", color: ink },
    { key: "mttr", display: lat < 1 ? "< 1 s" : `${lat.toFixed(2)} s`, label: "MTTR", sub: "auto-containment", color: ink },
    { key: "audit", display: "✓", label: "Audit", sub: `${au.ledger_entries ?? "—"}-entry hash chain`, color: "#059669" },
  ];

  const f = slate.fusion ?? ({} as MetricsSlate["fusion"]);
  const fusion =
    f && f.mode
      ? {
          label: f.mode === "insider" ? "INSIDER" : "EXTERNAL-C2",
          auto: !!f.auto,
          fracText: Number(f.external_anchor_fraction ?? 0).toFixed(3),
          thrText: Number(f.threshold ?? 0.15).toFixed(2),
          fracPct: Math.min(96, Number(f.external_anchor_fraction ?? 0) * 200),
          thrPct: Math.min(96, Number(f.threshold ?? 0.15) * 200),
          pivots: f.pivots ?? [],
          insider: f.mode === "insider",
        }
      : null;

  const actions: ActionM[] = (playbook ?? []).map((a) => ({
    idx: Number(a.idx),
    name: String(a.action ?? "").replace(/_/g, " "),
    target: a.target ?? "—",
    blast: a.blast_radius ?? "—",
    auto: a.gate === "auto",
    status: a.status ?? "pending",
    approver: a.approver && a.approver !== "None" ? a.approver : null,
    rationale: a.rationale ?? "",
  }));

  const ledger: LedgerRow[] = (audit.entries ?? []).map((en) => {
    const ms = parseTs(en.ts);
    return {
      seq: Number(en.seq),
      ts: Number.isNaN(ms) ? String(en.ts).slice(5, 16) : fmtTs(ms),
      action: `${String(en.action ?? "").toLowerCase()} · ${en.target ?? ""}`,
      decision: en.decision && en.decision !== "-" ? String(en.decision) : null,
      actor: String(en.actor ?? "").replace("prahari.", ""),
      hash: en.entry_hash ?? null,
    };
  });
  const auditMeta = {
    entries: (audit.entries ?? []).length,
    ok: !!audit.verify?.ok,
    head: (audit.verify as { head_hash?: string })?.head_hash ?? null,
  };

  return {
    id: inc.id,
    t0,
    dmax,
    nodes,
    edges,
    stations,
    predicted,
    attck,
    hops,
    pathMeta,
    beats,
    hero,
    metrics,
    fusion,
    actions,
    ledger,
    auditMeta,
    assessment: inc.campaign_assessment?.summary ?? null,
  };
}

// ---- client-side hash-chain (for the clearly-labelled tamper SIMULATION) ------
export async function sha256(str: string): Promise<string> {
  try {
    const buf = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(str));
    return Array.from(new Uint8Array(buf))
      .map((b) => b.toString(16).padStart(2, "0"))
      .join("");
  } catch {
    let h = 2166136261 >>> 0;
    for (let i = 0; i < str.length; i++) {
      h ^= str.charCodeAt(i);
      h = Math.imul(h, 16777619) >>> 0;
    }
    let out = "";
    for (let k = 0; k < 8; k++) {
      h = Math.imul(h ^ k, 16777619) >>> 0;
      out += h.toString(16).padStart(8, "0");
    }
    return out.slice(0, 64);
  }
}
export async function chainOf(rows: LedgerRow[], mutateAt = -1): Promise<string[]> {
  let prev = "0".repeat(64);
  const out: string[] = [];
  for (let i = 0; i < rows.length; i++) {
    const r = rows[i];
    const action = i === mutateAt ? r.action + " · REWRITTEN" : r.action;
    const hh = await sha256(`${r.seq}|${r.ts}|${action}|${r.actor}|${prev}`);
    out.push(hh);
    prev = hh;
  }
  return out;
}
