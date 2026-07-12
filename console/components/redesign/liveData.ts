/* eslint-disable @typescript-eslint/no-explicit-any */
// Live-data layer for the redesigned console: fetches the real PRAHARI BFF
// (:8000) and maps every endpoint into the exact shapes the design renders.
// The graph keeps the design's key insight — a hand-authored layout — by
// mapping real node ids onto the same coordinates (files match by basename;
// unknown ids get parked context slots). Honest-viz holds throughout: edge
// heat is the system's own anomaly_score; gt `malicious` feeds only the
// eval-only overlay.
import { api } from "@/lib/api";
import { parseTs } from "@/lib/replay";

export const INCIDENT_ID = "INC-001";
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
};

const TACTIC_LABEL: Record<string, string> = {
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
};

const ATTCK_COLS = [
  "Initial Access",
  "Persistence",
  "Defense Evasion",
  "Credential Access",
  "Lateral Movement",
  "Collection",
  "Command & Control",
  "Exfiltration",
  "Impact",
];

// hand layout (1040×640 viewBox) — same coordinates the design authored,
// keyed by id or file basename; spare slots park anything unexpected.
const POS: Record<string, [number, number]> = {
  "exam.clerk": [88, 150],
  WS03: [250, 206],
  DC01: [520, 182],
  "DB-EXAMS": [790, 208],
  "203.0.113.66": [972, 150],
  "admin.it": [520, 82],
  "db.service": [800, 92],
  "out.dmp": [250, 334],
  "rundll32.exe": [126, 288],
  "powershell.exe": [392, 298],
  pg_dump: [686, 330],
  "7z.exe": [900, 322],
  "exam-records.7z": [806, 344],
  "backup.sh": [912, 256],
  vacuumdb: [690, 414],
  postgres: [760, 436],
  "winword.exe": [120, 452],
  "chrome.exe": [210, 498],
  "outlook.exe": [308, 460],
  "teams.exe": [404, 500],
  "excel.exe": [498, 462],
  "onedrive.exe": [592, 502],
  "explorer.exe": [672, 470],
  "results_draft.docx": [170, 556],
  "daily_report.csv": [344, 560],
  "circular.pdf": [502, 560],
  "10.10.0.10": [606, 412],
  "10.10.0.20": [414, 410],
};
const PARKED: [number, number][] = [
  [660, 556],
  [884, 556],
  [962, 470],
  [62, 52],
  [178, 52],
  [298, 52],
  [64, 388],
  [938, 96],
];

function base(id: string): string {
  const b = id.split(/[\\/|]/).pop();
  return b && b.length ? b : id;
}
const MONTHS = ["Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"];
const p2 = (n: number) => String(n).padStart(2, "0");
const fmtMD = (ms: number) => {
  const d = new Date(ms);
  return `${MONTHS[d.getUTCMonth()]} ${p2(d.getUTCDate())}`;
};
const fmtTs = (ms: number) => {
  const d = new Date(ms);
  return `${p2(d.getUTCMonth() + 1)}-${p2(d.getUTCDate())} ${p2(d.getUTCHours())}:${p2(d.getUTCMinutes())}`;
};

export async function fetchLive(): Promise<any | null> {
  try {
    const [slate, inc, graph, playbook, audit, list]: any[] = await Promise.all([
      api.slate(),
      api.incident(INCIDENT_ID),
      api.graph(INCIDENT_ID),
      api.playbook(INCIDENT_ID),
      api.audit(),
      api.incidents(),
    ]);

    // ---- replay window ------------------------------------------------------
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
    const confirmedMs = parseTs(inc?.mttd?.confirmed_at ?? "");

    const nodeType: Record<string, string> = {};
    for (const n of graph.nodes) nodeType[n.id] = n.type;
    const isHost = (id: string) => nodeType[id] === "Host";
    const isExt = (id: string) => nodeType[id] === "IP" && !id.startsWith("10.");

    // ---- nodes: heat/first-seen from touching edges, hand positions ---------
    // Node heat is the MEAN OF THE TOP-2 edge anomaly scores, not the max:
    // real UEBA gives benign day-1 edges loud cold-start novelty, so a single
    // loud edge shouldn't paint a whole entity red — repeated flags should.
    // (Still purely the system's own scores; gt never enters.)
    const touch: Record<string, { scores: number[]; ms: number }> = {};
    for (const e of graph.edges) {
      const ms = parseTs(e.ts);
      const a = e.anomaly_score ?? 0;
      for (const id of [e.source, e.target]) {
        const t = touch[id] ?? (touch[id] = { scores: [], ms: Infinity });
        t.scores.push(a);
        if (!Number.isNaN(ms)) t.ms = Math.min(t.ms, ms);
      }
    }
    const top2 = (xs: number[]) => {
      const s = [...xs].sort((a, b) => b - a);
      return s.length >= 2 ? (s[0] + s[1]) / 2 : (s[0] ?? 0);
    };
    let pk = 0;
    const nodes = graph.nodes.map((n: any) => {
      const lb = base(n.id);
      const pos = POS[n.id] ?? POS[lb] ?? PARKED[Math.min(pk++, PARKED.length - 1)];
      const t = touch[n.id] ?? { scores: [0], ms: t0 };
      return {
        id: n.id,
        label: lb,
        type: String(n.type).toLowerCase(),
        score: top2(t.scores),
        day: dayOf(t.ms),
        x: pos[0],
        y: pos[1],
        star: n.id === "DB-EXAMS",
        c2: isExt(n.id),
      };
    });

    // ---- edges: heat = system's own anomaly; spine = its strongest signals --
    const isSpine = (e: any) => {
      const a = e.anomaly_score ?? 0;
      if (e.type === "REACHED" && a >= 0.7) return true;
      if ((e.type === "AUTH" || e.type === "CONNECTED_TO") && a >= 0.9) return true;
      return false;
    };
    const edges = graph.edges.map((e: any, i: number) => {
      const ms = parseTs(e.ts);
      const a = e.anomaly_score ?? 0;
      const prevented = e.technique === "T1041" && isExt(e.target);
      const confirmed =
        e.technique === "T1078" && !Number.isNaN(ms) && Math.abs(ms - confirmedMs) < 36 * 3600e3;
      return {
        id: "le" + i,
        s: e.source,
        t: e.target,
        tech: e.technique ?? null,
        techName: e.technique ? (TECH_NAMES[e.technique] ?? e.type) : e.type,
        score: a,
        day: dayOf(ms),
        ts: Number.isNaN(ms) ? "" : fmtTs(ms),
        spine: isSpine(e),
        mal: !!e.malicious, // eval-only overlay, never the base coloring
        prevented,
        verdict: confirmed ? "confirmed" : undefined,
        evt: e.event_id ? String(e.event_id).slice(0, 8) : null,
        reasons: Array.isArray(e.reasons) ? e.reasons : [],
      };
    });

    // ---- kill chain stations (dedupe, onsets/hosts from technique edges) ----
    const seen = new Set<string>();
    const kc = (inc.kill_chain ?? []).filter((k: any) => {
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
    const techniques = kc.map((k: any, i: number) => {
      const r = perTech[k.technique_id] ?? {
        ms: t0 + ((t1 - t0) * i) / Math.max(1, lastIdx),
        score: 0.6,
        host: "—",
      };
      const confirmed = k.technique_id === "T1078" && Math.abs(r.ms - confirmedMs) < 36 * 3600e3;
      const prevented = i === lastIdx;
      return {
        n: i + 1,
        id: k.technique_id,
        name: TECH_NAMES[k.technique_id] ?? "",
        tactic: TACTIC_LABEL[k.tactic] ?? k.tactic,
        host: r.host,
        date: fmtMD(r.ms),
        day: dayOf(r.ms),
        score: r.score,
        verdict: confirmed ? "confirmed · contained" : prevented ? "exfil prevented" : undefined,
        prevented,
        // the report's narrative embeds its build-time date — the chapter row
        // shows the real per-edge date already, so strip the stale prefix
        evidence: String(k.narrative ?? "").replace(/^\[\d{4}-\d{2}-\d{2}\]\s*/, ""),
        advisory: "MITRE ATT&CK " + k.technique_id,
      };
    });

    // ---- predicted next moves ------------------------------------------------
    const predicted = (inc.next_moves ?? []).map((m: any) => ({
      id: m.predicted_technique,
      name: TECH_NAMES[m.predicted_technique] ?? m.predicted_technique,
      tactic: TACTIC_LABEL[m.tactic] ?? m.tactic ?? "Impact",
      advisory: "MITRE ATT&CK " + m.predicted_technique,
      rationale: m.rationale ?? "",
      defend: m.recommended_defensive_action ?? "",
    }));

    // ---- ATT&CK matrix --------------------------------------------------------
    const colCells: Record<string, any[]> = {};
    for (const c of ATTCK_COLS) colCells[c] = [];
    for (const t of techniques) {
      const col = colCells[t.tactic] ? t.tactic : "Defense Evasion";
      const cell: any = {
        k: t.verdict === "confirmed · contained" ? "con" : "obs",
        tid: t.id,
        name: t.name || t.id,
      };
      if (t.verdict === "confirmed · contained") cell.note = "confirmed · contained";
      if (t.prevented) {
        cell.note = "PREVENTED";
        cell.prevented = true;
      }
      colCells[col].push(cell);
    }
    for (const p of predicted) {
      const col = colCells[p.tactic] ? p.tactic : "Impact";
      const suffix = p.id === "T1041" ? " · retry" : p.id === "T1078" ? " · re-entry" : "";
      colCells[col].push({ k: "pred", tid: p.id, name: (p.name || p.id) + suffix });
    }
    const attckDef = ATTCK_COLS.map((c) => ({ t: c, cells: colCells[c] }));

    // ---- lateral path hops ----------------------------------------------------
    const reach: Record<string, any> = {};
    for (const e of graph.edges) {
      if (e.type !== "REACHED" || (e.anomaly_score ?? 0) < 0.7) continue;
      const ms = parseTs(e.ts);
      if (Number.isNaN(ms)) continue;
      const key = e.source + ">" + e.target;
      if (!reach[key] || ms < reach[key].ms)
        reach[key] = { s: e.source, t: e.target, ms, reasons: e.reasons ?? [] };
    }
    const hops = Object.values(reach).sort((a: any, b: any) => a.ms - b.ms);
    const credFor = (hop: any) => {
      let best: any = null;
      for (const e of graph.edges) {
        if (e.type !== "AUTH" || e.target !== hop.t) continue;
        const ms = parseTs(e.ts);
        if (Number.isNaN(ms) || Math.abs(ms - hop.ms) > 2 * 3600e3) continue;
        if (!best || (e.anomaly_score ?? 0) > best.a) best = { u: e.source, a: e.anomaly_score ?? 0 };
      }
      return best ? best.u : "—";
    };
    const pathHopsDef = hops.map((h: any, i: number) => ({
      n: i + 1,
      to: h.t,
      cred: credFor(h),
      tech: "T1021",
      date: fmtMD(h.ms),
      day: dayOf(h.ms),
      detail: h.reasons[0] ?? "first-seen lateral session in the baseline",
    }));
    const exfilMs = perTech["T1041"]?.ms;
    const attackMs = parseTs(inc?.mttd?.attack_start ?? "");
    const pathMeta = {
      start: inc.lateral_path?.[0] ?? "WS03",
      startDetail: `Patient zero — phished ${Number.isNaN(attackMs) ? "" : fmtMD(attackMs)}; credentials later dumped and replayed from here.`,
      exfilIp: inc.external_ips?.[0] ?? "—",
      exfilDate: exfilMs ? fmtMD(exfilMs) : "—",
      exfilDetail: `${base(edges.find((e: any) => e.prevented)?.t ?? "the archive")} never left the building — the C2 channel was already severed ${Number.isNaN(confirmedMs) ? "" : "on " + fmtMD(confirmedMs)}.`,
    };

    // ---- replay beats (all derived from the data) ------------------------------
    const md = (ms: number) => fmtTs(ms).slice(0, 5);
    const beats: any[] = [];
    if (!Number.isNaN(attackMs)) beats.push({ date: md(attackMs), day: dayOf(attackMs), label: "Foothold" });
    if (!Number.isNaN(confirmedMs))
      beats.push({ date: md(confirmedMs), day: dayOf(confirmedMs), label: "Confirmed", key: "confirmed" });
    for (const h of hops as any[]) beats.push({ date: md(h.ms), day: dayOf(h.ms), label: "→ " + base(h.t) });
    if (perTech["T1560"])
      beats.push({ date: md(perTech["T1560"].ms), day: dayOf(perTech["T1560"].ms), label: "Staging" });
    if (exfilMs) beats.push({ date: md(exfilMs), day: dayOf(exfilMs), label: "Exfil ✕", key: "prevented" });

    // ---- slate → metric tiles ---------------------------------------------------
    const u = slate.ueba ?? {};
    const at = slate.attribution ?? {};
    const so = slate.soar ?? {};
    const mt = slate.mttd ?? {};
    const mr = slate.mttr ?? {};
    const au = slate.auditability ?? {};
    const lat = Number(mr.auto_containment_latency_seconds ?? 0);
    const metricTargets = {
      roc: Number(u.roc_auc ?? 0),
      recall: Math.round(Number(u.recall_at_1pct_fpr ?? 0) * 100),
      tech: Number(at.technique_accuracy_pct ?? 0),
      auto: Number(so.automation_coverage_pct ?? 0),
      mttd: Number(mt.mttd_days_after_foothold ?? 0),
      mttrText: lat < 1 ? "< 1 s" : `${lat.toFixed(2)} s`,
    };
    const metricSubs = {
      roc: `${u.malicious ?? "—"} malicious / ${u.benign ?? "—"} benign`,
      auto: `${so.auto ?? "—"} auto / ${so.gated ?? "—"} human-gated`,
      audit: `${au.ledger_entries ?? "—"}-entry hash chain`,
    };

    // ---- verdict hero -------------------------------------------------------------
    const second = (list ?? []).map((x: any) => Number(x.score)).sort((a: number, b: number) => b - a)[1];
    const hero = {
      mttd: String(mt.mttd_days_after_foothold ?? "—"),
      confirmedDate: String(mt.confirmed_at ?? "").slice(0, 10),
      dwell: String(mt.dwell_days_before_exfil ?? "—"),
      exfilMonth: exfilMs ? fmtMD(exfilMs).replace(" ", "-") : "—",
      score: Number(inc.score ?? 0).toFixed(2),
      ratio: second ? `${Math.round(Number(inc.score) / second)}×` : "—",
      spanDays: String(inc.span_days ?? "—"),
      nEvents: Number(inc.n_events ?? 0),
      hostsText: (inc.hosts ?? []).join(" · "),
      usersCount: (inc.users ?? []).length,
    };

    // ---- correlation strip ----------------------------------------------------------
    const f = slate.fusion ?? {};
    const frac = Number(f.external_anchor_fraction ?? 0);
    const thr = Number(f.threshold ?? 0.15);
    const fusionView = {
      label: f.mode === "insider" ? "INSIDER" : "EXTERNAL-C2",
      auto: !!f.auto,
      fracText: frac.toFixed(3),
      thrText: thr.toFixed(2),
      fracPct: Math.min(96, frac * 200),
      thrPct: Math.min(96, thr * 200),
      pivots: Array.isArray(f.pivots) ? f.pivots : [],
      insider: f.mode === "insider",
    };

    // ---- SOAR actions -----------------------------------------------------------------
    const actions = (playbook ?? []).map((a: any) => ({
      idx: Number(a.idx),
      name: String(a.action ?? "").replace(/_/g, " "),
      target: a.target ?? "—",
      blast: a.blast_radius ?? "—",
      auto: a.gate === "auto",
      status: a.status ?? "pending",
      approver: a.approver && a.approver !== "None" ? a.approver : null,
      rationale: a.rationale ?? "",
    }));

    // ---- ledger --------------------------------------------------------------------------
    const ledgerDef = (audit.entries ?? []).map((en: any) => {
      const ms = parseTs(en.ts);
      return {
        seq: Number(en.seq),
        ts: Number.isNaN(ms) ? String(en.ts).slice(5, 16) : fmtTs(ms),
        action: `${String(en.action ?? "").toLowerCase()} · ${en.target ?? ""}`,
        actor: String(en.actor ?? "").replace("prahari.", ""),
        decision: en.decision && en.decision !== "-" ? String(en.decision) : null,
        blast: en.blast_radius ?? null,
        hash: en.entry_hash ?? null,
      };
    });
    const auditMeta = {
      entries: (audit.entries ?? []).length,
      ok: !!audit.verify?.ok,
      head: audit.verify?.head_hash ?? null,
    };

    const assessment = inc.campaign_assessment?.summary ?? null;

    return {
      t0,
      dmax,
      nodes,
      edges,
      techniques,
      predicted,
      attckDef,
      pathHopsDef,
      pathMeta,
      beats,
      metricTargets,
      metricSubs,
      hero,
      fusionView,
      actions,
      ledgerDef,
      auditMeta,
      assessment,
      nEvents: hero.nEvents,
    };
  } catch {
    return null;
  }
}

export async function postDecision(idx: number, decision: "approve" | "deny"): Promise<boolean> {
  try {
    await api.decision(INCIDENT_ID, idx, { decision, approver: "analyst@prahari-console" });
    return true;
  } catch {
    return false;
  }
}
