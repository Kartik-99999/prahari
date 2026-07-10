"use client";
/* eslint-disable @typescript-eslint/no-explicit-any */
// Faithful port of the Claude-Design "PRAHARI Console.dc.html" into the app.
// The design authors styles as CSS strings and builds the provenance graph with
// React.createElement; both are kept as-is for fidelity. Figures are honest
// reconstructions of INC-001; the graph is coloured by the system's own computed
// anomaly score (never the ground-truth label), matching the honest-viz rule.
import React from "react";

const MONO = "var(--font-jetbrains), 'JetBrains Mono', monospace";
const SANS = "var(--font-inter), 'Inter', system-ui, sans-serif";

// Parse a CSS declaration string into a React style object; remap the design's
// font-family literals onto the console's next/font CSS variables.
function s(css: string): React.CSSProperties {
  const o: any = {};
  for (const decl of css.split(";")) {
    const i = decl.indexOf(":");
    if (i < 0) continue;
    const k = decl.slice(0, i).trim();
    if (!k) continue;
    o[k.replace(/-([a-z])/g, (_m, c) => c.toUpperCase())] = decl.slice(i + 1).trim();
  }
  if (o.fontFamily) {
    if (/JetBrains Mono/.test(o.fontFamily)) o.fontFamily = "var(--font-jetbrains)," + o.fontFamily;
    else if (/Inter/.test(o.fontFamily)) o.fontFamily = "var(--font-inter)," + o.fontFamily;
  }
  return o as React.CSSProperties;
}

type State = {
  playDay: number;
  playing: boolean;
  speed: number;
  lens: string;
  hovered: string | null;
  sel: any;
  overlayGT: boolean;
  countP: number;
  rm: boolean;
  chain: any;
  chainT: any;
  brokenFrom: number;
  tamperOn: boolean;
};

export default class RedesignConsole extends React.Component<Record<string, never>, State> {
  RATE = 2.4;
  nodes: any[] = [];
  edges: any[] = [];
  techniques: any[] = [];
  predicted: any[] = [];
  attckDef: any[] = [];
  pathHopsDef: any[] = [];
  metricsDef: any[] = [];
  beatsDef: any[] = [];
  actionsDef: any[] = [];
  ledgerDef: any[] = [];
  ledgerTampered: any[] = [];
  _nmap: any = {};
  _t0: number | null = null;
  _last: number | null = null;
  _raf = 0;

  constructor(props: any) {
    super(props);
    this.state = {
      playDay: 20,
      playing: false,
      speed: 1,
      lens: "story",
      hovered: null,
      sel: null,
      overlayGT: false,
      countP: 0,
      rm: false,
      chain: null,
      chainT: null,
      brokenFrom: 3,
      tamperOn: false,
    };

    this.nodes = [
      { id: "exam.clerk", label: "exam.clerk", type: "user", score: 0.86, day: 1, x: 88, y: 150 },
      { id: "WS03", label: "WS03", type: "host", score: 0.91, day: 1, x: 250, y: 206 },
      { id: "DC01", label: "DC01", type: "host", score: 0.88, day: 8, x: 520, y: 182 },
      { id: "DB-EXAMS", label: "DB-EXAMS", type: "host", score: 0.95, day: 12, x: 790, y: 208, star: true },
      { id: "203.0.113.66", label: "203.0.113.66", type: "ip", score: 0.99, day: 2, x: 972, y: 150, c2: true },
      { id: "out.dmp", label: "out.dmp", type: "file", score: 0.9, day: 4, x: 250, y: 334 },
      { id: "rundll32.exe", label: "rundll32.exe", type: "process", score: 0.72, day: 1, x: 126, y: 288 },
      { id: "powershell.exe", label: "powershell.exe", type: "process", score: 0.62, day: 8, x: 392, y: 298 },
      { id: "admin.it", label: "admin.it", type: "user", score: 0.7, day: 8, x: 520, y: 82 },
      { id: "db.service", label: "db.service", type: "user", score: 0.66, day: 12, x: 800, y: 92 },
      { id: "pg_dump", label: "pg_dump", type: "process", score: 0.83, day: 18, x: 686, y: 330 },
      { id: "7z.exe", label: "7z.exe", type: "process", score: 0.8, day: 18, x: 900, y: 322 },
      { id: "exam-records.7z", label: "exam-records.7z", type: "file", score: 0.93, day: 18, x: 806, y: 344 },
      { id: "backup.sh", label: "backup.sh", type: "process", score: 0.48, day: 18, x: 912, y: 256 },
      { id: "vacuumdb", label: "vacuumdb", type: "process", score: 0.33, day: 15, x: 690, y: 414 },
      { id: "winword.exe", label: "winword.exe", type: "process", score: 0.08, day: 0, x: 120, y: 452 },
      { id: "chrome.exe", label: "chrome.exe", type: "process", score: 0.05, day: 0, x: 210, y: 498 },
      { id: "outlook.exe", label: "outlook.exe", type: "process", score: 0.07, day: 0, x: 308, y: 460 },
      { id: "teams.exe", label: "teams.exe", type: "process", score: 0.06, day: 0, x: 404, y: 500 },
      { id: "excel.exe", label: "excel.exe", type: "process", score: 0.09, day: 0, x: 498, y: 462 },
      { id: "onedrive.exe", label: "onedrive.exe", type: "process", score: 0.05, day: 0, x: 592, y: 502 },
      { id: "explorer.exe", label: "explorer.exe", type: "process", score: 0.04, day: 0, x: 672, y: 470 },
      { id: "results_draft.docx", label: "results_draft.docx", type: "file", score: 0.1, day: 0, x: 170, y: 556 },
      { id: "daily_report.csv", label: "daily_report.csv", type: "file", score: 0.08, day: 0, x: 344, y: 560 },
      { id: "circular.pdf", label: "circular.pdf", type: "file", score: 0.06, day: 0, x: 502, y: 560 },
      { id: "10.10.0.10", label: "10.10.0.10", type: "ip", score: 0.12, day: 0, x: 606, y: 412 },
      { id: "10.10.0.20", label: "10.10.0.20", type: "ip", score: 0.14, day: 0, x: 414, y: 410 },
    ];

    this.edges = [
      { id: "e1", s: "exam.clerk", t: "WS03", tech: "T1566", techName: "Phishing", score: 0.87, day: 1, ts: "05-02 09:41", spine: true, mal: true, evt: "EVT-4102", reasons: ["Macro-enabled attachment opened by exam.clerk", "Sender domain first-seen in prior 90 days", "Document immediately spawned rundll32.exe"] },
      { id: "e2", s: "WS03", t: "203.0.113.66", tech: "T1071", techName: "Application Layer Protocol", score: 0.95, day: 2, ts: "05-03 02:14", spine: true, mal: true, evt: "EVT-4118", reasons: ["Periodic HTTPS beacon · 60s ± jitter", "Destination ASN never seen in baseline", "TLS JA3 matches a tracked C2 profile"] },
      { id: "e3", s: "WS03", t: "DC01", tech: "T1021", techName: "Remote Services", score: 0.9, day: 8, ts: "05-09 03:14", spine: true, mal: true, evt: "EVT-4207", reasons: ["admin.it NTLM auth WS03 → DC01 at 03:14 (off-hours)", "No WS03 → DC01 authentication in prior 90 days", "Hash reuse consistent with out.dmp"] },
      { id: "e4", s: "DC01", t: "DB-EXAMS", tech: "T1021", techName: "Remote Services", score: 0.93, day: 12, ts: "05-13 21:58", spine: true, mal: true, evt: "EVT-4288", reasons: ["db.service session DC01 → DB-EXAMS", "First DC01 → DB-EXAMS session in the baseline", "Immediate access to the exam_records schema"] },
      { id: "e5", s: "DB-EXAMS", t: "203.0.113.66", tech: "T1041", techName: "Exfiltration Over C2", score: 0.97, day: 20, ts: "05-21 06:02", spine: true, mal: true, prevented: true, evt: "EVT-4401", reasons: ["exam-records.7z queued for outbound transfer", "Destination = tracked C2 203.0.113.66", "BLOCKED — C2 channel severed at confirmation (05-04)"] },
      { id: "e6", s: "WS03", t: "out.dmp", tech: "T1003", techName: "OS Credential Dumping", score: 0.9, day: 4, ts: "05-05 01:37", mal: true, evt: "EVT-4155", reasons: ["rundll32.exe accessed lsass memory", "out.dmp written to C:\\Windows\\Temp", "Credential material extracted"] },
      { id: "e9", s: "DB-EXAMS", t: "exam-records.7z", tech: "T1560", techName: "Archive Collected Data", score: 0.9, day: 18, ts: "05-19 14:32", mal: true, evt: "EVT-4356", reasons: ["pg_dump export of exam_records", "7z.exe compressed the dump into an archive", "Archive staged in temp for exfil"] },
      { id: "e12", s: "admin.it", t: "DC01", tech: "T1078", techName: "Valid Accounts", score: 0.7, day: 3, ts: "05-04 03:17", mal: true, evt: "EVT-4141", verdict: "confirmed", reasons: ["Privileged account used off-hours", "Anomalous source host (WS03)", "Confirmation beat → auto-containment triggered"] },
      { id: "e10", s: "pg_dump", t: "DB-EXAMS", tech: "T1560", techName: "Process", score: 0.83, day: 18, ts: "05-19 14:30", mal: true, evt: "EVT-4351", reasons: ["Unscheduled pg_dump on the crown-jewel DB", "Run by db.service outside any maintenance window"] },
      { id: "e11", s: "7z.exe", t: "exam-records.7z", tech: "T1560", techName: "Process", score: 0.8, day: 18, ts: "05-19 14:33", mal: true, evt: "EVT-4353", reasons: ["Archive utility invoked by a non-interactive session", "Output matches the staged-exfil pattern"] },
      { id: "e13", s: "db.service", t: "DB-EXAMS", tech: "T1078", techName: "Valid Accounts", score: 0.66, day: 12, ts: "05-13 21:57", mal: true, evt: "EVT-4285", reasons: ["Service account used interactively", "Source host DC01 is anomalous for this identity"] },
      { id: "e7", s: "rundll32.exe", t: "WS03", tech: "T1204", techName: "Execution", score: 0.72, day: 1, ts: "05-02 09:42", mal: true, evt: "EVT-4104", reasons: ["Spawned by a winword.exe macro", "Living-off-the-land execution pattern"] },
      { id: "e8", s: "powershell.exe", t: "DC01", tech: "T1059", techName: "Execution", score: 0.62, day: 8, ts: "05-09 03:20", mal: true, evt: "EVT-4212", reasons: ["Encoded command line", "Retrieved a remote payload"] },
      { id: "e14", s: "out.dmp", t: "DC01", tech: "T1550", techName: "Use Alternate Auth", score: 0.75, day: 8, ts: "05-09 03:14", mal: true, evt: "EVT-4205", reasons: ["Credentials from out.dmp replayed against DC01", "Pass-the-hash indicators"] },
      { id: "e15", s: "backup.sh", t: "DB-EXAMS", tech: "T1059", techName: "Execution", score: 0.48, day: 18, ts: "05-18 23:11", mal: true, evt: "EVT-4340", reasons: ["Unrecognized script on the DB host", "Weak signal — flagged for review"] },
      { id: "b1", s: "exam.clerk", t: "outlook.exe", score: 0.07, day: 0 },
      { id: "b2", s: "exam.clerk", t: "chrome.exe", score: 0.05, day: 0 },
      { id: "b3", s: "exam.clerk", t: "winword.exe", score: 0.08, day: 0 },
      { id: "b4", s: "WS03", t: "teams.exe", score: 0.06, day: 0 },
      { id: "b5", s: "WS03", t: "excel.exe", score: 0.09, day: 0 },
      { id: "b6", s: "WS03", t: "onedrive.exe", score: 0.05, day: 0 },
      { id: "b7", s: "DC01", t: "explorer.exe", score: 0.04, day: 0 },
      { id: "b8", s: "WS03", t: "results_draft.docx", score: 0.1, day: 0 },
      { id: "b9", s: "WS03", t: "daily_report.csv", score: 0.08, day: 0 },
      { id: "b10", s: "DC01", t: "circular.pdf", score: 0.06, day: 0 },
      { id: "b11", s: "WS03", t: "10.10.0.10", score: 0.12, day: 0 },
      { id: "b12", s: "DC01", t: "10.10.0.20", score: 0.14, day: 0 },
      { id: "b13", s: "db.service", t: "vacuumdb", score: 0.33, day: 15 },
    ];

    this.techniques = [
      { n: 1, id: "T1566", name: "Phishing", tactic: "Initial Access", host: "WS03", date: "May 02", day: 1, score: 0.87, edge: "e1", evidence: "Macro-enabled email opened by exam.clerk; the document spawned rundll32.exe.", advisory: "MITRE ATT&CK T1566 · CISA AA22-321A" },
      { n: 2, id: "T1071", name: "Application Layer Protocol", tactic: "Command & Control", host: "WS03", date: "May 03", day: 2, score: 0.95, edge: "e2", evidence: "Periodic HTTPS beacon to 203.0.113.66; JA3 matches a tracked C2.", advisory: "MITRE ATT&CK T1071" },
      { n: 3, id: "T1078", name: "Valid Accounts", tactic: "Defense Evasion / Persistence", host: "DC01", date: "May 04", day: 3, score: 0.7, edge: "e12", verdict: "confirmed · contained", evidence: "admin.it used off-hours from WS03 — the confirmation beat. Auto-containment fired here.", advisory: "MITRE ATT&CK T1078 · NSA identity hardening" },
      { n: 4, id: "T1003", name: "OS Credential Dumping", tactic: "Credential Access", host: "WS03", date: "May 05", day: 4, score: 0.9, edge: "e6", evidence: "rundll32.exe read lsass; out.dmp written to temp.", advisory: "MITRE ATT&CK T1003 · CISA #StopRansomware" },
      { n: 5, id: "T1021", name: "Remote Services", tactic: "Lateral Movement", host: "DC01 → DB-EXAMS", date: "May 09", day: 8, score: 0.93, edge: "e3", evidence: "WS03 → DC01 then DC01 → DB-EXAMS, both first-seen paths, with hash reuse.", advisory: "MITRE ATT&CK T1021" },
      { n: 6, id: "T1560", name: "Archive Collected Data", tactic: "Collection", host: "DB-EXAMS", date: "May 19", day: 18, score: 0.9, edge: "e9", evidence: "pg_dump of exam_records; 7z.exe staged exam-records.7z.", advisory: "MITRE ATT&CK T1560" },
      { n: 7, id: "T1041", name: "Exfiltration Over C2", tactic: "Exfiltration", host: "DB-EXAMS", date: "May 21", day: 20, score: 0.97, edge: "e5", verdict: "exfil prevented", prevented: true, evidence: "Outbound of exam-records.7z to C2 — BLOCKED; the channel was already severed on 05-04.", advisory: "MITRE ATT&CK T1041 · CISA data-exfil advisory" },
    ];

    this.predicted = [
      { id: "T1070", name: "Indicator Removal", tactic: "Defense Evasion", advisory: "MITRE ATT&CK T1070" },
      { id: "T1486", name: "Data Encrypted for Impact", tactic: "Impact", advisory: "MITRE ATT&CK T1486 · CISA #StopRansomware" },
      { id: "T1078", name: "Valid Accounts · re-entry", tactic: "Persistence", advisory: "MITRE ATT&CK T1078" },
      { id: "T1041", name: "Exfiltration retry", tactic: "Exfiltration", advisory: "MITRE ATT&CK T1041" },
    ];

    this.attckDef = [
      { t: "Initial Access", cells: [{ k: "obs", tid: "T1566", name: "Phishing" }] },
      { t: "Persistence", cells: [{ k: "pred", tid: "T1078", name: "Valid Accounts · re-entry" }] },
      { t: "Defense Evasion", cells: [{ k: "con", tid: "T1078", name: "Valid Accounts", note: "confirmed · contained" }, { k: "pred", tid: "T1070", name: "Indicator Removal" }] },
      { t: "Credential Access", cells: [{ k: "obs", tid: "T1003", name: "OS Cred Dumping" }] },
      { t: "Lateral Movement", cells: [{ k: "obs", tid: "T1021", name: "Remote Services" }] },
      { t: "Collection", cells: [{ k: "obs", tid: "T1560", name: "Archive Data" }] },
      { t: "Command & Control", cells: [{ k: "obs", tid: "T1071", name: "App-Layer Protocol" }] },
      { t: "Exfiltration", cells: [{ k: "obs", tid: "T1041", name: "Exfil Over C2", note: "PREVENTED", prevented: true }, { k: "pred", tid: "T1041", name: "Exfil retry" }] },
      { t: "Impact", cells: [{ k: "pred", tid: "T1486", name: "Data Encrypted" }] },
    ];

    this.pathHopsDef = [
      { n: 1, to: "DC01", cred: "admin.it", tech: "T1021", date: "May 09", day: 8, detail: "Off-hours NTLM auth on a path never seen in 90 days; credentials sourced from out.dmp." },
      { n: 2, to: "DB-EXAMS", cred: "db.service", tech: "T1021", date: "May 13", day: 12, detail: "First DC01 → DB-EXAMS session in the baseline; immediate reach into the exam_records schema." },
    ];

    this.metricsDef = [
      { key: "roc", label: "UEBA ROC-AUC", sub: "13 malicious / 2115 benign" },
      { key: "recall", label: "Recall @ 1% FPR", sub: "weak-signal detection" },
      { key: "tech", label: "Technique accuracy", sub: "0 false attributions" },
      { key: "auto", label: "Automation coverage", sub: "6 auto / 2 human-gated" },
      { key: "mttd", label: "MTTD", sub: "vs ~200 d industry" },
      { key: "mttr", label: "MTTR", sub: "auto-containment" },
      { key: "audit", label: "Audit", sub: "10-entry hash chain" },
    ];

    this.beatsDef = [
      { date: "05-02", day: 1, label: "Foothold" },
      { date: "05-04", day: 3, label: "Confirmed", key: "confirmed" },
      { date: "05-09", day: 8, label: "→ DC01" },
      { date: "05-13", day: 12, label: "→ DB-EXAMS" },
      { date: "05-19", day: 18, label: "Staging" },
      { date: "05-21", day: 20, label: "Exfil ✕", key: "prevented" },
    ];

    this.actionsDef = [
      { name: "Sever C2 channel", target: "block 203.0.113.66", mode: "auto", blast: "1 egress rule" },
      { name: "Quarantine WS03", target: "clerk workstation", mode: "auto", blast: "1 host · 1 session" },
      { name: "Revoke exam.clerk sessions", target: "identity", mode: "auto", blast: "1 identity" },
      { name: "Block macro execution", target: "GPO org-wide", mode: "auto", blast: "org policy" },
      { name: "Snapshot DB-EXAMS", target: "forensic image", mode: "auto", blast: "1 volume" },
      { name: "Kill pg_dump / 7z.exe", target: "DB-EXAMS processes", mode: "auto", blast: "2 processes" },
      { name: "Isolate DB-EXAMS", target: "crown-jewel database", mode: "human", blast: "exam ops · crown jewel" },
      { name: "Disable admin.it", target: "privileged identity", mode: "human", blast: "IT ops · 1 privileged id" },
    ];

    this.ledgerDef = [
      { seq: 1, ts: "05-01 00:00", action: "incident.open · INC-001", actor: "system" },
      { seq: 2, ts: "05-02 09:41", action: "ingest.foothold · WS03", actor: "system" },
      { seq: 3, ts: "05-04 03:17", action: "detect.confirm · T1078 · MTTD 1.66d", actor: "ueba" },
      { seq: 4, ts: "05-04 03:17", action: "correlate.strategy · EXTERNAL-C2 · anchor 0.308", actor: "correlator" },
      { seq: 5, ts: "05-04 03:17", action: "contain.sever_c2 · 203.0.113.66", actor: "soar" },
      { seq: 6, ts: "05-04 03:17", action: "contain.quarantine · WS03", actor: "soar" },
      { seq: 7, ts: "05-04 03:18", action: "identity.revoke · exam.clerk", actor: "soar" },
      { seq: 8, ts: "05-13 22:05", action: "forensic.snapshot · DB-EXAMS", actor: "soar" },
      { seq: 9, ts: "05-19 14:32", action: "attribute.killchain · 7 techniques", actor: "system" },
      { seq: 10, ts: "05-21 06:02", action: "exfil.block · exam-records.7z · PREVENTED", actor: "soar" },
    ];
    this.ledgerTampered = this.ledgerDef.map((e, i) =>
      i === 3 ? Object.assign({}, e, { action: "correlate.strategy · INSIDER · anchor 0.021" }) : e,
    );

    this.nodes.forEach((n) => (this._nmap[n.id] = n));
    this._loop = this._loop.bind(this);
    this.onScrub = this.onScrub.bind(this);
    this.togglePlay = this.togglePlay.bind(this);
    this.clearSel = this.clearSel.bind(this);
    this.toggleOverlay = this.toggleOverlay.bind(this);
    this.toggleTamper = this.toggleTamper.bind(this);
  }

  componentDidMount() {
    const rm =
      (typeof window !== "undefined" &&
        window.matchMedia &&
        window.matchMedia("(prefers-reduced-motion: reduce)").matches) ||
      false;
    this._t0 = null;
    this._last = null;
    // deep links / reproducible captures: ?lens=graph|attack|path|events&day=12
    const patch: any = { rm, countP: rm ? 1 : this.state.countP };
    try {
      const q = new URLSearchParams(window.location.search);
      const lens = q.get("lens");
      if (lens && ["story", "graph", "attack", "path", "events"].includes(lens)) patch.lens = lens;
      const day = q.get("day");
      if (day !== null) {
        const d = parseFloat(day);
        if (!Number.isNaN(d)) patch.playDay = Math.max(0, Math.min(20, d));
      }
    } catch {
      /* no-op */
    }
    this.setState(patch);
    this._raf = requestAnimationFrame(this._loop);
    this._buildChains();
  }
  componentWillUnmount() {
    if (this._raf) cancelAnimationFrame(this._raf);
  }

  async _sha(str: string): Promise<string> {
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
  async _chain(entries: any[]) {
    let prev = "0".repeat(64);
    const out: any[] = [];
    for (const e of entries) {
      const canon = e.seq + "|" + e.ts + "|" + e.action + "|" + e.actor + "|" + prev;
      const hh = await this._sha(canon);
      out.push({ prev, hash: hh });
      prev = hh;
    }
    return out;
  }
  async _buildChains() {
    const base = await this._chain(this.ledgerDef);
    const tam = await this._chain(this.ledgerTampered);
    let bf = tam.findIndex((x, i) => x.hash !== base[i].hash);
    if (bf < 0) bf = 3;
    this.setState({ chain: base, chainT: tam, brokenFrom: bf });
  }

  _loop(ts: number) {
    if (this._t0 == null) this._t0 = ts;
    const np: any = {};
    if (!this.state.rm) {
      const cp = Math.min(1, (ts - this._t0) / 1300);
      if (cp !== this.state.countP) np.countP = cp > 0.999 ? 1 : cp;
    }
    if (this.state.playing) {
      if (this._last == null) this._last = ts;
      const dt = Math.min(0.05, (ts - this._last) / 1000);
      let d = this.state.playDay + this.state.speed * this.RATE * dt;
      if (d >= 20) {
        d = 20;
        np.playing = false;
        this._last = null;
      }
      np.playDay = d;
    } else {
      this._last = null;
    }
    if (Object.keys(np).length) this.setState(np);
    this._raf = requestAnimationFrame(this._loop);
  }

  onScrub(e: any) {
    this.setState({ playDay: Math.max(0, Math.min(20, parseFloat(e.target.value))), playing: false });
  }
  togglePlay() {
    if (this.state.playing) {
      this.setState({ playing: false });
    } else if (this.state.playDay >= 19.98) {
      this._last = null;
      this.setState({ playDay: 0, playing: true, sel: null });
    } else {
      this._last = null;
      this.setState({ playing: true });
    }
  }
  setSpeed(v: number) {
    this.setState({ speed: v });
  }
  setLens(k: string) {
    this.setState({ lens: k, hovered: null });
  }
  select(kind: string, id: string) {
    this.setState({ sel: { kind, id } });
  }
  selectTech(tid: string, pred: boolean) {
    this.setState({ sel: { kind: "tech", id: tid, pred: !!pred } });
  }
  selectEvent(id: string) {
    this.setState({ lens: "graph", sel: { kind: "edge", id }, hovered: null });
  }
  clearSel() {
    this.setState({ sel: null });
  }
  setHover(id: string | null) {
    this.setState({ hovered: id });
  }
  toggleOverlay() {
    this.setState({ overlayGT: !this.state.overlayGT });
  }
  toggleTamper() {
    this.setState({ tamperOn: !this.state.tamperOn });
  }

  heat(sc: number) {
    if (sc < 0.28) return { fill: "#94A3B8", stroke: "#E2E8F0" };
    const t = Math.min(1, (sc - 0.28) / 0.72),
      a = [217, 119, 6],
      b = [220, 38, 38];
    const c = a.map((v, i) => Math.round(v + (b[i] - v) * t));
    return { fill: "#" + c.map((x) => x.toString(16).padStart(2, "0")).join(""), stroke: "#ffffff" };
  }
  rad(n: any) {
    return 8 + n.score * 9;
  }
  typeName(t: string) {
    return ({ host: "Host", user: "User · identity", process: "Process", file: "File", ip: "IP address" } as any)[t] || t;
  }

  buildGraph() {
    const h = React.createElement,
      S = this.state,
      day = S.playDay,
      atEnd = day >= 19.98,
      rm = S.rm;
    const rev = (d: number) => atEnd || day >= d;
    const hov = S.hovered,
      sel = S.sel;
    let nbr: Set<string> | null = null;
    if (hov) {
      nbr = new Set([hov]);
      this.edges.forEach((e) => {
        if (e.s === hov) nbr!.add(e.t);
        if (e.t === hov) nbr!.add(e.s);
      });
    }

    const gt = S.overlayGT
      ? this.edges
          .filter((e) => e.mal && rev(e.day))
          .map((e) => {
            const a = this._nmap[e.s],
              b = this._nmap[e.t];
            if (!a || !b) return null;
            return h("line", { key: "gt" + e.id, x1: a.x, y1: a.y, x2: b.x, y2: b.y, stroke: "#0D9488", strokeWidth: 9, opacity: 0.15, strokeLinecap: "round" });
          })
      : [];

    const edgeEls: any[] = [];
    this.edges.forEach((e) => {
      const a = this._nmap[e.s],
        b = this._nmap[e.t];
      if (!a || !b) return;
      if (!rev(e.day)) return;
      let op = 1;
      if (hov) op = e.s === hov || e.t === hov ? 1 : 0.07;
      if (op <= 0) return;
      const spine = e.spine,
        mal = e.mal;
      const col = spine ? "#DC2626" : mal ? this.heat(e.score).fill : "#CBD5E1";
      let w = spine ? 3.4 : mal ? 1.9 : 1;
      const flare = !rm && S.playing && Math.abs(day - e.day) < 0.55 && !e.prevented;
      if (flare) w += 2.6;
      const selE = sel && sel.kind === "edge" && sel.id === e.id;
      if (selE) w += 1.4;
      const dash = e.prevented ? "3 6" : spine ? "7 6" : null;
      const cls = spine && !e.prevented && !rm ? "march" : "";
      const g: any[] = [];
      if (flare) g.push(h("line", { key: "fl", x1: a.x, y1: a.y, x2: b.x, y2: b.y, stroke: col, strokeWidth: w + 7, strokeLinecap: "round", opacity: 0.16 }));
      if (selE) g.push(h("line", { key: "sl", x1: a.x, y1: a.y, x2: b.x, y2: b.y, stroke: "#0D9488", strokeWidth: w + 5, strokeLinecap: "round", opacity: 0.2 }));
      g.push(h("line", { key: "ln", x1: a.x, y1: a.y, x2: b.x, y2: b.y, stroke: col, strokeWidth: w, strokeLinecap: "round", strokeDasharray: dash || undefined, className: cls, opacity: op }));
      if (spine || mal) {
        const dx = b.x - a.x,
          dy = b.y - a.y,
          L = Math.hypot(dx, dy) || 1,
          ux = dx / L,
          uy = dy / L;
        const bx = b.x - ux * (this.rad(b) + 5),
          by = b.y - uy * (this.rad(b) + 5);
        const ax = bx - ux * 10,
          ay = by - uy * 10,
          px = -uy * 5.5,
          py = ux * 5.5;
        g.push(h("polygon", { key: "ar", points: bx + "," + by + " " + (ax + px) + "," + (ay + py) + " " + (ax - px) + "," + (ay - py), fill: col, opacity: op }));
      }
      if (e.prevented) {
        const mx = (a.x + b.x) / 2,
          my = (a.y + b.y) / 2 - 12;
        g.push(
          h("g", { key: "pv", opacity: op }, [
            h("rect", { key: "pvr", x: mx - 30, y: my - 9, width: 60, height: 18, rx: 9, fill: "#059669" }),
            h("text", { key: "pvt", x: mx, y: my + 4, textAnchor: "middle", fontSize: 9, fontWeight: 700, fill: "#fff", fontFamily: SANS }, "BLOCKED"),
          ]),
        );
      }
      g.push(
        h("line", {
          key: "hit",
          x1: a.x,
          y1: a.y,
          x2: b.x,
          y2: b.y,
          stroke: "transparent",
          strokeWidth: 16,
          style: { cursor: "pointer" },
          onClick: (ev: any) => {
            if (ev.stopPropagation) ev.stopPropagation();
            this.select("edge", e.id);
          },
          onMouseEnter: () => this.setHover(e.s),
          onMouseLeave: () => this.setHover(null),
        }),
      );
      edgeEls.push(h("g", { key: e.id }, g));
    });

    const nodeEls: any[] = [];
    this.nodes.forEach((n) => {
      if (!rev(n.day)) return;
      let op = 1;
      if (hov) op = nbr!.has(n.id) ? 1 : 0.13;
      const H = this.heat(n.score),
        r = this.rad(n),
        faint = n.score < 0.28;
      const fillOp = faint ? 0.5 : 0.96;
      const selN = sel && sel.kind === "node" && sel.id === n.id;
      const cx = n.x,
        cy = n.y,
        g: any[] = [];
      if (selN) g.push(h("circle", { key: "sr", cx, cy, r: r + 8, fill: "none", stroke: "#0D9488", strokeWidth: 2.5 }));
      if (n.c2) {
        g.push(h("circle", { key: "c2a", cx, cy, r: r + 6, fill: "none", stroke: "#DC2626", strokeWidth: 2, opacity: 0.9 }));
        if (!rm) g.push(h("circle", { key: "c2p", cx, cy, r: r + 6, fill: "none", stroke: "#DC2626", strokeWidth: 2, style: { transformOrigin: cx + "px " + cy + "px", animation: "pulseRing 2.6s ease-out infinite" } }));
      }
      const shp: any = { fill: H.fill, fillOpacity: fillOp, stroke: faint ? "#E2E8F0" : "#ffffff", strokeWidth: faint ? 1 : 1.6 };
      if (n.type === "user") g.push(h("circle", Object.assign({ key: "sh", cx, cy, r }, shp)));
      else if (n.type === "host") g.push(h("rect", Object.assign({ key: "sh", x: cx - r, y: cy - r * 0.8, width: 2 * r, height: r * 1.6, rx: 5 }, shp)));
      else if (n.type === "process") g.push(h("polygon", Object.assign({ key: "sh", points: cx + "," + (cy - r) + " " + (cx + r) + "," + cy + " " + cx + "," + (cy + r) + " " + (cx - r) + "," + cy }, shp)));
      else if (n.type === "file") g.push(h("rect", Object.assign({ key: "sh", x: cx - r * 0.78, y: cy - r, width: r * 1.56, height: r * 2, rx: 2.5 }, shp)));
      else if (n.type === "ip") {
        const pts: string[] = [];
        for (let k = 0; k < 6; k++) {
          const ang = Math.PI / 6 + (k * Math.PI) / 3;
          pts.push((cx + r * Math.cos(ang)).toFixed(1) + "," + (cy + r * Math.sin(ang)).toFixed(1));
        }
        g.push(h("polygon", Object.assign({ key: "sh", points: pts.join(" ") }, shp)));
      }
      if (n.star) g.push(h("text", { key: "st", x: cx, y: cy - r - 6, textAnchor: "middle", fontSize: 13, fill: "#0F766E", style: { fontWeight: 700 } }, "★"));
      const lab = n.label,
        lw = lab.length * 6.3 + 14,
        ly = cy + r + (n.type === "file" ? 5 : 7);
      g.push(h("rect", { key: "lp", x: cx - lw / 2, y: ly, width: lw, height: 16, rx: 5, fill: "#ffffff", stroke: "#E5EAF0", strokeWidth: 1, opacity: faint ? 0.72 : 0.97 }));
      g.push(h("text", { key: "lt", x: cx, y: ly + 11.4, textAnchor: "middle", fontSize: faint ? 8.5 : 9.5, fontFamily: MONO, fill: faint ? "#94A3B8" : "#101828", style: { fontWeight: faint ? 400 : 600 } }, lab));
      nodeEls.push(
        h(
          "g",
          {
            key: n.id,
            opacity: op,
            style: { cursor: "pointer", transition: rm ? "none" : "opacity .25s ease" },
            onClick: (ev: any) => {
              if (ev.stopPropagation) ev.stopPropagation();
              this.select("node", n.id);
            },
            onMouseEnter: () => this.setHover(n.id),
            onMouseLeave: () => this.setHover(null),
          },
          g,
        ),
      );
    });

    return h(
      "svg",
      { viewBox: "0 0 1040 640", width: "100%", style: { display: "block", height: "auto" }, onClick: () => this.clearSel() },
      ([] as any[]).concat(gt, edgeEls, nodeEls),
    );
  }

  _buildSelected(): any {
    const sel = this.state.sel;
    if (!sel) return null;
    const chip = (sc: number) => ({ fontFamily: MONO, fontSize: "11px", fontWeight: 700, color: "#fff", background: this.heat(sc).fill, borderRadius: "6px", padding: "3px 9px" });
    const badge = (txt: string, c: string) => ({ fontSize: "10px", fontWeight: 700, letterSpacing: "0.05em", color: c, background: c === "#059669" ? "rgba(5,150,105,0.10)" : "rgba(220,38,38,0.08)", border: "1px solid " + (c === "#059669" ? "rgba(5,150,105,0.3)" : "rgba(220,38,38,0.3)"), borderRadius: "6px", padding: "3px 8px" });
    if (sel.kind === "node") {
      const n = this.nodes.find((x) => x.id === sel.id);
      if (!n) return null;
      const conn = this.edges.filter((e) => e.s === n.id || e.t === n.id).sort((a, b) => b.score - a.score);
      const meta: any[] = [{ k: "Type", v: this.typeName(n.type) }];
      if (n.star) meta.push({ k: "Role", v: "crown-jewel asset ★" });
      if (n.c2) meta.push({ k: "Role", v: "external C2 ◎" });
      meta.push({ k: "First observed", v: n.day === 0 ? "baseline" : "day " + n.day + " · May " + String(1 + n.day).padStart(2, "0") });
      meta.push({ k: "Correlated events", v: String(conn.filter((e) => e.evt).length) });
      return {
        kindLabel: "Entity",
        title: n.label,
        scoreLabel: n.score.toFixed(2),
        scoreChipSt: chip(n.score),
        badge: n.score >= 0.8 ? "HIGH ANOMALY" : null,
        badgeSt: badge("HIGH ANOMALY", "#DC2626"),
        meta,
        reasonsTitle: "Incident edges",
        reasons: conn.slice(0, 5).map((e) => (e.tech || "benign") + " · " + e.s + " → " + e.t + " · score " + e.score.toFixed(2)),
        footer: "Colored by the system’s own computed anomaly score — never the ground-truth label.",
      };
    }
    if (sel.kind === "edge") {
      const e = this.edges.find((x) => x.id === sel.id);
      if (!e) return null;
      const meta = [
        { k: "Event", v: e.evt || "—" },
        { k: "Technique", v: (e.tech || "benign") + (e.techName ? " " + e.techName : "") },
        { k: "Route", v: e.s + " → " + e.t },
        { k: "Timestamp", v: e.ts || "—" },
      ];
      let bd = null,
        bc = "#059669";
      if (e.prevented) {
        bd = "EXFIL PREVENTED";
        bc = "#059669";
      } else if (e.verdict === "confirmed") {
        bd = "CONFIRMED · CONTAINED";
        bc = "#059669";
      }
      const adv = (this.techniques.find((t) => t.id === e.tech) || {}).advisory;
      return {
        kindLabel: "Edge · event",
        title: e.s + " → " + e.t,
        scoreLabel: (e.score || 0).toFixed(2),
        scoreChipSt: chip(e.score || 0),
        badge: bd,
        badgeSt: badge(bd || "", bc),
        meta,
        reasonsTitle: "Why the system flagged it",
        reasons: e.reasons || ["Benign context — low anomaly, recedes into the graph."],
        footer: adv ? "Advisory · " + adv : null,
      };
    }
    if (sel.kind === "tech") {
      if (sel.pred) {
        const p = this.predicted.find((x) => x.id === sel.id) || ({} as any);
        return {
          kindLabel: "Predicted move",
          title: p.id + " " + (p.name || ""),
          scoreLabel: "forecast",
          scoreChipSt: { fontFamily: MONO, fontSize: "11px", fontWeight: 700, color: "#B45309", background: "rgba(217,119,6,0.10)", border: "1px solid rgba(217,119,6,0.3)", borderRadius: "6px", padding: "3px 9px" },
          badge: "NOT YET OBSERVED",
          badgeSt: { fontSize: "10px", fontWeight: 700, color: "#B45309", background: "rgba(217,119,6,0.08)", border: "1px dashed #D97706", borderRadius: "6px", padding: "3px 8px" },
          meta: [{ k: "Tactic", v: p.tactic }, { k: "Status", v: "model prediction" }],
          reasonsTitle: "Basis",
          reasons: ["Projected from the observed chain and campaign profile.", "Shown as forecast, never mixed with observed evidence."],
          footer: p.advisory ? "Advisory · " + p.advisory : null,
        };
      }
      const t = this.techniques.find((x) => x.id === sel.id) || ({} as any);
      let bd = null;
      const bc = "#059669";
      if (t.prevented) bd = "EXFIL PREVENTED";
      else if (t.verdict) bd = "CONFIRMED · CONTAINED";
      return {
        kindLabel: "Technique · observed",
        title: t.id + " " + t.name,
        scoreLabel: (t.score || 0).toFixed(2),
        scoreChipSt: chip(t.score || 0),
        badge: bd,
        badgeSt: badge(bd || "", bc),
        meta: [{ k: "Tactic", v: t.tactic }, { k: "Host", v: t.host }, { k: "First observed", v: t.date }],
        reasonsTitle: "Evidence",
        reasons: [t.evidence],
        footer: t.advisory ? "Advisory · " + t.advisory : null,
      };
    }
    return null;
  }

  renderVals(): any {
    const S = this.state,
      day = S.playDay,
      atEnd = day >= 19.98,
      t = S.countP;
    const pct = (day / 20) * 100;
    const dom = Math.min(21, 1 + Math.floor(day + 1e-6));
    const showConfirm = day >= 3 || atEnd;

    const teal = "#0D9488",
      green = "#059669";
    const disp: any = {
      roc: (t * 0.9988).toFixed(4),
      recall: Math.round(t * 100) + "%",
      tech: (t * 92.3).toFixed(1) + "%",
      auto: Math.round(t * 75) + "%",
      mttd: (t * 1.66).toFixed(2) + " d",
      mttr: "< 1 s",
      audit: "✓",
    };
    const tileColor: any = { roc: teal, recall: teal, tech: teal, auto: teal, mttd: teal, mttr: teal, audit: green };
    const metricTilesV = this.metricsDef.map((m) => ({ label: m.label, sub: m.sub, display: disp[m.key], valColor: tileColor[m.key] }));

    const beatMarks = this.beatsDef.map((b) => {
      const lit = atEnd || day >= b.day;
      const active = !S.rm && S.playing && Math.abs(day - b.day) < 0.6;
      const dc = lit ? (b.key === "confirmed" ? "#059669" : b.key === "prevented" ? "#DC2626" : "#0D9488") : "#CBD5E1";
      const dotSt = `width:${b.key ? 13 : 10}px;height:${b.key ? 13 : 10}px;border-radius:50%;background:${dc};border:2px solid #fff;box-shadow:0 0 0 1px ${lit ? dc : "#E5EAF0"};margin-top:${b.key ? 1 : 2}px;${active ? "animation:beatPing 1s ease-out infinite;" : ""}`;
      const labelSt = `font-size:9.5px;font-weight:${b.key ? 700 : 600};color:${lit ? (b.key === "confirmed" ? "#047857" : b.key === "prevented" ? "#B91C1C" : "#101828") : "#94A3B8"};margin-top:7px;white-space:nowrap`;
      return { left: (b.day / 20) * 100 + "%", label: b.label, date: b.date, dotSt, labelSt };
    });

    const speedBtns = [1, 4, 12].map((v) => ({
      label: v + "×",
      onClick: () => this.setSpeed(v),
      st: `border:0;border-radius:7px;padding:5px 11px;font-family:'JetBrains Mono',monospace;font-size:12px;font-weight:700;cursor:pointer;background:${S.speed === v ? "#101828" : "transparent"};color:${S.speed === v ? "#fff" : "#475569"}`,
    }));
    const playing = S.playing,
      atEndNow = day >= 19.98;
    const playLabel = playing ? "❚❚ Pause" : atEndNow ? "▶ Replay attack" : "▶ Play";
    const playBtnStyle = `display:inline-flex;align-items:center;gap:7px;border:0;border-radius:9px;padding:8px 16px;font-size:13px;font-weight:700;cursor:pointer;background:${playing ? "#F1F5F9" : "#0D9488"};color:${playing ? "#101828" : "#fff"};box-shadow:${playing ? "none" : "0 2px 8px -2px rgba(13,148,136,0.5)"}`;

    const lensDef = [
      { k: "story", label: "Story", sub: "kill-chain spine" },
      { k: "graph", label: "Graph", sub: "provenance" },
      { k: "attack", label: "ATT&CK", sub: "technique matrix" },
      { k: "path", label: "Path", sub: "lateral walk" },
      { k: "events", label: "Events", sub: "ranked evidence" },
    ];
    const lensBtns = lensDef.map((l) => ({
      label: l.label,
      sub: l.sub,
      onClick: () => this.setLens(l.k),
      st: `display:flex;flex-direction:column;gap:1px;align-items:flex-start;border:1px solid ${S.lens === l.k ? "#0D9488" : "#E5EAF0"};background:${S.lens === l.k ? "rgba(13,148,136,0.07)" : "#fff"};color:${S.lens === l.k ? "#0F766E" : "#475569"};border-radius:10px;padding:7px 13px;cursor:pointer;text-align:left`,
    }));

    const stations = this.techniques.map((st) => {
      const lit = atEnd || day >= st.day;
      const hc = st.verdict === "confirmed · contained" ? "#059669" : st.prevented ? "#DC2626" : this.heat(st.score).fill;
      const dotSt = `width:20px;height:20px;border-radius:50%;background:${lit ? hc : "#fff"};border:3px solid ${lit ? hc : "#D8E0E8"};box-shadow:${lit ? "0 0 0 4px " + (hc === "#059669" ? "rgba(5,150,105,0.14)" : hc === "#DC2626" ? "rgba(220,38,38,0.12)" : "rgba(217,119,6,0.12)") : "none"};transition:all .35s ease`;
      const idSt = `color:${lit ? "#101828" : "#94A3B8"};transition:color .35s`;
      const nameSt = st.prevented ? `color:${lit ? "#101828" : "#94A3B8"};text-decoration:line-through;text-decoration-color:#DC2626;text-decoration-thickness:1.5px` : `color:${lit ? "#101828" : "#94A3B8"}`;
      const wrapSt = `opacity:${lit ? 1 : 0.7};transition:opacity .35s`;
      let flag = null,
        flagText = null,
        flagSt = null;
      if (st.verdict === "confirmed · contained") {
        flag = true;
        flagText = "✓ confirmed · contained";
        flagSt = `margin-top:8px;font-size:9.5px;font-weight:700;color:#fff;background:#059669;border-radius:6px;padding:3px 8px;opacity:${lit ? 1 : 0.4};transition:opacity .35s`;
      } else if (st.prevented) {
        flag = true;
        flagText = "✕ exfil prevented";
        flagSt = `margin-top:8px;font-size:9.5px;font-weight:700;color:#B91C1C;background:rgba(220,38,38,0.08);border:1px solid rgba(220,38,38,0.3);border-radius:6px;padding:3px 8px;opacity:${lit ? 1 : 0.4};transition:opacity .35s`;
      }
      return { id: st.id, name: st.name, tactic: st.tactic, host: st.host, date: st.date, dotSt, idSt, nameSt, wrapSt, flag, flagText, flagSt };
    });
    const storyFill = (Math.min(day, 20) / 20) * 100 + "%";

    const cellSt = (k: string) => {
      if (k === "pred") return `display:flex;flex-direction:column;gap:2px;align-items:flex-start;text-align:left;border:1.5px dashed #D97706;background:rgba(217,119,6,0.05);color:#92400E;border-radius:9px;padding:8px 9px;cursor:pointer;width:100%;animation:softPulse 2.4s ease-in-out infinite`;
      if (k === "con") return `display:flex;flex-direction:column;gap:2px;align-items:flex-start;text-align:left;border:1px solid #059669;background:rgba(5,150,105,0.08);color:#065F46;border-radius:9px;padding:8px 9px;cursor:pointer;width:100%`;
      return `display:flex;flex-direction:column;gap:2px;align-items:flex-start;text-align:left;border:1px solid #0D9488;background:rgba(13,148,136,0.07);color:#0F766E;border-radius:9px;padding:8px 9px;cursor:pointer;width:100%`;
    };
    const attckCols = this.attckDef.map((col) => ({
      t: col.t,
      cells: col.cells.map((c: any) => ({
        tech: c.tid,
        name: c.name,
        note: c.note || null,
        onClick: () => this.selectTech(c.tid, c.k === "pred"),
        st: cellSt(c.k),
        noteSt: c.prevented ? "font-size:8.5px;font-weight:700;color:#B91C1C;text-decoration:line-through;margin-top:1px" : c.k === "con" ? "font-size:8.5px;font-weight:700;color:#059669;margin-top:1px" : "font-size:8.5px;color:#94A3B8;margin-top:1px",
      })),
    }));

    const pathHops = this.pathHopsDef.map((hp) => {
      const lit = atEnd || day >= hp.day;
      return {
        n: hp.n,
        to: hp.to,
        cred: hp.cred,
        tech: hp.tech + " Remote Services",
        date: hp.date,
        detail: hp.detail,
        accent: lit ? "#DC2626" : "#94A3B8",
        arrowSt: `font-size:22px;font-weight:700;color:${lit ? "#DC2626" : "#CBD5E1"}`,
        cardSt: `flex:1 1 200px;min-width:190px;border:1px solid ${lit ? "rgba(220,38,38,0.35)" : "#E5EAF0"};border-radius:14px;padding:18px;background:${lit ? "rgba(220,38,38,0.03)" : "#FBFCFD"};transition:all .35s;opacity:${lit ? 1 : 0.55}`,
      };
    });

    const evVerd = (e: any) => (e.prevented ? { t: "PREVENTED", c: "#059669", bg: "rgba(5,150,105,0.10)" } : e.verdict === "confirmed" ? { t: "CONFIRMED", c: "#059669", bg: "rgba(5,150,105,0.10)" } : { t: "MALICIOUS", c: "#B91C1C", bg: "rgba(220,38,38,0.07)" });
    const eventsRanked = this.edges
      .filter((e) => e.evt)
      .sort((a, b) => b.score - a.score)
      .map((e, i) => {
        const sc = this.heat(e.score).fill,
          vd = evVerd(e);
        return {
          rank: String(i + 1).padStart(2, "0"),
          evt: e.evt,
          score: e.score.toFixed(2),
          tech: e.tech,
          techName: e.techName,
          route: e.s + " → " + e.t,
          ts: e.ts,
          verdict: vd.t,
          rowBg: S.sel && S.sel.kind === "edge" && S.sel.id === e.id ? "rgba(13,148,136,0.05)" : "#fff",
          scoreSt: `font-family:'JetBrains Mono',monospace;font-size:12px;font-weight:700;color:#fff;background:${sc};border-radius:5px;padding:2px 7px`,
          verdictSt: `font-size:9.5px;font-weight:700;letter-spacing:0.03em;color:${vd.c};background:${vd.bg};border-radius:5px;padding:2px 7px`,
          onClick: () => this.selectEvent(e.id),
        };
      });

    const techniques = this.techniques.map((tt) => ({
      n: tt.n,
      id: tt.id,
      name: tt.name,
      tactic: tt.tactic,
      date: tt.date,
      verdict: tt.verdict ? (tt.prevented ? "exfil prevented" : "confirmed · contained") : null,
      verdictSt: tt.prevented ? "font-size:9.5px;font-weight:700;color:#B91C1C;background:rgba(220,38,38,0.08);border:1px solid rgba(220,38,38,0.25);border-radius:6px;padding:2px 8px;flex:0 0 auto" : "font-size:9.5px;font-weight:700;color:#047857;background:rgba(5,150,105,0.10);border-radius:6px;padding:2px 8px;flex:0 0 auto",
      nameSt: tt.prevented ? "text-decoration:line-through;text-decoration-color:#DC2626" : "",
      tickSt: `width:9px;height:9px;border-radius:50%;flex:0 0 auto;background:${tt.prevented ? "#DC2626" : tt.verdict ? "#059669" : this.heat(tt.score).fill}`,
      onClick: () => {
        this.setState({ lens: "attack" });
        this.selectTech(tt.id, false);
      },
    }));
    const predicted = this.predicted.map((p) => ({ id: p.id, name: p.name }));

    const actionsView = this.actionsDef.map((a) => {
      const auto = a.mode === "auto";
      return {
        name: a.name,
        target: a.target,
        blast: a.blast,
        bg: auto ? "#FBFCFD" : "rgba(217,119,6,0.04)",
        icon: auto ? "✓" : "⏸",
        iconSt: `flex:0 0 26px;width:26px;height:26px;border-radius:8px;display:flex;align-items:center;justify-content:center;font-size:13px;font-weight:700;color:#fff;background:${auto ? "#059669" : "#D97706"}`,
        tag: auto ? "auto-executed" : "awaiting approval",
        tagSt: `flex:0 0 auto;font-size:9.5px;font-weight:700;letter-spacing:0.03em;color:${auto ? "#047857" : "#B45309"};background:${auto ? "rgba(5,150,105,0.10)" : "rgba(217,119,6,0.10)"};border-radius:6px;padding:3px 8px`,
      };
    });

    const useT = S.tamperOn,
      chain = useT ? S.chainT : S.chain;
    const src = useT ? this.ledgerTampered : this.ledgerDef;
    const ledgerRows = src.map((e, i) => {
      const broken = useT && i >= S.brokenFrom;
      const mutated = useT && i === S.brokenFrom;
      const hh = chain ? chain[i].hash.slice(0, 14) + "…" : "—";
      return {
        seq: "#" + e.seq,
        ts: e.ts,
        action: e.action,
        actor: e.actor,
        hash: broken ? (chain ? chain[i].hash.slice(0, 14) + "…" : "—") : hh,
        bg: mutated ? "rgba(220,38,38,0.07)" : broken ? "rgba(220,38,38,0.028)" : "#fff",
        seqColor: broken ? "#B91C1C" : "#94A3B8",
        actionColor: mutated ? "#B91C1C" : "#101828",
        hashColor: broken ? "#DC2626" : "#94A3B8",
        dotSt: `width:7px;height:7px;border-radius:50%;flex:0 0 auto;background:${broken ? "#DC2626" : e.actor === "soar" ? "#0D9488" : "#CBD5E1"}`,
      };
    });
    const tamperLabel = S.tamperOn ? "↺ Restore ledger" : "⚠ Simulate tamper";
    const tamperBtnSt = `border:1px solid ${S.tamperOn ? "#DC2626" : "#E5EAF0"};background:${S.tamperOn ? "#DC2626" : "#fff"};color:${S.tamperOn ? "#fff" : "#475569"};border-radius:9px;padding:8px 14px;font-size:12px;font-weight:600;cursor:pointer;flex:0 0 auto`;

    const selected = this._buildSelected();

    return {
      metricTiles: metricTilesV,
      beatMarks,
      playPct: pct + "%",
      playDay: day,
      dayReadout: day.toFixed(1),
      curDate: "May " + String(dom).padStart(2, "0"),
      playLabel,
      playBtnStyle,
      speedBtns,
      showConfirm,
      notConfirm: !showConfirm,
      lensBtns,
      isStory: S.lens === "story",
      isGraph: S.lens === "graph",
      isAttack: S.lens === "attack",
      isPath: S.lens === "path",
      isEvents: S.lens === "events",
      stations,
      storyFill,
      graphEl: this.buildGraph(),
      overlayGT: S.overlayGT,
      selected,
      noSel: !selected,
      attckCols,
      pathHops,
      eventsRanked,
      techniques,
      predicted,
      actionsView,
      ledgerRows,
      tamperOn: S.tamperOn,
      tamperLabel,
      tamperBtnSt,
    };
  }

  render() {
    const V = this.renderVals();
    const sel = V.selected;
    return (
      <div style={s("max-width:1340px;margin:0 auto;padding:18px 26px 90px")}>
        {/* header */}
        <header style={s("display:flex;align-items:center;justify-content:space-between;gap:20px;padding:6px 2px 20px")}>
          <div style={s("display:flex;align-items:baseline;gap:14px")}>
            <div style={s("font-size:26px;font-weight:800;letter-spacing:-0.02em;color:#101828")}>
              PRAHAR
              <span style={s("position:relative;display:inline-block")}>
                Í<span style={s("position:absolute;left:50%;top:-3px;transform:translateX(-50%);width:6px;height:6px;border-radius:50%;background:#F59E0B")} />
              </span>
            </div>
            <div style={s("font-size:12.5px;color:#94A3B8;font-weight:500;letter-spacing:0.01em")}>AI cyber-resilience console</div>
          </div>
          <div style={s("display:flex;align-items:center;gap:10px")}>
            <div style={s("display:flex;align-items:center;gap:9px;background:#fff;border:1px solid #E5EAF0;border-radius:10px;padding:7px 12px")}>
              <span style={s("font-family:'JetBrains Mono',monospace;font-size:12.5px;font-weight:600;color:#101828")}>INC-001</span>
              <span style={s("width:1px;height:14px;background:#E5EAF0")} />
              <span style={s("font-size:11.5px;color:#475569")}>low-and-slow APT</span>
              <span style={s("font-size:10px;font-weight:700;letter-spacing:0.06em;color:#059669;background:rgba(5,150,105,0.10);border-radius:5px;padding:2px 7px")}>CONTAINED</span>
            </div>
            <div style={s("display:flex;align-items:center;gap:8px;background:rgba(5,150,105,0.08);border:1px solid rgba(5,150,105,0.22);border-radius:10px;padding:7px 12px")}>
              <span style={s("width:7px;height:7px;border-radius:50%;background:#059669;box-shadow:0 0 0 3px rgba(5,150,105,0.15)")} />
              <span style={s("font-size:11px;font-weight:700;letter-spacing:0.07em;color:#047857")}>AUDIT VERIFIED</span>
              <span style={s("font-family:'JetBrains Mono',monospace;font-size:11.5px;font-weight:700;color:#047857")}>· 10</span>
            </div>
          </div>
        </header>

        {/* verdict */}
        <section style={s("background:#fff;border:1px solid #E5EAF0;border-radius:18px;padding:30px 32px;box-shadow:0 1px 2px rgba(16,24,40,0.04),0 18px 40px -28px rgba(16,24,40,0.18);margin-bottom:16px")}>
          <div style={s("display:flex;gap:34px;align-items:flex-start;flex-wrap:wrap")}>
            <div style={s("flex:1 1 560px;min-width:340px")}>
              <div style={s("font-family:'JetBrains Mono',monospace;font-size:11px;letter-spacing:0.16em;text-transform:uppercase;color:#0D9488;font-weight:600;margin-bottom:14px")}>The verdict · INC-001</div>
              <h1 style={s("margin:0;font-size:33px;line-height:1.24;font-weight:700;letter-spacing:-0.02em;color:#101828;text-wrap:balance;max-width:22ch")}>
                A patient nation-state intrusion was detected in <span style={s("color:#0D9488")}>1.66 days</span>, <span style={s("color:#059669;font-weight:800")}>contained</span> in under a second, and the <span style={s("font-weight:800")}>exam-records</span> exfil was <span style={s("color:#059669;font-weight:800")}>prevented</span>.
              </h1>
              <p style={s("margin:16px 0 0;font-size:14.5px;line-height:1.6;color:#475569;max-width:60ch")}>
                Confirmed <span style={s("font-family:'JetBrains Mono',monospace;color:#101828")}>2026-05-04</span> — <span style={s("font-family:'JetBrains Mono',monospace;color:#101828")}>17.04 days</span> before the planned exfiltration. Auto-containment severed the C2 channel at confirmation, so the <span style={s("font-family:'JetBrains Mono',monospace;color:#101828")}>May-21</span> exfiltration <span style={s("color:#059669;font-weight:600")}>never completed</span>. Every step below is provable.
              </p>
            </div>
            <div style={s("flex:0 0 auto;display:flex;flex-direction:column;align-items:flex-end;gap:2px;padding:4px 4px 0")}>
              <div style={s("font-size:11px;letter-spacing:0.1em;text-transform:uppercase;color:#94A3B8;font-weight:600")}>Incident score</div>
              <div style={s("font-family:'JetBrains Mono',monospace;font-size:56px;font-weight:700;line-height:1;letter-spacing:-0.03em;color:#0D9488")}>34.16</div>
              <div style={s("font-size:12px;color:#475569;margin-top:2px")}>
                <span style={s("color:#DC2626;font-weight:600")}>4×</span> the next incident
              </div>
            </div>
          </div>
          <div style={s("display:grid;grid-template-columns:repeat(7,1fr);gap:10px;margin-top:26px")}>
            {V.metricTiles.map((tile: any, i: number) => (
              <div key={i} style={s("background:#FBFCFD;border:1px solid #EDF1F5;border-radius:12px;padding:13px 13px 12px;display:flex;flex-direction:column;gap:3px;min-height:92px")}>
                <div style={{ ...s("font-family:'JetBrains Mono',monospace;font-size:23px;font-weight:700;letter-spacing:-0.02em;line-height:1.05"), color: tile.valColor }}>{tile.display}</div>
                <div style={s("font-size:11px;font-weight:600;color:#101828;line-height:1.2;margin-top:2px")}>{tile.label}</div>
                <div style={s("font-size:10px;color:#94A3B8;line-height:1.25;margin-top:auto")}>{tile.sub}</div>
              </div>
            ))}
          </div>
        </section>

        {/* correlation strategy */}
        <section style={s("background:#fff;border:1px solid #E5EAF0;border-radius:16px;padding:18px 22px;box-shadow:0 1px 2px rgba(16,24,40,0.04);margin-bottom:16px")}>
          <div style={s("display:flex;gap:26px;align-items:center;flex-wrap:wrap")}>
            <div style={s("display:flex;flex-direction:column;gap:5px;min-width:230px")}>
              <span style={s("font-family:'JetBrains Mono',monospace;font-size:10.5px;letter-spacing:0.12em;color:#94A3B8;font-weight:600")}>CORRELATION STRATEGY</span>
              <div style={s("display:flex;align-items:center;gap:9px")}>
                <span style={s("font-family:'JetBrains Mono',monospace;font-size:16px;font-weight:700;color:#0D9488;letter-spacing:-0.01em")}>EXTERNAL-C2</span>
                <span style={s("font-size:9.5px;font-weight:700;letter-spacing:0.06em;color:#0F766E;background:rgba(13,148,136,0.10);border:1px solid rgba(13,148,136,0.22);border-radius:5px;padding:2px 6px")}>AUTO-SELECTED</span>
              </div>
              <div style={s("font-size:11.5px;color:#475569;line-height:1.4;max-width:34ch")}>External-anchor fraction crossed the decision threshold — the system chose this without a human.</div>
            </div>
            <div style={s("flex:1 1 300px;min-width:260px")}>
              <div style={s("display:flex;justify-content:space-between;align-items:baseline;margin-bottom:7px")}>
                <span style={s("font-size:11px;color:#475569")}>external-anchor fraction</span>
                <span style={s("font-family:'JetBrains Mono',monospace;font-size:12px;color:#94A3B8")}>threshold <span style={s("color:#101828;font-weight:600")}>0.15</span></span>
              </div>
              <div style={s("position:relative;height:10px;background:#EEF2F6;border-radius:6px;overflow:visible")}>
                <div style={s("position:absolute;left:0;top:0;bottom:0;width:61.6%;background:linear-gradient(90deg,#0D9488,#0F766E);border-radius:6px")} />
                <div style={s("position:absolute;left:30%;top:-4px;bottom:-4px;width:2px;background:#94A3B8")} />
                <div style={s("position:absolute;left:30%;top:-19px;transform:translateX(-50%);font-family:'JetBrains Mono',monospace;font-size:9.5px;color:#94A3B8;white-space:nowrap")}>0.15</div>
                <div style={s("position:absolute;left:61.6%;top:16px;transform:translateX(-50%);font-family:'JetBrains Mono',monospace;font-size:10.5px;font-weight:700;color:#0D9488;white-space:nowrap")}>0.308 ✓</div>
              </div>
            </div>
            <div style={s("display:flex;flex-direction:column;gap:7px")}>
              <span style={s("font-size:10px;letter-spacing:0.1em;text-transform:uppercase;color:#94A3B8;font-weight:600")}>Pivots used</span>
              <div style={s("display:flex;gap:6px")}>
                {["extip", "file", "host", "process"].map((p) => (
                  <span key={p} style={s("font-family:'JetBrains Mono',monospace;font-size:11px;color:#101828;background:#F1F5F9;border:1px solid #E5EAF0;border-radius:6px;padding:3px 9px")}>{p}</span>
                ))}
                <span style={s("font-family:'JetBrains Mono',monospace;font-size:11px;color:#94A3B8;background:#F8FAFC;border:1px dashed #CBD5E1;border-radius:6px;padding:3px 9px")}>+user (insider only)</span>
              </div>
            </div>
          </div>
        </section>

        {/* replay master clock */}
        <section style={s("background:#fff;border:1px solid #E5EAF0;border-radius:16px;padding:18px 22px 20px;box-shadow:0 1px 2px rgba(16,24,40,0.04);margin-bottom:16px")}>
          <div style={s("display:flex;align-items:center;justify-content:space-between;gap:16px;margin-bottom:16px;flex-wrap:wrap")}>
            <div style={s("display:flex;align-items:center;gap:12px")}>
              <button onClick={this.togglePlay} style={s(V.playBtnStyle)}>{V.playLabel}</button>
              <div style={s("display:flex;background:#F1F5F9;border:1px solid #E5EAF0;border-radius:9px;padding:2px")}>
                {V.speedBtns.map((sb: any, i: number) => (
                  <button key={i} onClick={sb.onClick} style={s(sb.st)}>{sb.label}</button>
                ))}
              </div>
              <div style={s("font-family:'JetBrains Mono',monospace;font-size:12px;color:#475569;margin-left:2px;white-space:nowrap")}>clock <span style={s("color:#101828;font-weight:600")}>{V.curDate}</span> · <span style={s("color:#94A3B8")}>day {V.dayReadout}</span></div>
            </div>
            <div style={s("font-family:'JetBrains Mono',monospace;font-size:10.5px;letter-spacing:0.08em;color:#94A3B8")}>MASTER CLOCK · MAY 1 → MAY 21, 2026</div>
          </div>
          <div style={s("min-height:36px;margin:2px 44px 16px")}>
            {V.showConfirm && (
              <div style={{ ...s("display:flex;align-items:center;gap:11px;background:rgba(5,150,105,0.08);border:1px solid rgba(5,150,105,0.28);border-radius:11px;padding:9px 14px"), animation: "confirmPulse 0.9s ease-out" }}>
                <span style={s("flex:0 0 auto;width:22px;height:22px;border-radius:50%;background:#059669;color:#fff;display:flex;align-items:center;justify-content:center;font-size:12px;font-weight:700")}>✓</span>
                <span style={s("font-size:12.5px;color:#065F46;line-height:1.45")}><span style={s("font-weight:700")}>Confirmed 2026-05-04 · MTTD 1.66 d</span> — C2 channel severed at confirmation, so the exam-records exfiltration on May 21 <span style={s("font-weight:700")}>never completed</span>.</span>
              </div>
            )}
            {V.notConfirm && (
              <div style={s("display:flex;align-items:center;gap:11px;background:#F8FAFC;border:1px dashed #D8E0E8;border-radius:11px;padding:9px 14px")}>
                <span style={s("flex:0 0 auto;width:22px;height:22px;border-radius:50%;background:#EEF2F6;color:#94A3B8;display:flex;align-items:center;justify-content:center;font-size:13px")}>⋯</span>
                <span style={s("font-size:12.5px;color:#94A3B8")}>Correlating weak signals — awaiting confirmation…</span>
              </div>
            )}
          </div>
          <div style={s("position:relative;height:58px;margin:0 44px")}>
            <div style={s("position:absolute;left:0;right:0;top:20px;height:6px;background:#EEF2F6;border-radius:4px")} />
            <div style={{ ...s("position:absolute;left:0;top:20px;height:6px;background:linear-gradient(90deg,#0D9488,#0F766E);border-radius:4px"), width: V.playPct }} />
            {V.beatMarks.map((b: any, i: number) => (
              <div key={i} style={{ ...s("position:absolute;top:0;transform:translateX(-50%);display:flex;flex-direction:column;align-items:center"), left: b.left }}>
                <div style={s(b.dotSt)} />
                <div style={s(b.labelSt)}>{b.label}</div>
                <div style={s("font-family:'JetBrains Mono',monospace;font-size:9px;color:#94A3B8;margin-top:1px")}>{b.date}</div>
              </div>
            ))}
            <div style={{ ...s("position:absolute;top:11px;transform:translateX(-50%);display:flex;flex-direction:column;align-items:center;pointer-events:none"), left: V.playPct }}>
              <div style={s("width:16px;height:16px;border-radius:50%;background:#101828;border:3px solid #fff;box-shadow:0 2px 6px rgba(16,24,40,0.28)")} />
            </div>
            <input type="range" min={0} max={20} step={0.02} value={V.playDay} onChange={this.onScrub} aria-label="Replay timeline" className="rc-range" style={s("position:absolute;left:-4px;right:-4px;top:12px;width:calc(100% + 8px);height:20px;margin:0")} />
          </div>
        </section>

        {/* the instrument */}
        <section style={s("background:#fff;border:1px solid #E5EAF0;border-radius:18px;box-shadow:0 1px 2px rgba(16,24,40,0.04),0 22px 48px -34px rgba(16,24,40,0.22);margin-bottom:16px;overflow:hidden")}>
          <div style={s("display:flex;align-items:flex-end;justify-content:space-between;gap:16px;padding:20px 24px 0;flex-wrap:wrap")}>
            <div>
              <div style={s("font-family:'JetBrains Mono',monospace;font-size:11px;letter-spacing:0.16em;text-transform:uppercase;color:#0D9488;font-weight:600;display:flex;align-items:center;gap:7px")}><span style={s("color:#0F766E")}>★</span> The instrument</div>
              <div style={s("font-size:20px;font-weight:700;letter-spacing:-0.01em;margin-top:5px")}>Provenance graph &amp; ATT&amp;CK kill chain</div>
              <div style={s("font-size:12.5px;color:#94A3B8;margin-top:3px")}>One incident, five lenses — all driven by the replay clock above.</div>
            </div>
            <div style={s("display:flex;gap:6px;flex-wrap:wrap")}>
              {V.lensBtns.map((lb: any, i: number) => (
                <button key={i} onClick={lb.onClick} style={s(lb.st)}>
                  <span style={s("font-weight:700;font-size:12.5px")}>{lb.label}</span>
                  <span style={s("font-size:9.5px;opacity:0.7;letter-spacing:0.02em")}>{lb.sub}</span>
                </button>
              ))}
            </div>
          </div>
          <div style={s("height:1px;background:#EDF1F5;margin:18px 0 0")} />
          <div style={s("padding:8px 24px 26px")}>
            {V.isStory && (
              <div style={s("padding:26px 6px 8px")}>
                <div style={s("position:relative;padding:0 2px")}>
                  <div style={s("position:absolute;left:2%;right:2%;top:9px;height:4px;background:#EEF2F6;border-radius:3px")} />
                  <div style={{ ...s("position:absolute;left:2%;top:9px;height:4px;background:linear-gradient(90deg,#D97706,#DC2626);border-radius:3px;max-width:96%"), width: V.storyFill }} />
                  <div style={s("display:flex;justify-content:space-between;gap:8px;position:relative")}>
                    {V.stations.map((st: any, i: number) => (
                      <div key={i} style={{ ...s("flex:1 1 0;display:flex;flex-direction:column;align-items:center;text-align:center;min-width:0"), ...s(st.wrapSt) }}>
                        <div style={s(st.dotSt)} />
                        <div style={{ ...s("font-family:'JetBrains Mono',monospace;font-size:13px;font-weight:700;margin-top:12px"), ...s(st.idSt) }}>{st.id}</div>
                        <div style={{ ...s("font-size:11px;font-weight:600;margin-top:3px;line-height:1.25;color:#101828"), ...s(st.nameSt) }}>{st.name}</div>
                        <div style={s("font-size:9.5px;color:#94A3B8;margin-top:2px")}>{st.tactic}</div>
                        <div style={s("font-family:'JetBrains Mono',monospace;font-size:9.5px;color:#94A3B8;margin-top:4px")}>{st.host} · {st.date}</div>
                        {st.flag && <div style={s(st.flagSt)}>{st.flagText}</div>}
                      </div>
                    ))}
                  </div>
                </div>
                <div style={s("font-size:11.5px;color:#94A3B8;text-align:center;margin-top:22px")}>Scrub the clock above — each station ignites the moment the playhead crosses its first-observed time.</div>
              </div>
            )}

            {V.isGraph && (
              <div style={s("display:flex;gap:18px;padding-top:16px;flex-wrap:wrap")}>
                <div style={s("flex:1 1 640px;min-width:420px")}>
                  <div style={s("border:1px solid #EDF1F5;border-radius:14px;overflow:hidden;background:#FBFCFD")}>{V.graphEl}</div>
                  <div style={s("display:flex;align-items:center;justify-content:space-between;gap:14px;margin-top:12px;flex-wrap:wrap")}>
                    <div style={s("display:flex;align-items:center;gap:14px;flex-wrap:wrap")}>
                      <div style={s("display:flex;align-items:center;gap:6px;font-size:10.5px;color:#475569")}><svg width="34" height="12"><line x1="1" y1="6" x2="33" y2="6" stroke="#DC2626" strokeWidth="3" strokeDasharray="7 6" /></svg> attack spine</div>
                      <div style={s("display:flex;align-items:center;gap:6px;font-size:10.5px;color:#475569")}><span style={s("width:11px;height:11px;border-radius:3px;background:#DC2626")} /> high anomaly</div>
                      <div style={s("display:flex;align-items:center;gap:6px;font-size:10.5px;color:#475569")}><span style={s("width:11px;height:11px;border-radius:3px;background:#D97706")} /> elevated</div>
                      <div style={s("display:flex;align-items:center;gap:6px;font-size:10.5px;color:#475569")}><span style={s("width:11px;height:11px;border-radius:3px;background:#94A3B8;opacity:0.6")} /> benign context</div>
                    </div>
                    <label style={s("display:flex;align-items:center;gap:8px;font-size:11px;color:#475569;cursor:pointer;user-select:none;background:#F8FAFC;border:1px solid #E5EAF0;border-radius:8px;padding:6px 10px")}>
                      <input type="checkbox" checked={V.overlayGT} onChange={this.toggleOverlay} style={s("accent-color:#0D9488;width:14px;height:14px")} />
                      ground-truth overlay <span style={s("font-size:9.5px;color:#94A3B8")}>(eval only)</span>
                    </label>
                  </div>
                  <div style={s("display:flex;gap:16px;margin-top:10px;flex-wrap:wrap;font-size:10px;color:#94A3B8")}>
                    <span>shape = entity type:</span>
                    <span>● user</span><span>▮ host</span><span>◆ process</span><span>▭ file</span><span>⬡ ip</span>
                    <span style={s("color:#0F766E")}>★ crown jewel</span>
                    <span style={s("color:#DC2626")}>◎ external C2</span>
                  </div>
                </div>
                <div style={s("flex:1 1 300px;min-width:280px;max-width:360px")}>
                  {sel ? (
                    <div style={s("border:1px solid #E5EAF0;border-radius:14px;padding:18px;background:#fff;box-shadow:0 12px 30px -22px rgba(16,24,40,0.3)")}>
                      <div style={s("display:flex;align-items:flex-start;justify-content:space-between;gap:10px")}>
                        <div>
                          <div style={s("font-family:'JetBrains Mono',monospace;font-size:10px;letter-spacing:0.12em;text-transform:uppercase;color:#94A3B8;font-weight:600")}>{sel.kindLabel}</div>
                          <div style={s("font-family:'JetBrains Mono',monospace;font-size:17px;font-weight:700;margin-top:4px;color:#101828")}>{sel.title}</div>
                        </div>
                        <button onClick={this.clearSel} style={s("border:1px solid #E5EAF0;background:#F8FAFC;border-radius:7px;width:26px;height:26px;color:#94A3B8;cursor:pointer;font-size:14px;line-height:1;flex:0 0 auto")}>×</button>
                      </div>
                      <div style={s("display:flex;align-items:center;gap:8px;margin-top:12px;flex-wrap:wrap")}>
                        <span style={sel.scoreChipSt}>anomaly {sel.scoreLabel}</span>
                        {sel.badge && <span style={sel.badgeSt}>{sel.badge}</span>}
                      </div>
                      <div style={s("display:flex;flex-direction:column;gap:0;margin-top:14px;border-top:1px solid #F1F5F9")}>
                        {sel.meta.map((m: any, i: number) => (
                          <div key={i} style={s("display:flex;justify-content:space-between;gap:12px;padding:8px 0;border-bottom:1px solid #F1F5F9")}>
                            <span style={s("font-size:11.5px;color:#94A3B8")}>{m.k}</span>
                            <span style={s("font-family:'JetBrains Mono',monospace;font-size:11.5px;color:#101828;text-align:right")}>{m.v}</span>
                          </div>
                        ))}
                      </div>
                      <div style={s("font-size:10.5px;letter-spacing:0.1em;text-transform:uppercase;color:#94A3B8;font-weight:600;margin-top:14px")}>{sel.reasonsTitle}</div>
                      <div style={s("display:flex;flex-direction:column;gap:7px;margin-top:8px")}>
                        {sel.reasons.map((r: string, i: number) => (
                          <div key={i} style={s("display:flex;gap:8px;font-size:12px;color:#475569;line-height:1.45")}><span style={s("color:#0D9488;flex:0 0 auto")}>›</span><span>{r}</span></div>
                        ))}
                      </div>
                      {sel.footer && <div style={s("margin-top:14px;padding-top:12px;border-top:1px solid #F1F5F9;font-size:10.5px;color:#94A3B8;line-height:1.5")}>{sel.footer}</div>}
                    </div>
                  ) : (
                    <div style={s("border:1px dashed #D8E0E8;border-radius:14px;padding:30px 20px;background:#FBFCFD;text-align:center;height:100%;display:flex;flex-direction:column;align-items:center;justify-content:center;min-height:260px")}>
                      <div style={s("width:40px;height:40px;border-radius:11px;background:#F1F5F9;display:flex;align-items:center;justify-content:center;margin-bottom:12px")}><svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="#94A3B8" strokeWidth="1.6"><circle cx="11" cy="11" r="7" /><path d="M20 20l-3.2-3.2" /></svg></div>
                      <div style={s("font-size:13px;font-weight:600;color:#475569")}>Inspect any node or edge</div>
                      <div style={s("font-size:11.5px;color:#94A3B8;margin-top:5px;max-width:26ch;line-height:1.5")}>Hover to spotlight its neighborhood; click to open the evidence underneath.</div>
                    </div>
                  )}
                </div>
              </div>
            )}

            {V.isAttack && (
              <div style={s("padding-top:18px")}>
                <div style={s("display:flex;gap:18px;align-items:center;margin-bottom:14px;font-size:11px;color:#475569;flex-wrap:wrap")}>
                  <span style={s("display:flex;align-items:center;gap:6px")}><span style={s("width:11px;height:11px;border-radius:3px;background:#0D9488")} /> observed</span>
                  <span style={s("display:flex;align-items:center;gap:6px")}><span style={s("width:11px;height:11px;border-radius:3px;background:#059669")} /> confirmed · contained</span>
                  <span style={s("display:flex;align-items:center;gap:6px")}><span style={{ ...s("width:11px;height:11px;border-radius:3px;border:1.5px dashed #D97706"), animation: "softPulse 2s ease-in-out infinite" }} /> predicted next move</span>
                </div>
                <div style={s("display:grid;grid-template-columns:repeat(9,1fr);gap:8px;align-items:start")}>
                  {V.attckCols.map((col: any, i: number) => (
                    <div key={i} style={s("display:flex;flex-direction:column;gap:8px;min-width:0")}>
                      <div style={s("font-size:9.5px;font-weight:700;color:#475569;line-height:1.25;min-height:26px;letter-spacing:0.01em")}>{col.t}</div>
                      {col.cells.map((c: any, j: number) => (
                        <button key={j} onClick={c.onClick} style={s(c.st)}>
                          <span style={s("font-family:'JetBrains Mono',monospace;font-size:11px;font-weight:700")}>{c.tech}</span>
                          <span style={s("font-size:9.5px;line-height:1.2;opacity:0.85")}>{c.name}</span>
                          {c.note && <span style={s(c.noteSt)}>{c.note}</span>}
                        </button>
                      ))}
                    </div>
                  ))}
                </div>
                <div style={s("font-size:11px;color:#94A3B8;margin-top:16px")}>Tap a technique to open its evidence and advisory citation. Forecast cells are model predictions, not observed events.</div>
              </div>
            )}

            {V.isPath && (
              <div style={s("padding:22px 6px 8px")}>
                <div style={s("display:flex;gap:14px;align-items:stretch;flex-wrap:wrap")}>
                  <div style={s("flex:1 1 200px;min-width:190px;border:1px solid #E5EAF0;border-radius:14px;padding:18px;background:#FBFCFD")}>
                    <div style={s("font-family:'JetBrains Mono',monospace;font-size:11px;color:#94A3B8")}>START · patient zero</div>
                    <div style={s("font-family:'JetBrains Mono',monospace;font-size:20px;font-weight:700;margin-top:8px;color:#101828")}>WS03</div>
                    <div style={s("font-size:11.5px;color:#475569;margin-top:6px;line-height:1.5")}>The exam clerk&apos;s workstation. Phished on May 02; credentials dumped to out.dmp.</div>
                  </div>
                  {V.pathHops.map((hop: any, i: number) => (
                    <React.Fragment key={i}>
                      <div style={s("flex:0 0 auto;display:flex;align-items:center;padding:0 2px")}><div style={s(hop.arrowSt)}>→</div></div>
                      <div style={s(hop.cardSt)}>
                        <div style={{ ...s("font-family:'JetBrains Mono',monospace;font-size:11px"), color: hop.accent }}>HOP {hop.n} · {hop.date}</div>
                        <div style={s("font-family:'JetBrains Mono',monospace;font-size:20px;font-weight:700;margin-top:8px;color:#101828")}>{hop.to}</div>
                        <div style={s("display:flex;align-items:center;gap:6px;margin-top:8px;flex-wrap:wrap")}>
                          <span style={s("font-family:'JetBrains Mono',monospace;font-size:10.5px;color:#101828;background:#fff;border:1px solid #E5EAF0;border-radius:5px;padding:2px 7px")}>{hop.cred}</span>
                          <span style={s("font-family:'JetBrains Mono',monospace;font-size:10.5px;color:#DC2626;background:rgba(220,38,38,0.06);border:1px solid rgba(220,38,38,0.2);border-radius:5px;padding:2px 7px")}>{hop.tech}</span>
                        </div>
                        <div style={s("font-size:11.5px;color:#475569;margin-top:8px;line-height:1.5")}>{hop.detail}</div>
                      </div>
                    </React.Fragment>
                  ))}
                  <div style={s("flex:0 0 auto;display:flex;align-items:center;padding:0 2px")}><div style={s("font-size:22px;color:#DC2626;font-weight:700")}>→</div></div>
                  <div style={s("flex:1 1 190px;min-width:180px;border:1.5px dashed #DC2626;border-radius:14px;padding:18px;background:rgba(220,38,38,0.03);position:relative")}>
                    <div style={s("font-family:'JetBrains Mono',monospace;font-size:11px;color:#DC2626")}>EXFIL · May 21</div>
                    <div style={s("font-family:'JetBrains Mono',monospace;font-size:17px;font-weight:700;margin-top:8px;color:#101828;text-decoration:line-through;text-decoration-color:#DC2626")}>203.0.113.66</div>
                    <div style={s("display:inline-flex;align-items:center;gap:5px;margin-top:10px;background:#059669;color:#fff;border-radius:6px;padding:4px 9px;font-size:10.5px;font-weight:700;letter-spacing:0.04em")}>✓ PREVENTED</div>
                    <div style={s("font-size:11.5px;color:#475569;margin-top:8px;line-height:1.5")}>exam-records.7z never left the building — the C2 channel was already severed on May 04.</div>
                  </div>
                </div>
              </div>
            )}

            {V.isEvents && (
              <div style={s("padding-top:14px")}>
                <div style={s("display:grid;grid-template-columns:44px 96px 74px 1.4fr 1.5fr 108px 96px;gap:0;font-size:10px;letter-spacing:0.08em;text-transform:uppercase;color:#94A3B8;font-weight:600;padding:0 12px 10px;border-bottom:1px solid #EDF1F5")}>
                  <div>#</div><div>Event</div><div style={s("text-align:right")}>Score</div><div style={s("padding-left:16px")}>Technique</div><div>Route</div><div>Timestamp</div><div style={s("text-align:right")}>Verdict</div>
                </div>
                {V.eventsRanked.map((ev: any, i: number) => (
                  <button key={i} onClick={ev.onClick} style={{ ...s("display:grid;grid-template-columns:44px 96px 74px 1.4fr 1.5fr 108px 96px;gap:0;width:100%;text-align:left;align-items:center;border:0;border-bottom:1px solid #F1F5F9;padding:11px 12px;cursor:pointer"), background: ev.rowBg, fontFamily: "inherit" }}>
                    <div style={s("font-family:'JetBrains Mono',monospace;font-size:12px;color:#94A3B8;font-weight:600")}>{ev.rank}</div>
                    <div style={s("font-family:'JetBrains Mono',monospace;font-size:11.5px;color:#101828")}>{ev.evt}</div>
                    <div style={s("text-align:right")}><span style={s(ev.scoreSt)}>{ev.score}</span></div>
                    <div style={s("padding-left:16px;display:flex;flex-direction:column")}><span style={s("font-family:'JetBrains Mono',monospace;font-size:11.5px;font-weight:600;color:#101828")}>{ev.tech}</span><span style={s("font-size:10.5px;color:#94A3B8")}>{ev.techName}</span></div>
                    <div style={s("font-family:'JetBrains Mono',monospace;font-size:11px;color:#475569")}>{ev.route}</div>
                    <div style={s("font-family:'JetBrains Mono',monospace;font-size:11px;color:#475569")}>{ev.ts}</div>
                    <div style={s("text-align:right")}><span style={s(ev.verdictSt)}>{ev.verdict}</span></div>
                  </button>
                ))}
                <div style={s("font-size:11px;color:#94A3B8;margin-top:14px;padding:0 12px")}>60 correlated events in INC-001 · showing the 15 highest-scored. Click a row to jump to its edge in the graph.</div>
              </div>
            )}
          </div>
        </section>

        {/* attribution + response */}
        <div style={s("display:grid;grid-template-columns:1.35fr 1fr;gap:16px;margin-bottom:16px")}>
          <section style={s("background:#fff;border:1px solid #E5EAF0;border-radius:16px;padding:22px 24px;box-shadow:0 1px 2px rgba(16,24,40,0.04)")}>
            <div style={s("font-family:'JetBrains Mono',monospace;font-size:11px;letter-spacing:0.16em;text-transform:uppercase;color:#0D9488;font-weight:600")}>Attribution</div>
            <div style={s("font-size:18px;font-weight:700;margin-top:5px")}>Reconstructed kill chain</div>
            <div style={s("font-size:12.5px;color:#475569;margin-top:6px;line-height:1.55;max-width:64ch")}><span style={s("font-weight:600;color:#101828")}>Assessment:</span> low-and-slow, patient tradecraft consistent with a nation-state-style actor — long dwell, valid-account abuse, single crown-jewel objective. Technique attribution accuracy <span style={s("font-family:'JetBrains Mono',monospace")}>92.3%</span>, zero false attributions.</div>
            <div style={s("display:flex;flex-direction:column;gap:8px;margin-top:16px")}>
              {V.techniques.map((tt: any, i: number) => (
                <button key={i} onClick={tt.onClick} style={s("display:flex;align-items:center;gap:14px;background:#FBFCFD;border:1px solid #EDF1F5;border-radius:11px;padding:11px 14px;text-align:left;cursor:pointer;width:100%")}>
                  <span style={s("font-family:'JetBrains Mono',monospace;font-size:12px;font-weight:700;color:#94A3B8;flex:0 0 18px")}>{tt.n}</span>
                  <span style={s(tt.tickSt)} />
                  <span style={s("flex:0 0 66px;font-family:'JetBrains Mono',monospace;font-size:12.5px;font-weight:700;color:#101828")}>{tt.id}</span>
                  <span style={s("flex:1 1 auto;min-width:0")}><span style={{ ...s("font-size:12.5px;font-weight:600;color:#101828"), ...s(tt.nameSt) }}>{tt.name}</span> <span style={s("font-size:11px;color:#94A3B8")}>· {tt.tactic}</span></span>
                  {tt.verdict && <span style={s(tt.verdictSt)}>{tt.verdict}</span>}
                  <span style={s("font-family:'JetBrains Mono',monospace;font-size:10.5px;color:#94A3B8;flex:0 0 auto")}>{tt.date}</span>
                </button>
              ))}
            </div>
            <div style={s("margin-top:18px")}>
              <div style={s("font-size:10.5px;letter-spacing:0.1em;text-transform:uppercase;color:#94A3B8;font-weight:600;margin-bottom:9px")}>Predicted next moves</div>
              <div style={s("display:flex;gap:8px;flex-wrap:wrap")}>
                {V.predicted.map((p: any, i: number) => (
                  <div key={i} style={{ ...s("display:flex;flex-direction:column;gap:1px;border:1.5px dashed #D97706;background:rgba(217,119,6,0.05);border-radius:9px;padding:8px 11px"), animation: "softPulse 2.4s ease-in-out infinite" }}>
                    <span style={s("font-family:'JetBrains Mono',monospace;font-size:11.5px;font-weight:700;color:#B45309")}>{p.id}</span>
                    <span style={s("font-size:10px;color:#92400E")}>{p.name}</span>
                  </div>
                ))}
              </div>
            </div>
          </section>

          <section style={s("background:#fff;border:1px solid #E5EAF0;border-radius:16px;padding:22px 24px;box-shadow:0 1px 2px rgba(16,24,40,0.04)")}>
            <div style={s("display:flex;align-items:baseline;justify-content:space-between;gap:10px")}>
              <div>
                <div style={s("font-family:'JetBrains Mono',monospace;font-size:11px;letter-spacing:0.16em;text-transform:uppercase;color:#0D9488;font-weight:600")}>Response queue</div>
                <div style={s("font-size:18px;font-weight:700;margin-top:5px")}>SOAR actions</div>
              </div>
              <div style={s("text-align:right")}><span style={s("font-family:'JetBrains Mono',monospace;font-size:12px;font-weight:700;color:#0D9488")}>75%</span><div style={s("font-size:10px;color:#94A3B8")}>6 auto · 2 human-gated</div></div>
            </div>
            <div style={s("display:flex;flex-direction:column;gap:7px;margin-top:14px")}>
              {V.actionsView.map((a: any, i: number) => (
                <div key={i} style={{ ...s("display:flex;align-items:center;gap:11px;border:1px solid #EDF1F5;border-radius:10px;padding:10px 12px"), background: a.bg }}>
                  <span style={s(a.iconSt)}>{a.icon}</span>
                  <div style={s("flex:1 1 auto;min-width:0")}>
                    <div style={s("font-size:12.5px;font-weight:600;color:#101828")}>{a.name}</div>
                    <div style={s("font-size:10.5px;color:#94A3B8;font-family:'JetBrains Mono',monospace")}>{a.target} · blast {a.blast}</div>
                  </div>
                  <span style={s(a.tagSt)}>{a.tag}</span>
                </div>
              ))}
            </div>
          </section>
        </div>

        {/* ledger */}
        <section style={s("background:#fff;border:1px solid #E5EAF0;border-radius:16px;padding:22px 24px 24px;box-shadow:0 1px 2px rgba(16,24,40,0.04)")}>
          <div style={s("display:flex;align-items:flex-start;justify-content:space-between;gap:16px;flex-wrap:wrap")}>
            <div>
              <div style={s("font-family:'JetBrains Mono',monospace;font-size:11px;letter-spacing:0.16em;text-transform:uppercase;color:#0D9488;font-weight:600")}>Tamper-evident ledger</div>
              <div style={s("font-size:18px;font-weight:700;margin-top:5px")}>SHA-256 hash chain · append-only</div>
              <div style={s("font-size:12px;color:#475569;margin-top:5px;max-width:60ch;line-height:1.5")}>Each entry hashes the previous entry&apos;s digest. Mutate any row and every downstream hash breaks — the chain can&apos;t be silently edited.</div>
            </div>
            <button onClick={this.toggleTamper} style={s(V.tamperBtnSt)}>{V.tamperLabel}</button>
          </div>
          {V.tamperOn && (
            <div style={s("display:flex;align-items:center;gap:8px;margin-top:14px;background:rgba(220,38,38,0.06);border:1px solid rgba(220,38,38,0.25);border-radius:9px;padding:9px 12px;font-size:12px;color:#B91C1C")}><span style={s("font-weight:700")}>⚠ Chain broken.</span> Entry #4 was mutated — its digest no longer matches entry #5&apos;s stored <span style={s("font-family:'JetBrains Mono',monospace")}>prev</span>, and the break cascades to the tip.</div>
          )}
          <div style={s("margin-top:16px;border:1px solid #EDF1F5;border-radius:12px;overflow:hidden")}>
            <div style={s("display:grid;grid-template-columns:44px 120px 1.7fr 96px 150px;gap:0;font-size:10px;letter-spacing:0.08em;text-transform:uppercase;color:#94A3B8;font-weight:600;padding:10px 14px;background:#FBFCFD;border-bottom:1px solid #EDF1F5")}>
              <div>Seq</div><div>Timestamp</div><div>Action</div><div>Actor</div><div>SHA-256</div>
            </div>
            {V.ledgerRows.map((row: any, i: number) => (
              <div key={i} style={{ ...s("display:grid;grid-template-columns:44px 120px 1.7fr 96px 150px;gap:0;align-items:center;padding:9px 14px;border-bottom:1px solid #F4F7FA"), background: row.bg }}>
                <div style={{ ...s("font-family:'JetBrains Mono',monospace;font-size:12px;font-weight:600"), color: row.seqColor }}>{row.seq}</div>
                <div style={s("font-family:'JetBrains Mono',monospace;font-size:11px;color:#475569")}>{row.ts}</div>
                <div style={{ ...s("font-size:12px;display:flex;align-items:center;gap:7px"), color: row.actionColor }}><span style={s(row.dotSt)} /><span style={{ fontFamily: MONO }}>{row.action}</span></div>
                <div style={s("font-family:'JetBrains Mono',monospace;font-size:11px;color:#94A3B8")}>{row.actor}</div>
                <div style={{ ...s("font-family:'JetBrains Mono',monospace;font-size:11px;letter-spacing:-0.02em"), color: row.hashColor }}>{row.hash}</div>
              </div>
            ))}
          </div>
        </section>

        <div style={s("text-align:center;font-size:11px;color:#94A3B8;margin-top:26px;line-height:1.6")}>PRAHARÍ · self-contained analyst view for INC-001 · all figures are fixtures from the reconstructed incident.<br />Graph coloring is the system&apos;s own computed anomaly score — never the ground-truth label. Respects reduced-motion.</div>
      </div>
    );
  }
}
