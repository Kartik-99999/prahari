// Typed client for the Prahari BFF gateway.
// Base URL from NEXT_PUBLIC_API_BASE (default http://localhost:8000).

export const API_BASE =
  process.env.NEXT_PUBLIC_API_BASE ?? "http://localhost:8000";

// ---- response types --------------------------------------------------------

export interface Health {
  status: string;
  datastores: Record<string, string>;
}

export interface MetricsSlate {
  scenario: string;
  ueba: { roc_auc: number; recall_at_1pct_fpr: number; malicious: number; benign: number };
  fusion: {
    top_incident: string;
    incident_malicious_recall: string;
    weak_signals: number;
    weak_recovered: number;
    incident_precision: number;
    has_lateral_path: boolean;
  };
  attribution: {
    technique_accuracy: string;
    technique_accuracy_pct: number;
    events_labeled: number;
    false_attributions: number;
  };
  soar: { automation_coverage_pct: number; auto: number; gated: number; total: number };
  mttd: {
    confirmed_at: string;
    attack_start: string;
    exfil_complete: string;
    mttd_days_after_foothold: number;
    dwell_days_before_exfil: number;
    industry_mean_dwell_days: number;
  };
  mttr: { auto_containment_latency_seconds: number; auto_steps_executed: number; note: string };
  auditability: {
    ledger_entries: number;
    chain_verified: boolean;
    head_hash: string;
    append_only_trigger: boolean;
    tamper_detection: string;
  };
}

export interface IncidentSummary {
  id: string;
  score: number;
  n_events: number;
  span_days: number;
  hosts: string[];
  status: string;
  mttd_days: number | null;
}

export interface EventDetail {
  event_id: string;
  timestamp: string;
  activity: string;
  user: string | null;
  host: string | null;
  src_ip: string | null;
  dst_ip: string | null;
  dst_port: number | null;
  process_name: string | null;
  cmdline: string | null;
  file_path: string | null;
  anomaly_score: number | null;
  fused_score: number | null;
  inferred_technique: string | null;
  agent_technique: string | null;
  reasons: string[];
}

export interface KillChainStep {
  tactic: string;
  technique_id: string;
  narrative: string;
}

export interface CampaignAssessment {
  summary?: string;
  threat_profile?: string;
  advisory_citations?: string[];
}

export interface NextMove {
  predicted_technique: string;
  tactic: string;
  rationale: string;
  recommended_defensive_action: string;
}

export interface IncidentDetail {
  id: string;
  score: number;
  status: string;
  agent_mode: string;
  hosts: string[];
  users: string[];
  external_ips: string[];
  n_events: number;
  span_days: number;
  first_seen: string;
  last_seen: string;
  lateral_path: { present: boolean; path: string[] };
  mttd: MetricsSlate["mttd"] | Record<string, never>;
  events: EventDetail[];
  kill_chain: KillChainStep[];
  campaign_assessment: CampaignAssessment;
  next_moves: NextMove[];
}

export interface GraphNode {
  id: string;
  label: string;
  type: string;
}
export interface GraphEdge {
  source: string;
  target: string;
  type: string;
  malicious: boolean;
  anomaly_score: number | null;
  fused_score: number | null;
  technique: string | null;
  ts: string | null;
  event_id: string | null;
  reasons: string[];
}
export interface GraphData {
  nodes: GraphNode[];
  edges: GraphEdge[];
}

export interface PlaybookAction {
  idx: number;
  action: string;
  target: string;
  blast_radius: "LOW" | "MEDIUM" | "HIGH";
  gate: "auto" | "human";
  status: string;
  rationale: string;
  approver: string | null;
}

export interface DecisionResp {
  incident_id: string;
  playbook: PlaybookAction[];
  ledger_head_hash: string | null;
  ledger_entries: number;
  chain_verified: boolean;
}

export interface AuditEntry {
  seq: number;
  ts: string;
  actor: string;
  action: string;
  target: string | null;
  decision: string | null;
  blast_radius: string | null;
  prev_hash: string;
  entry_hash: string;
}
export interface AuditResp {
  entries: AuditEntry[];
  verify: { ok: boolean; entries?: number; head_hash?: string; broken_seq?: number; reason?: string };
}

// ---- fetchers --------------------------------------------------------------

async function getJSON<T>(path: string): Promise<T> {
  const res = await fetch(`${API_BASE}${path}`, { cache: "no-store" });
  if (!res.ok) throw new Error(`GET ${path} -> ${res.status}`);
  return res.json() as Promise<T>;
}

export const api = {
  health: () => getJSON<Health>("/api/health"),
  slate: () => getJSON<MetricsSlate>("/api/metrics/slate"),
  incidents: () => getJSON<IncidentSummary[]>("/api/incidents"),
  incident: (id: string) => getJSON<IncidentDetail>(`/api/incidents/${id}`),
  graph: (id: string) => getJSON<GraphData>(`/api/incidents/${id}/graph`),
  playbook: (id: string) => getJSON<PlaybookAction[]>(`/api/incidents/${id}/playbook`),
  audit: () => getJSON<AuditResp>("/api/audit"),
  decision: async (
    id: string,
    idx: number,
    body: { decision: "approve" | "deny"; approver: string },
  ): Promise<DecisionResp> => {
    const res = await fetch(`${API_BASE}/api/incidents/${id}/actions/${idx}/decision`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(body),
    });
    if (!res.ok) throw new Error(`POST decision -> ${res.status}`);
    return res.json() as Promise<DecisionResp>;
  },
};
