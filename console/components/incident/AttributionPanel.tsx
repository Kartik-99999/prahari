import { Panel } from "@/components/ui/Panel";
import { Badge } from "@/components/ui/Badge";
import { TechPill } from "@/components/ui/TechPill";
import type { IncidentDetail } from "@/lib/api";

const TECH_NAMES: Record<string, string> = {
  T1566: "Phishing",
  T1071: "App Layer Protocol (C2)",
  T1078: "Valid Accounts",
  T1003: "OS Credential Dumping",
  T1021: "Remote Services",
  T1560: "Archive Collected Data",
  T1041: "Exfiltration Over C2",
  T1059: "Command & Scripting",
  T1070: "Indicator Removal",
  T1486: "Data Encrypted for Impact",
  T1005: "Data from Local System",
};

function AgentModeBadge({ mode }: { mode: string }) {
  const live = mode === "live";
  return (
    <Badge variant={live ? "accent" : "muted"}>
      {live ? "● LIVE agent" : "○ deterministic / fallback"}
    </Badge>
  );
}

export function AttributionPanel({ incident }: { incident: IncidentDetail }) {
  const ca = incident.campaign_assessment;
  return (
    <Panel
      title="ATT&CK Attribution"
      subtitle="kill chain · campaign assessment · predicted next moves"
      right={<AgentModeBadge mode={incident.agent_mode} />}
    >
      <div className="space-y-5">
        {/* kill chain */}
        <div>
          <div className="mb-2 text-[10px] uppercase tracking-wider text-faint">
            Reconstructed kill chain
          </div>
          <ol className="space-y-1.5">
            {incident.kill_chain.map((step, i) => (
              <li key={`${step.technique_id}-${i}`} className="flex items-center gap-2.5">
                <span className="font-mono text-[10px] text-faint">{i + 1}</span>
                <span className="w-36 shrink-0 truncate text-[10px] uppercase tracking-wider text-muted">
                  {step.tactic}
                </span>
                <TechPill
                  code={step.technique_id}
                  name={TECH_NAMES[step.technique_id]}
                />
              </li>
            ))}
          </ol>
        </div>

        {/* campaign assessment */}
        <div className="hairline rounded-md bg-panel-2/50 p-3">
          <div className="mb-1 text-[10px] uppercase tracking-wider text-faint">
            Campaign assessment
          </div>
          <p className="text-xs leading-relaxed text-text">{ca.summary}</p>
          {ca.threat_profile && (
            <p className="mt-2 text-xs leading-relaxed text-muted">
              <span className="text-faint">threat profile · </span>
              {ca.threat_profile}
            </p>
          )}
          {ca.advisory_citations && ca.advisory_citations.length > 0 && (
            <div className="mt-2 flex flex-wrap items-center gap-1.5">
              <span className="text-[10px] uppercase tracking-wider text-faint">
                cites
              </span>
              {ca.advisory_citations.map((c) => (
                <span
                  key={c}
                  className="rounded bg-panel px-1.5 py-0.5 font-mono text-[10px] text-accent"
                >
                  {c}
                </span>
              ))}
            </div>
          )}
        </div>

        {/* next moves */}
        <div>
          <div className="mb-2 text-[10px] uppercase tracking-wider text-faint">
            Predicted next moves
          </div>
          <div className="grid grid-cols-1 gap-2 sm:grid-cols-2">
            {incident.next_moves.map((m, i) => (
              <div key={`${m.predicted_technique}-${i}`} className="hairline rounded-md bg-panel-2/40 p-2.5">
                <div className="flex items-center gap-2">
                  <TechPill code={m.predicted_technique} name={TECH_NAMES[m.predicted_technique]} />
                  <span className="text-[10px] uppercase tracking-wider text-faint">
                    {m.tactic}
                  </span>
                </div>
                <p className="mt-1.5 text-[11px] leading-snug text-muted">{m.rationale}</p>
                <p className="mt-1.5 flex gap-1 text-[11px] leading-snug text-accent">
                  <span className="text-faint">▸ defend:</span>
                  {m.recommended_defensive_action}
                </p>
              </div>
            ))}
          </div>
        </div>
      </div>
    </Panel>
  );
}
