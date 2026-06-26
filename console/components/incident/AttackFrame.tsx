import type { IncidentDetail } from "@/lib/api";

const TECH_NAMES: Record<string, string> = {
  T1566: "Phishing",
  T1059: "Command & Scripting",
  T1078: "Valid Accounts",
  T1003: "OS Cred Dumping",
  T1021: "Remote Services",
  T1560: "Archive Collected Data",
  T1005: "Data from Local System",
  T1071: "App Layer Protocol",
  T1041: "Exfil over C2",
  T1070: "Indicator Removal",
  T1486: "Data Encrypted (Impact)",
};

// focused lane view: only the tactics in play, ordered along the kill chain,
// with two predicted lanes at the end.
const LANES: { tactic: string; techs: string[]; predictedLane?: boolean }[] = [
  { tactic: "Initial Access", techs: ["T1566"] },
  { tactic: "Execution", techs: ["T1059"] },
  { tactic: "Persistence", techs: ["T1078"] },
  { tactic: "Credential Access", techs: ["T1003"] },
  { tactic: "Lateral Movement", techs: ["T1021"] },
  { tactic: "Collection", techs: ["T1560", "T1005"] },
  { tactic: "Command & Control", techs: ["T1071"] },
  { tactic: "Exfiltration", techs: ["T1041"] },
  { tactic: "Defense Evasion", techs: ["T1070"], predictedLane: true },
  { tactic: "Impact", techs: ["T1486"], predictedLane: true },
];

function Cell({
  code,
  status,
}: {
  code: string;
  status: "observed" | "predicted" | "pending" | "idle";
}) {
  if (status === "observed")
    return (
      <div className="rounded border border-red/60 bg-red/15 px-2 py-1.5 glow-red">
        <div className="font-mono text-xs font-semibold text-red">{code}</div>
        <div className="text-[9px] leading-tight text-muted">{TECH_NAMES[code]}</div>
        <div className="mt-0.5 text-[8px] uppercase tracking-wider text-red/80">observed</div>
      </div>
    );
  if (status === "pending")
    return (
      <div className="rounded border border-dashed border-faint px-2 py-1.5 opacity-70">
        <div className="font-mono text-xs text-muted">{code}</div>
        <div className="text-[9px] leading-tight text-faint">{TECH_NAMES[code]}</div>
        <div className="mt-0.5 text-[8px] uppercase tracking-wider text-faint">awaiting</div>
      </div>
    );
  if (status === "predicted")
    return (
      <div className="predicted-pulse rounded border border-dashed border-amber bg-amber/10 px-2 py-1.5">
        <div className="font-mono text-xs font-semibold text-amber">{code}</div>
        <div className="text-[9px] leading-tight text-muted">{TECH_NAMES[code]}</div>
        <div className="mt-0.5 text-[8px] uppercase tracking-wider text-amber/80">predicted</div>
      </div>
    );
  return (
    <div className="rounded border border-dashed border-border px-2 py-1.5 opacity-40">
      <div className="font-mono text-xs text-faint">{code}</div>
      <div className="text-[9px] leading-tight text-faint">{TECH_NAMES[code]}</div>
    </div>
  );
}

export function AttackFrame({
  incident,
  lit,
}: {
  incident: IncidentDetail;
  lit?: Set<string>;
}) {
  const observed = new Set(incident.kill_chain.map((k) => k.technique_id));
  const predicted = new Set(incident.next_moves.map((m) => m.predicted_technique));

  const status = (code: string): "observed" | "predicted" | "pending" | "idle" => {
    if (observed.has(code)) return lit && !lit.has(code) ? "pending" : "observed";
    if (predicted.has(code)) return "predicted";
    return "idle";
  };

  return (
    <div className="flex h-full flex-col">
      <div className="scroll-thin flex-1 overflow-x-auto">
        <div className="flex min-w-max items-stretch gap-1 pb-2">
          {LANES.map((lane, i) => (
            <div key={lane.tactic} className="flex items-stretch">
              <div
                className={`flex w-32 flex-col rounded-md border p-2 ${
                  lane.predictedLane
                    ? "border-amber/30 bg-amber/[0.03]"
                    : "border-border bg-panel-2/40"
                }`}
              >
                <div className="mb-2 text-center text-[10px] font-medium uppercase leading-tight tracking-wider text-muted">
                  {lane.tactic}
                  {lane.predictedLane && (
                    <span className="ml-1 text-amber">▸</span>
                  )}
                </div>
                <div className="flex flex-1 flex-col justify-center gap-1.5">
                  {lane.techs.map((t) => (
                    <Cell key={t} code={t} status={status(t)} />
                  ))}
                </div>
              </div>
              {i < LANES.length - 1 && (
                <div className="flex items-center px-0.5 text-faint">→</div>
              )}
            </div>
          ))}
        </div>
      </div>

      {/* legend */}
      <div className="mt-2 flex items-center gap-4 border-t border-border pt-2 text-[10px]">
        <span className="flex items-center gap-1.5 text-muted">
          <span className="inline-block h-3 w-3 rounded border border-red/60 bg-red/15" />
          observed (in this incident)
        </span>
        <span className="flex items-center gap-1.5 text-muted">
          <span className="predicted-pulse inline-block h-3 w-3 rounded border border-dashed border-amber bg-amber/10" />
          predicted next move
        </span>
        <span className="ml-auto font-mono text-faint">
          {lit
            ? `${[...observed].filter((c) => lit.has(c)).length}/${observed.size} observed`
            : `${observed.size} observed`}{" "}
          · {incident.next_moves.length} predicted
        </span>
      </div>
    </div>
  );
}
