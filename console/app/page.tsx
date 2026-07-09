import { api } from "@/lib/api";
import { TopBar } from "@/components/layout/TopBar";
import { MetricsRibbon } from "@/components/layout/MetricsRibbon";
import { CorrelatorStrip } from "@/components/incident/CorrelatorStrip";
import { Workspace } from "@/components/incident/Workspace";
import { AuditStrip } from "@/components/incident/AuditStrip";

// fetched live from the BFF at request time (never prerendered at build)
export const dynamic = "force-dynamic";

const INCIDENT_ID = "INC-001";

export default async function Home() {
  let data;
  try {
    const [incident, playbook, audit, slate, graph] = await Promise.all([
      api.incident(INCIDENT_ID),
      api.playbook(INCIDENT_ID),
      api.audit(),
      api.slate(),
      api.graph(INCIDENT_ID),
    ]);
    data = { incident, playbook, audit, slate, graph };
  } catch (e) {
    return (
      <div className="flex min-h-screen flex-col items-center justify-center gap-3 px-6 text-center">
        <div className="text-lg font-semibold text-red">BFF unreachable</div>
        <p className="max-w-md text-sm text-muted">
          Could not reach the Prahari API at{" "}
          <span className="font-mono text-faint">
            {process.env.NEXT_PUBLIC_API_BASE ?? "http://localhost:8000"}
          </span>
          . Start it with <span className="font-mono text-accent">make api</span>.
        </p>
        <p className="font-mono text-xs text-faint">
          {e instanceof Error ? e.message : String(e)}
        </p>
      </div>
    );
  }

  const { incident, playbook, audit, slate, graph } = data;

  return (
    <div className="flex min-h-full flex-col">
      <TopBar
        incidentId={incident.id}
        auditOk={audit.verify.ok}
        ledgerEntries={audit.entries.length}
      />
      <main className="mx-auto w-full max-w-[1440px] flex-1 space-y-5 px-6 py-6">
        <MetricsRibbon slate={slate} />
        <CorrelatorStrip fusion={slate.fusion} />
        <Workspace incident={incident} graph={graph} playbook={playbook} />
        <AuditStrip audit={audit} />
      </main>
      <footer className="dev-chrome border-t border-border px-5 py-3 text-center text-[11px] text-faint">
        Prahari · ingest → UEBA → graph fusion → ATT&amp;CK attribution → SOAR →
        tamper-evident audit · {slate.scenario}
      </footer>
    </div>
  );
}
