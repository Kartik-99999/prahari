import { Panel } from "@/components/ui/Panel";
import { Badge } from "@/components/ui/Badge";
import type { IncidentDetail } from "@/lib/api";

export function GraphPanel({ incident }: { incident: IncidentDetail }) {
  return (
    <Panel
      title="Provenance Graph"
      subtitle="entity correlation · anomaly heat · lateral-movement path"
      right={<Badge variant="muted">next task</Badge>}
      className="h-full"
    >
      <div
        className="relative flex min-h-[360px] flex-col items-center justify-center overflow-hidden rounded-md border border-dashed border-border"
        style={{
          backgroundImage:
            "radial-gradient(circle at 1px 1px, rgba(36,48,68,0.6) 1px, transparent 0)",
          backgroundSize: "22px 22px",
        }}
      >
        {/* teaser of the lateral path the real viz will animate */}
        {incident.lateral_path.present && (
          <div className="mb-6 flex items-center gap-2 font-mono text-sm">
            {incident.lateral_path.path.map((h, i) => (
              <span key={h} className="flex items-center gap-2">
                <span className="hairline rounded bg-panel-2 px-2.5 py-1 text-text">
                  {h}
                </span>
                {i < incident.lateral_path.path.length - 1 && (
                  <span className="text-red">→</span>
                )}
              </span>
            ))}
          </div>
        )}
        <div className="text-center">
          <div className="text-sm font-medium text-muted">
            Provenance graph visualization
          </div>
          <div className="mt-1 text-xs text-faint">
            Neo4j subgraph · {incident.n_events} events across{" "}
            {incident.hosts.length} hosts — lights up from fused_score next task
          </div>
        </div>
      </div>
    </Panel>
  );
}
