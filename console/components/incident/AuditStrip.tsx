import { Panel } from "@/components/ui/Panel";
import { Badge } from "@/components/ui/Badge";
import type { AuditResp } from "@/lib/api";

export function AuditStrip({ audit }: { audit: AuditResp }) {
  const ok = audit.verify.ok;
  return (
    <Panel
      title="Tamper-Evident Audit Ledger"
      subtitle="every detection, attribution & response action — hash-chained, append-only"
      right={
        <Badge variant={ok ? "success" : "red"} mono>
          {ok ? "✓ chain verified" : "✗ chain broken"}
        </Badge>
      }
    >
      <div className="scroll-thin max-h-64 overflow-y-auto">
        <table className="w-full border-collapse text-left font-mono text-[11px]">
          <thead className="sticky top-0 bg-panel text-faint">
            <tr className="border-b border-border">
              <th className="px-2 py-1 font-medium">seq</th>
              <th className="px-2 py-1 font-medium">actor</th>
              <th className="px-2 py-1 font-medium">action</th>
              <th className="px-2 py-1 font-medium">target</th>
              <th className="px-2 py-1 font-medium">decision</th>
              <th className="px-2 py-1 font-medium">prev</th>
              <th className="px-2 py-1 font-medium">entry</th>
            </tr>
          </thead>
          <tbody>
            {audit.entries.map((e) => (
              <tr
                key={e.seq}
                className="border-b border-border/50 transition-prahari hover:bg-panel-2/50"
              >
                <td className="px-2 py-1 text-faint">{e.seq}</td>
                <td className="px-2 py-1 text-muted">{e.actor}</td>
                <td className="px-2 py-1 text-text">{e.action}</td>
                <td className="px-2 py-1 text-muted">{e.target ?? "—"}</td>
                <td className="px-2 py-1 text-muted">{e.decision ?? "—"}</td>
                <td className="px-2 py-1 text-faint">{e.prev_hash.slice(0, 8)}</td>
                <td className="px-2 py-1 text-accent">{e.entry_hash.slice(0, 8)}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
      <p className="mt-2 text-[11px] text-faint">
        Tamper-evident — every action SHA-256 hash-chained to its predecessor; a
        DB trigger blocks UPDATE/DELETE and any silent edit breaks the chain.
      </p>
    </Panel>
  );
}
