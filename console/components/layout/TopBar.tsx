import { Badge } from "@/components/ui/Badge";

export function TopBar({
  incidentId,
  auditOk,
  ledgerEntries,
}: {
  incidentId: string;
  auditOk: boolean;
  ledgerEntries: number;
}) {
  return (
    <header className="sticky top-0 z-20 border-b border-border bg-panel/90 backdrop-blur">
      <div className="flex items-center justify-between gap-4 px-6 py-3">
        {/* wordmark */}
        <div className="flex items-center gap-3">
          <div className="leading-none">
            <span className="select-none text-lg font-semibold tracking-[0.22em] text-text">
              PRAHAR
              <span className="relative inline-block">
                I
                <span className="absolute -top-1.5 left-1/2 -translate-x-1/2 text-saffron text-xs">
                  ´
                </span>
              </span>
            </span>
            <p className="mt-0.5 text-[10px] uppercase tracking-[0.18em] text-faint">
              Cyber Resilience for Critical Infrastructure
            </p>
          </div>
        </div>

        {/* incident selector + status */}
        <div className="flex items-center gap-3">
          <button
            type="button"
            className="hairline flex items-center gap-2 rounded-md bg-panel px-3 py-1.5 text-sm transition-prahari hover:border-faint"
          >
            <span className="pulse-active inline-block h-2 w-2 rounded-full bg-red glow-red" />
            <span className="font-mono text-text">{incidentId}</span>
            <span className="text-faint">▾</span>
          </button>

          <Badge variant={auditOk ? "success" : "red"} mono>
            {auditOk ? "✓ AUDIT VERIFIED" : "✗ AUDIT BROKEN"}
            <span className="text-faint">· {ledgerEntries}</span>
          </Badge>

          {/* Live / Replay toggle (placeholder) */}
          <div className="dev-chrome hairline flex overflow-hidden rounded-md text-xs">
            <span className="bg-accent/15 px-2.5 py-1 font-medium text-accent">
              ● Live
            </span>
            <span className="px-2.5 py-1 text-faint">Replay</span>
          </div>
        </div>
      </div>
    </header>
  );
}
