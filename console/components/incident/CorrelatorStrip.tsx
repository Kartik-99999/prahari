import type { MetricsSlate } from "@/lib/api";

/**
 * The correlator showing its work: which correlation strategy it chose for this
 * telemetry, and the measured evidence behind the choice. The reasoning IS the
 * content — an anchor gauge (external-anchor fraction vs the decision threshold)
 * plus the pivot set it assembled the incident with.
 */
export function CorrelatorStrip({ fusion }: { fusion: MetricsSlate["fusion"] }) {
  const mode = fusion.mode;
  if (!mode) return null; // sidecar not present (older pipeline run)

  const frac = fusion.external_anchor_fraction ?? 0;
  const thr = fusion.threshold ?? 0.15;
  const insider = mode === "insider";
  const pivots = fusion.pivots ?? [];
  // gauge is log-ish for readability at small fractions; cap at 1
  const pct = Math.min(frac, 1) * 100;
  const thrPct = Math.min(thr, 1) * 100;

  return (
    <section
      aria-label="Correlation strategy"
      className="hairline flex flex-wrap items-center gap-x-5 gap-y-2 rounded-lg bg-panel px-4 py-2.5"
    >
      <div className="flex items-center gap-2.5">
        <span className="relative flex h-2 w-2">
          <span className="absolute inline-flex h-full w-full animate-ping rounded-full bg-accent/60 motion-reduce:hidden" />
          <span className="relative inline-flex h-2 w-2 rounded-full bg-accent" />
        </span>
        <span className="text-[10px] uppercase tracking-[0.18em] text-faint">
          correlation strategy
        </span>
        <span className="font-mono text-sm font-semibold text-accent">
          {insider ? "INSIDER" : "EXTERNAL-C2"}
        </span>
        {fusion.auto !== false && (
          <span className="hairline rounded bg-accent/10 px-1.5 py-0.5 text-[10px] font-medium uppercase tracking-wider text-accent">
            auto-selected
          </span>
        )}
      </div>

      {/* the evidence: anchor-fraction gauge against the decision threshold */}
      <div className="flex min-w-[220px] flex-1 items-center gap-3">
        <span className="shrink-0 text-[10px] uppercase tracking-wider text-faint">
          external anchor
        </span>
        <div className="relative h-1.5 flex-1 overflow-hidden rounded-full bg-panel-2">
          <div
            className={`absolute inset-y-0 left-0 rounded-full ${insider ? "bg-amber" : "bg-accent"}`}
            style={{ width: `${Math.max(pct, 1.5)}%` }}
          />
          <div
            className="absolute inset-y-[-2px] w-px bg-faint"
            style={{ left: `${thrPct}%` }}
            title={`decision threshold ${thr}`}
          />
        </div>
        <span className="shrink-0 font-mono text-xs text-muted">
          {frac.toFixed(3)}{" "}
          <span className="text-faint">
            {insider ? "<" : "≥"} {thr}
          </span>
        </span>
      </div>

      <div className="flex items-center gap-1.5">
        <span className="text-[10px] uppercase tracking-wider text-faint">pivots</span>
        {pivots.map((p) => (
          <span
            key={p}
            className={`rounded px-1.5 py-0.5 font-mono text-[10px] ${
              p === "user"
                ? "bg-amber/15 text-amber"
                : "bg-panel-2 text-muted"
            }`}
          >
            {p}
          </span>
        ))}
      </div>

      <p className="dev-chrome w-full text-[11px] leading-snug text-faint">
        {insider
          ? "No external-C2 footprint in the flagged events — the correlator added the user pivot to reconnect an insider's dispersed actions."
          : "Flagged events carry an external-IP anchor — the campaign threads through C2, so the user pivot stays off to avoid dragging in benign same-account activity."}
      </p>
    </section>
  );
}
