import { Badge } from "@/components/ui/Badge";
import { ThreatDot } from "@/components/ui/ThreatDot";
import { briefUrl, type IncidentDetail } from "@/lib/api";

function ChipRow({ label, items, mono = false }: { label: string; items: string[]; mono?: boolean }) {
  return (
    <div className="flex items-start gap-2">
      <span className="mt-1 w-16 shrink-0 text-[10px] uppercase tracking-wider text-faint">
        {label}
      </span>
      <div className="flex flex-wrap gap-1.5">
        {items.map((it) => (
          <span
            key={it}
            className={`hairline rounded bg-panel-2 px-2 py-0.5 text-xs text-text ${
              mono ? "font-mono" : ""
            }`}
          >
            {it}
          </span>
        ))}
      </div>
    </div>
  );
}

export function IncidentHeader({ incident }: { incident: IncidentDetail }) {
  const mttd = incident.mttd as Record<string, number | string>;
  return (
    <section className="hairline relative overflow-hidden rounded-lg bg-panel">
      <div className="absolute inset-y-0 left-0 w-1 bg-red glow-red" />
      <div className="grid grid-cols-1 gap-5 p-5 lg:grid-cols-[auto_1fr_auto]">
        {/* score */}
        <div className="flex items-center gap-4">
          <div className="flex flex-col items-center">
            <ThreatDot score={0.95} size={14} />
            <div className="mt-2 font-mono text-4xl font-bold leading-none text-red">
              {incident.score.toFixed(2)}
            </div>
            <div className="mt-1 text-[10px] uppercase tracking-wider text-faint">
              incident score
            </div>
          </div>
          <div className="h-16 w-px bg-border" />
          <div>
            <div className="flex items-center gap-2">
              <span className="font-mono text-xl font-semibold text-text">
                {incident.id}
              </span>
              <Badge variant="red">{incident.status.toUpperCase()}</Badge>
            </div>
            <div className="mt-1 text-xs text-muted">
              low-and-slow APT · {incident.span_days}d span ·{" "}
              {incident.n_events} correlated events
            </div>
            {incident.lateral_path.present && (
              <div className="mt-1 font-mono text-xs text-orange">
                lateral: {incident.lateral_path.path.join(" → ")}
              </div>
            )}
          </div>
        </div>

        {/* entities */}
        <div className="flex flex-col justify-center gap-2 border-y border-border py-3 lg:border-x lg:border-y-0 lg:px-5">
          <ChipRow label="Hosts" items={incident.hosts} mono />
          <ChipRow label="Users" items={incident.users} mono />
          <ChipRow label="Ext IPs" items={incident.external_ips} mono />
        </div>

        {/* MTTD */}
        <div className="flex flex-col justify-center gap-1">
          <div className="text-[10px] uppercase tracking-wider text-faint">
            mean time to detect
          </div>
          <div className="font-mono text-2xl font-bold text-amber">
            {mttd.mttd_days_after_foothold}d
          </div>
          <div className="text-[11px] text-muted">
            confirmed {String(mttd.confirmed_at).slice(0, 10)} ·{" "}
            <span className="text-success">
              {mttd.dwell_days_before_exfil}d before exfil
            </span>
          </div>
        </div>
      </div>

      {/* campaign one-liner + analyst brief */}
      <div className="flex items-center justify-between gap-4 border-t border-border bg-panel-2/50 px-5 py-2.5">
        <p className="text-xs text-muted">{incident.campaign_assessment.summary}</p>
        <a
          href={briefUrl(incident.id)}
          target="_blank"
          rel="noreferrer"
          className="hairline shrink-0 rounded-md bg-panel px-2.5 py-1 font-mono text-[11px] text-accent transition-prahari hover:border-accent/50 focus-visible:outline focus-visible:outline-2 focus-visible:outline-accent"
          title="One-page analyst brief (Markdown) — why it fired, kill chain, response, assurance"
        >
          analyst brief ↗
        </a>
      </div>
    </section>
  );
}
