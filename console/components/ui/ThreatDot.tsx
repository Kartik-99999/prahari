// Maps a 0..1 anomaly/fused score onto the amber -> red threat ramp.
export function threatColor(score: number): string {
  if (score >= 0.85) return "#dc2626"; // critical
  if (score >= 0.7) return "#ef4444"; // red
  if (score >= 0.5) return "#f97316"; // orange
  if (score >= 0.3) return "#d97706"; // amber
  return "#94a3b8"; // faint
}

export function ThreatDot({
  score,
  size = 10,
  showValue = false,
}: {
  score: number | null | undefined;
  size?: number;
  showValue?: boolean;
}) {
  const s = score ?? 0;
  const color = threatColor(s);
  const critical = s >= 0.85;
  return (
    <span className="inline-flex items-center gap-1.5">
      <span className="relative inline-flex" style={{ width: size, height: size }}>
        {critical && (
          <span
            className="threat-ping absolute inset-0 rounded-full"
            style={{ background: color }}
          />
        )}
        <span
          className="relative inline-block rounded-full"
          style={{
            width: size,
            height: size,
            background: color,
            boxShadow: critical ? `0 0 0 3px ${color}22` : undefined,
          }}
        />
      </span>
      {showValue && (
        <span className="font-mono text-xs tabular-nums" style={{ color }}>
          {s.toFixed(3)}
        </span>
      )}
    </span>
  );
}
