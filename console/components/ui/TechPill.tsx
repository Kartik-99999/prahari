export function TechPill({
  code,
  name,
  active = false,
}: {
  code: string;
  name?: string;
  active?: boolean;
}) {
  return (
    <span
      className={`inline-flex items-center gap-1.5 rounded border px-2 py-1 font-mono text-xs transition-prahari ${
        active
          ? "border-accent/50 bg-accent/10 text-accent"
          : "border-border bg-panel-2 text-text"
      }`}
      title={name ? `${code} — ${name}` : code}
    >
      <span className="font-semibold">{code}</span>
      {name && <span className="font-sans text-[11px] text-muted">{name}</span>}
    </span>
  );
}
