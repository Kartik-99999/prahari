const STYLES: Record<string, string> = {
  LOW: "border-success/40 bg-success/10 text-success",
  MEDIUM: "border-amber/40 bg-amber/10 text-amber",
  HIGH: "border-red/50 bg-red/10 text-red glow-red",
};

const LABEL: Record<string, string> = { LOW: "LOW", MEDIUM: "MED", HIGH: "HIGH" };

export function BlastChip({ level }: { level: string }) {
  const key = level.toUpperCase();
  return (
    <span
      className={`inline-flex items-center rounded px-1.5 py-0.5 font-mono text-[10px] font-bold tracking-wider ${
        STYLES[key] ?? STYLES.MEDIUM
      }`}
    >
      {LABEL[key] ?? key}
    </span>
  );
}
