import type { ReactNode } from "react";

const TONES = {
  accent: "text-accent",
  success: "text-success",
  amber: "text-amber",
  red: "text-red",
  text: "text-text",
} as const;

export function StatTile({
  label,
  value,
  sub,
  tone = "text",
}: {
  label: string;
  value: ReactNode;
  sub?: string;
  tone?: keyof typeof TONES;
}) {
  return (
    <div className="hairline rounded-md bg-panel-2/60 px-3 py-2 transition-prahari hover:border-faint">
      <div className="text-[10px] font-medium uppercase tracking-[0.12em] text-faint">
        {label}
      </div>
      <div className={`mt-1 font-mono text-lg leading-none ${TONES[tone]}`}>
        {value}
      </div>
      {sub && <div className="mt-1 text-[10px] text-faint">{sub}</div>}
    </div>
  );
}
