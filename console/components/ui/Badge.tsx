import type { ReactNode } from "react";

const VARIANTS = {
  accent: "border-accent/40 bg-accent/10 text-accent",
  success: "border-success/40 bg-success/10 text-success",
  muted: "border-border bg-panel-2 text-muted",
  amber: "border-amber/40 bg-amber/10 text-amber",
  red: "border-red/50 bg-red/10 text-red",
} as const;

export function Badge({
  children,
  variant = "muted",
  mono = false,
  className = "",
}: {
  children: ReactNode;
  variant?: keyof typeof VARIANTS;
  mono?: boolean;
  className?: string;
}) {
  return (
    <span
      className={`inline-flex items-center gap-1 rounded-full border px-2 py-0.5 text-[11px] font-medium ${
        mono ? "font-mono" : ""
      } ${VARIANTS[variant]} ${className}`}
    >
      {children}
    </span>
  );
}
