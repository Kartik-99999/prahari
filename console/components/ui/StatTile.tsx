"use client";

import { useEffect, useRef, useState, type ReactNode } from "react";

const TONES = {
  accent: "text-accent",
  success: "text-success",
  amber: "text-amber",
  red: "text-red",
  text: "text-text",
} as const;

// Count a numeric metric up from 0 on mount, preserving any prefix/suffix
// (e.g. "<1s", "1.66d", "92.3%", "10-entry chain"). Non-numeric values (✓)
// render as-is. Respects reduced-motion.
function AnimatedValue({ value }: { value: ReactNode }) {
  const raw = typeof value === "string" ? value : null;
  const m = raw ? raw.match(/^(\D*)(\d[\d,]*(?:\.\d+)?)(.*)$/) : null;
  const reduce =
    typeof window !== "undefined" &&
    !!window.matchMedia?.("(prefers-reduced-motion: reduce)").matches;
  const [shown, setShown] = useState<string | null>(() =>
    m && !reduce ? `${m[1]}0${m[3]}` : null,
  );
  const done = useRef(false);

  useEffect(() => {
    if (!m || done.current || reduce) return;
    done.current = true;
    const [, prefix, numStr, suffix] = m;
    const target = parseFloat(numStr.replace(/,/g, ""));
    const decimals = numStr.includes(".") ? numStr.split(".")[1].length : 0;
    const dur = 620;
    const start = performance.now();
    let raf = 0;
    const step = (now: number) => {
      const p = Math.min(1, (now - start) / dur);
      const eased = 1 - Math.pow(1 - p, 3);
      setShown(`${prefix}${(target * eased).toFixed(decimals)}${suffix}`);
      if (p < 1) raf = requestAnimationFrame(step);
      else setShown(null); // hand back to the exact source value
    };
    raf = requestAnimationFrame(step);
    return () => cancelAnimationFrame(raf);
  }, [m, reduce]);

  return <>{shown ?? value}</>;
}

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
    <div className="hairline card rounded-xl bg-panel px-3.5 py-2.5 transition-prahari hover:border-faint">
      <div className="text-[10px] font-medium uppercase tracking-[0.12em] text-faint">
        {label}
      </div>
      <div className={`mt-1.5 font-mono text-xl leading-none tabular-nums ${TONES[tone]}`}>
        <AnimatedValue value={value} />
      </div>
      {sub && <div className="mt-1 text-[10px] text-faint">{sub}</div>}
    </div>
  );
}
