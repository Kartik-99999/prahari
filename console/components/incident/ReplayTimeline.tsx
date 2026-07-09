"use client";

import type { Annotation } from "@/lib/replay";
import { fmtDateTime } from "@/lib/replay";

export function ReplayTimeline({
  t0,
  t1,
  t,
  onScrub,
  playing,
  onTogglePlay,
  speed,
  onSpeed,
  annotations,
  runningScore,
  totalScore,
  mttdFired,
  atEnd,
  onReplay,
  demo,
  onDemo,
}: {
  t0: number;
  t1: number;
  t: number;
  onScrub: (ms: number) => void;
  playing: boolean;
  onTogglePlay: () => void;
  speed: number;
  onSpeed: (s: number) => void;
  annotations: Annotation[];
  runningScore: number;
  totalScore: number;
  mttdFired: boolean;
  atEnd: boolean;
  onReplay: () => void;
  demo: boolean;
  onDemo: () => void;
}) {
  const span = Math.max(1, t1 - t0);
  const pct = (ms: number) => `${Math.min(100, Math.max(0, ((ms - t0) / span) * 100))}%`;
  const scorePct = Math.min(100, totalScore ? (runningScore / totalScore) * 100 : 0);

  return (
    <section className="hairline card rounded-xl bg-panel p-4">
      {/* controls row */}
      <div className="mb-3 flex flex-wrap items-center gap-3">
        <button
          type="button"
          onClick={onTogglePlay}
          className="flex h-8 w-8 items-center justify-center rounded-md border border-accent/50 bg-accent/15 text-accent transition-prahari hover:bg-accent/25"
          aria-label={playing ? "Pause" : "Play"}
        >
          {playing ? "⏸" : atEnd ? "⏮" : "▶"}
        </button>
        <button
          type="button"
          onClick={onReplay}
          className="rounded-md border border-border px-2 py-1 text-xs text-muted transition-prahari hover:text-text"
        >
          ⟲ Replay
        </button>
        <div className="hairline flex gap-0.5 rounded-md p-0.5">
          {[1, 4, 12].map((s) => (
            <button
              key={s}
              type="button"
              onClick={() => onSpeed(s)}
              className={`rounded px-2 py-0.5 text-xs font-mono transition-prahari ${
                speed === s ? "bg-accent/15 text-accent" : "text-faint hover:text-muted"
              }`}
            >
              {s}×
            </button>
          ))}
        </div>

        <span className="font-mono text-sm text-text">{fmtDateTime(t)}</span>

        {/* running incident-heat meter */}
        <div className="ml-auto flex items-center gap-2">
          <span className="text-[10px] uppercase tracking-wider text-faint">
            incident heat Σanom
          </span>
          <div className="h-2 w-28 overflow-hidden rounded-full bg-panel-2">
            <div
              className="h-full rounded-full transition-prahari"
              style={{
                width: `${scorePct}%`,
                background: "linear-gradient(90deg,#0d9488,#d97706,#dc2626)",
              }}
            />
          </div>
          <span className="w-12 font-mono text-sm text-amber tabular-nums">
            {runningScore.toFixed(1)}
          </span>
        </div>

        {/* MTTD status */}
        <span
          className={`rounded-full border px-2 py-0.5 font-mono text-[11px] transition-prahari ${
            mttdFired
              ? "border-success/50 bg-success/10 text-success glow-success"
              : "border-border text-faint"
          }`}
        >
          {mttdFired ? "● INCIDENT CONFIRMED · MTTD 1.66d" : "○ monitoring…"}
        </span>

        <button
          type="button"
          onClick={onDemo}
          className={`rounded-md border px-2 py-1 text-[11px] transition-prahari ${
            demo ? "border-accent/50 text-accent" : "border-border text-faint hover:text-muted"
          }`}
        >
          {demo ? "◉ Demo mode" : "○ Demo mode"}
        </button>
      </div>

      {/* timeline track */}
      <div className="relative h-12">
        {/* annotation labels */}
        {annotations.map((a) => (
          <div
            key={a.label}
            className="absolute top-0 -translate-x-1/2 text-center"
            style={{ left: pct(a.ms) }}
          >
            <div
              className={`whitespace-nowrap font-mono text-[9px] leading-tight ${
                a.kind === "confirm"
                  ? mttdFired
                    ? "text-success"
                    : "text-muted"
                  : a.kind === "prevented"
                    ? "text-success"
                    : "text-red"
              }`}
            >
              {a.label}
            </div>
            <div className="mx-auto mt-0.5 text-[8px] text-faint">
              {new Date(a.ms).toISOString().slice(5, 10)}
            </div>
          </div>
        ))}

        {/* track */}
        <div className="absolute bottom-1 left-0 right-0 h-2 rounded-full bg-panel-2">
          {/* filled */}
          <div
            className="absolute bottom-0 left-0 top-0 rounded-full"
            style={{
              width: pct(t),
              background: "linear-gradient(90deg,#cbd5e1,#94a3b8,#f59e0b,#dc2626)",
            }}
          />
          {/* annotation ticks */}
          {annotations.map((a) => (
            <span
              key={a.label}
              className={`absolute bottom-0 h-2 w-0.5 -translate-x-1/2 ${
                a.kind === "confirm"
                  ? mttdFired
                    ? "bg-success glow-success"
                    : "bg-muted"
                  : a.kind === "prevented"
                    ? "bg-success"
                    : "bg-red"
              }`}
              style={{ left: pct(a.ms) }}
              title={a.label}
            />
          ))}
          {/* playhead */}
          <span
            className="absolute -top-1 h-4 w-1 -translate-x-1/2 rounded bg-text"
            style={{ left: pct(t) }}
          />
        </div>

        {/* invisible scrub input */}
        <input
          type="range"
          min={t0}
          max={t1}
          step={Math.max(1, Math.round(span / 2000))}
          value={t}
          onChange={(e) => onScrub(Number(e.target.value))}
          className="absolute bottom-0 left-0 right-0 h-4 w-full cursor-pointer opacity-0"
          aria-label="replay scrubber"
        />
      </div>
    </section>
  );
}
