export function ScenarioIntro({ onPlay }: { onPlay: () => void }) {
  return (
    <div className="absolute inset-0 z-30 flex items-center justify-center rounded-md bg-bg/82 backdrop-blur-sm">
      <div className="hairline max-w-xl rounded-lg bg-panel/95 p-6 text-center glow-accent">
        <div className="text-[10px] uppercase tracking-[0.18em] text-accent">
          Scenario · Critical Infrastructure
        </div>
        <h3 className="mt-2 text-lg font-semibold text-text">
          State Examinations Authority — “exam-records” database
        </h3>
        <p className="mt-2 text-sm leading-relaxed text-muted">
          A national examinations body (CBSE-style): clerks on workstations, a
          domain controller, and the crown-jewel <span className="font-mono text-text">DB-EXAMS</span>{" "}
          server holding millions of candidates’ results. Baseline operations look
          normal — until a patient, low-and-slow adversary moves in over 21 days.
        </p>
        <p className="mt-2 text-xs text-faint">
          Press play to replay what Prahari detected, attributed, and contained —
          May&nbsp;1 → May&nbsp;21, 2026.
        </p>
        <button
          type="button"
          onClick={onPlay}
          className="mt-4 inline-flex items-center gap-2 rounded-md border border-accent/50 bg-accent/15 px-4 py-2 text-sm font-medium text-accent transition-prahari hover:bg-accent/25"
        >
          ▶ Play attack replay
        </button>
      </div>
    </div>
  );
}
