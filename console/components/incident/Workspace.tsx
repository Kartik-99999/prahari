"use client";

import { useEffect, useMemo, useState } from "react";
import { IncidentHeader } from "@/components/incident/IncidentHeader";
import { HeroPanel } from "@/components/incident/HeroPanel";
import { AttributionPanel } from "@/components/incident/AttributionPanel";
import { ActionQueue } from "@/components/incident/ActionQueue";
import { ReplayTimeline } from "@/components/incident/ReplayTimeline";
import { ScenarioIntro } from "@/components/incident/ScenarioIntro";
import {
  graphWindow,
  keyEvents,
  parseTs,
  scoreEvents,
  techniqueOnsets,
} from "@/lib/replay";
import type { GraphData, IncidentDetail, PlaybookAction } from "@/lib/api";

const BASE_MS = 38000; // wall-clock ms for a full 1× replay of the window

export function Workspace({
  incident,
  graph,
  playbook,
}: {
  incident: IncidentDetail;
  graph: GraphData;
  playbook: PlaybookAction[];
}) {
  const { t0, t1 } = useMemo(() => graphWindow(graph), [graph]);
  const annotations = useMemo(() => keyEvents(), []);
  const onsets = useMemo(() => techniqueOnsets(graph), [graph]);
  const sEvents = useMemo(() => scoreEvents(graph), [graph]);
  const totalScore = useMemo(
    () => sEvents.reduce((s, e) => s + e.anomaly, 0),
    [sEvents],
  );
  const confirmedMs = useMemo(() => {
    const m = incident.mttd as { confirmed_at?: string };
    const ms = parseTs(m.confirmed_at ?? "2026-05-04T02:13:58");
    return Number.isNaN(ms) ? parseTs("2026-05-04T02:13:58") : ms;
  }, [incident.mttd]);

  const initT = useMemo(() => {
    if (typeof window !== "undefined") {
      const p = new URLSearchParams(window.location.search).get("t");
      if (p) {
        const ms = parseTs(p);
        if (!Number.isNaN(ms)) return Math.min(Math.max(ms, t0), t1);
      }
    }
    return t1; // default: fully revealed
  }, [t0, t1]);

  const [t, setT] = useState(initT);
  const [playing, setPlaying] = useState(false);
  const [speed, setSpeed] = useState(1);
  const [demo, setDemo] = useState(() => {
    // ?demo=1 starts in demo mode (clean 16:9 capture, dev chrome hidden)
    if (typeof window !== "undefined") {
      return new URLSearchParams(window.location.search).get("demo") === "1";
    }
    return false;
  });

  // play loop
  useEffect(() => {
    if (!playing) return;
    let raf = 0;
    let last = performance.now();
    const step = (now: number) => {
      const dt = now - last;
      last = now;
      setT((prev) => {
        const next = prev + ((t1 - t0) / BASE_MS) * speed * dt;
        if (next >= t1) {
          setPlaying(false);
          return t1;
        }
        return next;
      });
      raf = requestAnimationFrame(step);
    };
    raf = requestAnimationFrame(step);
    return () => cancelAnimationFrame(raf);
  }, [playing, speed, t0, t1]);

  // demo mode hides dev chrome (marked .dev-chrome)
  useEffect(() => {
    document.documentElement.classList.toggle("demo", demo);
    return () => document.documentElement.classList.remove("demo");
  }, [demo]);

  const runningScore = useMemo(
    () => sEvents.reduce((s, e) => (e.ms <= t ? s + e.anomaly : s), 0),
    [sEvents, t],
  );
  const lit = useMemo(
    () =>
      new Set(
        Object.entries(onsets)
          .filter(([, ms]) => ms <= t)
          .map(([code]) => code),
      ),
    [onsets, t],
  );
  const armed = t >= confirmedMs;
  const atStart = t <= t0 + (t1 - t0) * 0.002;

  const togglePlay = () => {
    if (t >= t1) {
      setT(t0);
      setPlaying(true);
    } else {
      setPlaying((p) => !p);
    }
  };
  const replay = () => {
    setT(t0);
    setPlaying(true);
  };

  return (
    <div className="space-y-5">
      <ReplayTimeline
        t0={t0}
        t1={t1}
        t={t}
        onScrub={(ms) => {
          setPlaying(false);
          setT(ms);
        }}
        playing={playing}
        onTogglePlay={togglePlay}
        speed={speed}
        onSpeed={setSpeed}
        annotations={annotations}
        runningScore={runningScore}
        totalScore={totalScore}
        mttdFired={armed}
        atEnd={t >= t1}
        onReplay={replay}
        demo={demo}
        onDemo={() => setDemo((d) => !d)}
      />

      <IncidentHeader incident={incident} />

      {armed && (
        <div
          key="confirm-beat"
          className="confirm-beat hairline card flex items-center gap-3 rounded-xl border-success/40 bg-success/[0.07] px-5 py-3"
        >
          <span className="text-lg text-success">✓</span>
          <p className="text-sm text-text">
            <span className="font-semibold text-success">
              C2 severed at confirmation.
            </span>{" "}
            Auto-containment fired ~1.66 days after foothold — the May-21 exfil over
            the (now-blocked) channel never completes.{" "}
            <span className="font-semibold text-success">Breach prevented.</span>
          </p>
        </div>
      )}

      <div className="relative">
        <HeroPanel graph={graph} incident={incident} t={t} lit={lit} />
        {atStart && <ScenarioIntro onPlay={replay} />}
      </div>

      <AttributionPanel incident={incident} />
      <ActionQueue incidentId={incident.id} initial={playbook} armed={armed} />
    </div>
  );
}
