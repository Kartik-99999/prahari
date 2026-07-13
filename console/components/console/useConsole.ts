"use client";
// One hook owns all backend I/O. Generic: loads whatever incidents the BFF
// reports, defaults to the top-ranked one, and rebuilds the model on demand.
import { useCallback, useEffect, useRef, useState } from "react";
import { api, type IncidentSummary, type MetricsSlate } from "@/lib/api";
import { buildModel, type ConsoleModel } from "./derive";

export type ConsoleState = {
  status: "loading" | "live" | "offline";
  incidents: IncidentSummary[];
  slate: MetricsSlate | null;
  model: ConsoleModel | null;
};

export type AttackUi = { state: "idle" | "running" | "error"; label: string };

export function useConsole(initialIncident: string | null) {
  const [st, setSt] = useState<ConsoleState>({
    status: "loading",
    incidents: [],
    slate: null,
    model: null,
  });
  const [attack, setAttack] = useState<AttackUi>({ state: "idle", label: "" });
  const [deciding, setDeciding] = useState<number | null>(null);
  const selected = useRef<string | null>(initialIncident);
  const poll = useRef<number>(0);

  const load = useCallback(async (id?: string | null) => {
    try {
      const [slate, incidents] = await Promise.all([api.slate(), api.incidents()]);
      const ranked = [...incidents].sort((a, b) => b.score - a.score);
      const want = id ?? selected.current;
      const pick = ranked.find((x) => x.id === want) ?? ranked[0];
      if (!pick) throw new Error("no incidents");
      selected.current = pick.id;
      const [inc, graph, playbook, audit] = await Promise.all([
        api.incident(pick.id),
        api.graph(pick.id),
        api.playbook(pick.id),
        api.audit(),
      ]);
      const model = buildModel(inc, graph, playbook, audit, slate, incidents);
      if (!model) throw new Error("empty graph");
      setSt({ status: "live", incidents: ranked, slate, model });
      return true;
    } catch {
      setSt((p) => ({ ...p, status: "offline" }));
      return false;
    }
  }, []);

  useEffect(() => {
    load(initialIncident);
    return () => {
      if (poll.current) window.clearInterval(poll.current);
    };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  const selectIncident = useCallback(
    (id: string) => {
      selected.current = id;
      setSt((p) => ({ ...p, status: "loading" }));
      load(id);
    },
    [load],
  );

  const decide = useCallback(
    async (idx: number, decision: "approve" | "deny") => {
      if (!selected.current) return;
      setDeciding(idx);
      try {
        await api.decision(selected.current, idx, {
          decision,
          approver: "analyst@prahari-console",
        });
        await load();
      } catch {
        /* surfaced by state staying unchanged */
      }
      setDeciding(null);
    },
    [load],
  );

  const runAttack = useCallback(async () => {
    if (attack.state === "running") return;
    setAttack({ state: "running", label: "starting…" });
    try {
      await api.attackRun();
    } catch {
      // 409 = already running server-side; just poll it
    }
    poll.current = window.setInterval(async () => {
      let s;
      try {
        s = await api.attackStatus();
      } catch {
        return; // transient — keep polling
      }
      if (s.state === "running") {
        const label = String(s.stage_label || "").split("—")[0].trim();
        setAttack({ state: "running", label: s.stage ? `${s.stage}/6 · ${label}` : "starting…" });
      } else {
        window.clearInterval(poll.current);
        poll.current = 0;
        if (s.state === "done") {
          setAttack({ state: "idle", label: "" });
          await load(null); // fresh run may re-rank incidents — re-pick the top
        } else {
          setAttack({ state: "error", label: "run failed — retry" });
        }
      }
    }, 1500);
  }, [attack.state, load]);

  return { st, attack, deciding, selectIncident, decide, runAttack, reload: load };
}
