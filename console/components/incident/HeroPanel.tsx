"use client";

import { useState } from "react";
import { Panel } from "@/components/ui/Panel";
import { GraphView } from "@/components/incident/GraphView";
import { AttackFrame } from "@/components/incident/AttackFrame";
import type { GraphData, IncidentDetail } from "@/lib/api";

export function HeroPanel({
  graph,
  incident,
  t,
  lit,
}: {
  graph: GraphData;
  incident: IncidentDetail;
  t: number;
  lit: Set<string>;
}) {
  const [tab, setTab] = useState<"graph" | "attack">(() => {
    // ?view=attack preselects the ATT&CK frame (reproducible captures/deep links)
    if (typeof window !== "undefined") {
      const v = new URLSearchParams(window.location.search).get("view");
      if (v === "attack") return "attack";
    }
    return "graph";
  });

  const tabBtn = (id: "graph" | "attack", label: string) => (
    <button
      type="button"
      onClick={() => setTab(id)}
      className={`rounded px-2.5 py-1 text-xs font-medium transition-prahari ${
        tab === id
          ? "bg-accent/15 text-accent"
          : "text-faint hover:text-muted"
      }`}
    >
      {label}
    </button>
  );

  return (
    <Panel
      title="Provenance Graph & ATT&CK Kill Chain"
      subtitle={
        tab === "graph"
          ? "entities & edges coloured by Prahari's own anomaly heat — malicious actions light up, benign context recedes"
          : "observed techniques (heat) vs predicted next moves (pulsing)"
      }
      right={
        <div className="hairline flex gap-0.5 rounded-md p-0.5">
          {tabBtn("graph", "◉ Graph")}
          {tabBtn("attack", "▦ ATT&CK")}
        </div>
      }
    >
      <div className="h-[520px]">
        {tab === "graph" ? (
          <GraphView graph={graph} t={t} />
        ) : (
          <AttackFrame incident={incident} lit={lit} />
        )}
      </div>
    </Panel>
  );
}
