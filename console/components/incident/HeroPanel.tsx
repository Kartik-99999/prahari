"use client";

import { useState } from "react";
import { Panel } from "@/components/ui/Panel";
import { GraphView } from "@/components/incident/GraphView";
import { AttackFrame } from "@/components/incident/AttackFrame";
import { KillChainSpine } from "@/components/incident/KillChainSpine";
import type { GraphData, IncidentDetail } from "@/lib/api";

type Lens = "story" | "graph" | "attack";

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
  const [tab, setTab] = useState<Lens>(() => {
    // ?view=graph|attack preselects a lens (reproducible captures / deep links)
    if (typeof window !== "undefined") {
      const v = new URLSearchParams(window.location.search).get("view");
      if (v === "graph" || v === "attack") return v;
    }
    return "story";
  });

  const tabBtn = (id: Lens, label: string, q: string) => (
    <button
      type="button"
      onClick={() => setTab(id)}
      aria-pressed={tab === id}
      className={`flex items-center gap-1.5 rounded-md px-2.5 py-1 text-xs font-medium transition-prahari ${
        tab === id ? "bg-accent/10 text-accent" : "text-faint hover:text-muted"
      }`}
    >
      {label}
      <span className={`hidden font-sans sm:inline ${tab === id ? "text-accent/70" : "text-faint"}`}>
        {q}
      </span>
    </button>
  );

  const subtitle =
    tab === "story"
      ? "the kill chain as one story — foothold → exfil, in the order it happened"
      : tab === "graph"
        ? "entities & edges coloured by Prahari's own anomaly heat — malicious actions light up, benign context recedes"
        : "observed techniques vs predicted next moves";

  return (
    <Panel
      title="Provenance Graph & ATT&CK Kill Chain"
      subtitle={subtitle}
      right={
        <div className="hairline flex gap-0.5 rounded-md p-0.5">
          {tabBtn("story", "◔ Story", "what happened")}
          {tabBtn("graph", "◇ Graph", "how connected")}
          {tabBtn("attack", "▦ ATT&CK", "what tradecraft")}
        </div>
      }
    >
      {tab === "story" ? (
        <div className="py-4">
          <KillChainSpine incident={incident} graph={graph} t={t} />
        </div>
      ) : (
        <div className="h-[520px]">
          {tab === "graph" ? (
            <GraphView graph={graph} t={t} />
          ) : (
            <AttackFrame incident={incident} lit={lit} />
          )}
        </div>
      )}
    </Panel>
  );
}
