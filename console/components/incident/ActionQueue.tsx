"use client";

import { useState } from "react";
import { Panel } from "@/components/ui/Panel";
import { BlastChip } from "@/components/ui/BlastChip";
import { api, type PlaybookAction } from "@/lib/api";

const APPROVER = "soc-lead@exams.gov.local";

function StatusCell({ a }: { a: PlaybookAction }) {
  if (a.gate === "auto" || a.status === "auto-executed")
    return <span className="text-success">✓ auto-executed</span>;
  if (a.status === "approved")
    return (
      <span className="text-success">
        ✓ approved <span className="text-faint">· {a.approver}</span>
      </span>
    );
  if (a.status === "denied") return <span className="text-red">✗ denied</span>;
  return <span className="text-amber">awaiting approval</span>;
}

export function ActionQueue({
  incidentId,
  initial,
  armed = true,
}: {
  incidentId: string;
  initial: PlaybookAction[];
  armed?: boolean;
}) {
  const [actions, setActions] = useState<PlaybookAction[]>(initial);
  const [busy, setBusy] = useState<number | null>(null);
  const [ledgerHead, setLedgerHead] = useState<string | null>(null);
  const [entries, setEntries] = useState<number | null>(null);
  const [error, setError] = useState<string | null>(null);

  async function decide(idx: number, decision: "approve" | "deny") {
    setBusy(idx);
    setError(null);
    try {
      const resp = await api.decision(incidentId, idx, { decision, approver: APPROVER });
      setActions(resp.playbook);
      setLedgerHead(resp.ledger_head_hash);
      setEntries(resp.ledger_entries);
    } catch (e) {
      setError(e instanceof Error ? e.message : String(e));
    } finally {
      setBusy(null);
    }
  }

  const autoN = actions.filter((a) => a.gate === "auto").length;
  const gatedN = actions.length - autoN;

  return (
    <Panel
      title="Response Action Queue"
      subtitle={
        armed
          ? `${autoN} auto-executed · ${gatedN} human-gated`
          : "queued — awaiting incident confirmation"
      }
      right={
        ledgerHead ? (
          <span className="font-mono text-[10px] text-success">
            ledger head {ledgerHead.slice(0, 12)} · {entries} entries
          </span>
        ) : (
          <span className="font-mono text-[10px] text-faint">
            blast-radius gated
          </span>
        )
      }
    >
      <div className={`space-y-1.5 ${armed ? "" : "opacity-50"}`}>
        {actions.map((a) => (
          <div
            key={a.idx}
            className="hairline grid grid-cols-[auto_1fr_auto] items-center gap-3 rounded-md bg-panel-2/40 px-3 py-2"
          >
            <span className="font-mono text-[10px] text-faint">
              {String(a.idx + 1).padStart(2, "0")}
            </span>
            <div className="min-w-0">
              <div className="flex items-center gap-2">
                <span className="font-mono text-sm text-text">{a.action}</span>
                <span className="font-mono text-xs text-muted">→ {a.target}</span>
                <BlastChip level={a.blast_radius} />
              </div>
              <div className="mt-0.5 truncate text-[11px] text-faint">
                {a.rationale}
              </div>
            </div>
            <div className="flex items-center gap-2 text-xs">
              {!armed ? (
                <span className="font-mono text-faint">queued</span>
              ) : a.gate === "human" && a.status === "pending" ? (
                <>
                  <button
                    type="button"
                    disabled={busy === a.idx}
                    onClick={() => decide(a.idx, "approve")}
                    className="rounded border border-success/50 bg-success/10 px-2.5 py-1 font-medium text-success transition-prahari hover:bg-success/20 disabled:opacity-50"
                  >
                    {busy === a.idx ? "…" : "Approve"}
                  </button>
                  <button
                    type="button"
                    disabled={busy === a.idx}
                    onClick={() => decide(a.idx, "deny")}
                    className="rounded border border-red/50 bg-red/10 px-2.5 py-1 font-medium text-red transition-prahari hover:bg-red/20 disabled:opacity-50"
                  >
                    Deny
                  </button>
                </>
              ) : (
                <StatusCell a={a} />
              )}
            </div>
          </div>
        ))}
      </div>
      {error && <p className="mt-2 text-xs text-red">decision failed: {error}</p>}
    </Panel>
  );
}
