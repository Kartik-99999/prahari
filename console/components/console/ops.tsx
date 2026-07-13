"use client";
// Operations lenses: Response (attribution + live SOAR gates) and Audit
// (the real hash chain + a clearly-labelled tamper SIMULATION computed
// client-side — the actual Postgres ledger is never touched by it).
import React, { useMemo, useState } from "react";
import s from "./console.module.css";
import { chainOf, heat, type ConsoleModel } from "./derive";

/* ================= Response ================= */
export function ResponseLens(props: {
  model: ConsoleModel;
  live: boolean;
  deciding: number | null;
  onDecide: (idx: number, d: "approve" | "deny") => void;
}) {
  const { model: M, live, deciding, onDecide } = props;
  const autoN = M.actions.filter((a) => a.auto).length;
  const gatedN = M.actions.length - autoN;
  const pct = M.actions.length ? Math.round((autoN / M.actions.length) * 100) : 0;
  return (
    <div style={{ display: "grid", gridTemplateColumns: "1.35fr 1fr", gap: 40, paddingTop: 20 }}>
      <div>
        <div className={s.kicker}>Attribution</div>
        <div className={s.serifH} style={{ fontSize: 21, marginTop: 6 }}>Reconstructed kill chain</div>
        {M.assessment && (
          <div style={{ fontSize: 12.5, color: "var(--ink2)", marginTop: 6, lineHeight: 1.55, maxWidth: "64ch" }}>
            <span style={{ fontWeight: 600, color: "var(--ink)" }}>Assessment:</span> {M.assessment}
          </div>
        )}
        <div style={{ display: "flex", flexDirection: "column", gap: 8, marginTop: 16 }}>
          {M.stations.map((st) => (
            <div key={st.id} style={{ display: "flex", alignItems: "center", gap: 14, background: "#FBFCFD", border: "1px solid var(--line2)", borderRadius: 12, padding: "11px 14px" }}>
              <span className={s.mono} style={{ fontSize: 12, fontWeight: 700, color: "var(--mut)", flex: "0 0 18px" }}>{st.n}</span>
              <span style={{ width: 9, height: 9, borderRadius: "50%", flex: "0 0 auto", background: st.prevented ? "#DC2626" : st.verdict ? "#059669" : heat(st.score).fill }} />
              <span className={s.mono} style={{ flex: "0 0 66px", fontSize: 12.5, fontWeight: 700 }}>{st.id}</span>
              <span style={{ flex: "1 1 auto", minWidth: 0 }}>
                <span style={{ fontSize: 12.5, fontWeight: 600, textDecoration: st.prevented ? "line-through" : "none", textDecorationColor: "#DC2626" }}>{st.name}</span>{" "}
                <span style={{ fontSize: 11, color: "var(--mut)" }}>· {st.tactic}</span>
              </span>
              {st.verdict && (
                <span style={{ fontSize: 9.5, fontWeight: 700, color: st.prevented ? "#B91C1C" : "#047857", background: st.prevented ? "rgba(220,38,38,0.08)" : "rgba(5,150,105,0.10)", border: st.prevented ? "1px solid rgba(220,38,38,0.25)" : "0", borderRadius: 6, padding: "2px 8px", flex: "0 0 auto" }}>
                  {st.verdict}
                </span>
              )}
              <span className={s.mono} style={{ fontSize: 10.5, color: "var(--mut)", flex: "0 0 auto" }}>{st.date}</span>
            </div>
          ))}
        </div>
        {M.predicted.length > 0 && (
          <div style={{ marginTop: 18 }}>
            <div className={s.kicker} style={{ fontSize: 10.5, marginBottom: 9 }}>Predicted next moves</div>
            <div style={{ display: "flex", gap: 8, flexWrap: "wrap" }}>
              {M.predicted.map((p) => (
                <div key={p.id} title={p.rationale} style={{ display: "flex", flexDirection: "column", gap: 1, border: "1.5px dashed #D97706", background: "rgba(217,119,6,0.05)", borderRadius: 9, padding: "8px 11px", animation: "softPulse 2.4s ease-in-out infinite" }}>
                  <span className={s.mono} style={{ fontSize: 11.5, fontWeight: 700, color: "#B45309" }}>{p.id}</span>
                  <span style={{ fontSize: 10, color: "#92400E" }}>{p.name}</span>
                </div>
              ))}
            </div>
          </div>
        )}
      </div>

      <div>
        <div style={{ display: "flex", alignItems: "baseline", justifyContent: "space-between", gap: 10 }}>
          <div>
            <div className={s.kicker}>Response queue</div>
            <div className={s.serifH} style={{ fontSize: 21, marginTop: 6 }}>SOAR actions</div>
          </div>
          <div style={{ textAlign: "right" }}>
            <span className={s.mono} style={{ fontSize: 12, fontWeight: 700 }}>{pct}%</span>
            <div style={{ fontSize: 10, color: "var(--mut)" }}>
              {autoN} auto · {gatedN} human-gated
            </div>
          </div>
        </div>
        <div style={{ display: "flex", flexDirection: "column", gap: 7, marginTop: 14 }}>
          {M.actions.map((a) => {
            const approved = /approved/.test(a.status);
            const denied = /denied/.test(a.status);
            const pending = !a.auto && !approved && !denied;
            const iconBg = a.auto ? "#059669" : approved ? "#059669" : denied ? "#DC2626" : "#D97706";
            const tag = a.auto ? "auto-executed" : approved ? "✓ approved" : denied ? "✕ denied" : "awaiting approval";
            const tagC = a.auto || approved ? "#047857" : denied ? "#B91C1C" : "#B45309";
            const tagBg = a.auto || approved ? "rgba(5,150,105,0.10)" : denied ? "rgba(220,38,38,0.08)" : "rgba(217,119,6,0.10)";
            const canDecide = live && pending;
            return (
              <div key={a.idx} style={{ display: "flex", alignItems: "center", gap: 11, border: "1px solid var(--line2)", borderRadius: 12, padding: "10px 12px", background: pending ? "rgba(217,119,6,0.04)" : "#FBFCFD" }}>
                <span style={{ flex: "0 0 26px", width: 26, height: 26, borderRadius: 8, display: "flex", alignItems: "center", justifyContent: "center", fontSize: 13, fontWeight: 700, color: "#fff", background: iconBg }}>
                  {denied ? "✕" : pending ? "⏸" : "✓"}
                </span>
                <div style={{ flex: "1 1 auto", minWidth: 0 }}>
                  <div style={{ fontSize: 12.5, fontWeight: 600 }}>{a.name}</div>
                  <div className={s.mono} style={{ fontSize: 10.5, color: "var(--mut)" }}>
                    {a.target} · blast {a.blast}
                    {a.approver ? ` · by ${a.approver}` : ""}
                  </div>
                  {a.rationale && <div style={{ fontSize: 11, color: "var(--mut)", lineHeight: 1.5, marginTop: 5 }}>{a.rationale}</div>}
                </div>
                {canDecide && (
                  <span style={{ display: "flex", gap: 6, flex: "0 0 auto" }}>
                    <button className={`${s.pillBtn} ${s.focusable}`} disabled={deciding === a.idx} onClick={() => onDecide(a.idx, "approve")} style={{ padding: "6px 14px", fontSize: 11, fontWeight: 700, background: "#059669", color: "#fff", opacity: deciding === a.idx ? 0.5 : 1 }}>
                      {deciding === a.idx ? "…" : "Approve"}
                    </button>
                    <button className={`${s.pillBtn} ${s.focusable}`} disabled={deciding === a.idx} onClick={() => onDecide(a.idx, "deny")} style={{ padding: "6px 14px", fontSize: 11, fontWeight: 700, background: "#fff", color: "#B91C1C", border: "1.5px solid rgba(220,38,38,0.35)", opacity: deciding === a.idx ? 0.5 : 1 }}>
                      Deny
                    </button>
                  </span>
                )}
                <span style={{ flex: "0 0 auto", fontSize: 9.5, fontWeight: 700, letterSpacing: "0.03em", color: tagC, background: tagBg, borderRadius: 6, padding: "3px 8px" }}>{tag}</span>
              </div>
            );
          })}
        </div>
      </div>
    </div>
  );
}

/* ================= Audit ================= */
export function AuditLens({ model: M }: { model: ConsoleModel }) {
  const [tamper, setTamper] = useState(false);
  const [simChain, setSimChain] = useState<string[] | null>(null);
  const MUT = Math.min(3, Math.max(0, M.ledger.length - 2));

  const toggleTamper = () => {
    if (tamper) {
      setTamper(false);
      setSimChain(null);
    } else {
      setTamper(true);
      chainOf(M.ledger, MUT).then(setSimChain);
    }
  };

  const rows = useMemo(
    () =>
      M.ledger.map((r, i) => {
        const broken = tamper && i >= MUT;
        const mutated = tamper && i === MUT;
        const hash = tamper
          ? simChain
            ? simChain[i].slice(0, 14) + "…"
            : "…"
          : r.hash
            ? String(r.hash).slice(0, 14) + "…"
            : "—";
        return { ...r, broken, mutated, hashText: hash };
      }),
    [M.ledger, tamper, simChain, MUT],
  );

  const grid = "44px 118px 1.6fr 118px 92px 148px";
  return (
    <div style={{ paddingTop: 20 }}>
      <div style={{ display: "flex", alignItems: "flex-start", justifyContent: "space-between", gap: 16, flexWrap: "wrap" }}>
        <div>
          <div className={s.kicker}>Tamper-evident ledger</div>
          <div className={s.serifH} style={{ fontSize: 21, marginTop: 6 }}>SHA-256 hash chain · append-only</div>
          <div style={{ fontSize: 12, color: "var(--ink2)", marginTop: 5, maxWidth: "60ch", lineHeight: 1.5 }}>
            Each entry hashes the previous entry&apos;s digest. Mutate any row and every downstream hash breaks — the chain can&apos;t be silently edited.
          </div>
        </div>
        <button className={`${s.pillBtn} ${s.focusable}`} onClick={toggleTamper} style={{ border: `1.5px solid ${tamper ? "#DC2626" : "#D1D5DB"}`, background: tamper ? "#DC2626" : "#fff", color: tamper ? "#fff" : "var(--navy)", padding: "9px 18px", fontSize: 12.5 }}>
          {tamper ? "↺ Restore ledger" : "⚠ Simulate tamper"}
        </button>
      </div>
      <div className={s.mono} style={{ display: "flex", alignItems: "center", gap: 9, marginTop: 14, fontSize: 11, color: "#64748B", flexWrap: "wrap" }}>
        <span className={s.dot} style={{ background: tamper ? "#DC2626" : "#059669" }} />
        <span>
          verify_chain() → <b style={{ color: tamper ? "#B91C1C" : "#047857" }}>{tamper ? "BROKEN (simulated)" : M.auditMeta.ok ? "ok" : "BROKEN"}</b>
        </span>
        <span>· {M.auditMeta.entries} entries</span>
        {M.auditMeta.head && !tamper && (
          <span>
            · head <b style={{ color: "#4F46B8" }}>{M.auditMeta.head.slice(0, 12)}…</b>
          </span>
        )}
        <span>· append-only (UPDATE/DELETE blocked by trigger)</span>
      </div>
      {tamper && (
        <div style={{ display: "flex", alignItems: "center", gap: 8, marginTop: 14, background: "rgba(220,38,38,0.06)", border: "1px solid rgba(220,38,38,0.25)", borderRadius: 9, padding: "9px 12px", fontSize: 12, color: "#B91C1C" }}>
          <b>⚠ Chain broken (simulation).</b> Entry #{MUT + 1} was mutated — its digest no longer matches the next entry&apos;s stored <span className={s.mono}>prev</span>, and the break cascades to the tip. The real Postgres ledger is untouched.
        </div>
      )}
      <div style={{ marginTop: 16, border: "1px solid var(--line2)", borderRadius: 12, overflow: "hidden" }}>
        <div className={s.thead} style={{ display: "grid", gridTemplateColumns: grid, padding: "10px 14px", background: "#FBFCFD" }}>
          <div>Seq</div>
          <div>Timestamp</div>
          <div>Action</div>
          <div>Decision</div>
          <div>Actor</div>
          <div>SHA-256</div>
        </div>
        {rows.map((r, i) => (
          <div key={i} style={{ display: "grid", gridTemplateColumns: grid, alignItems: "center", padding: "9px 14px", borderBottom: "1px solid #F4F7FA", background: r.mutated ? "rgba(220,38,38,0.07)" : r.broken ? "rgba(220,38,38,0.028)" : "#fff" }}>
            <div className={s.mono} style={{ fontSize: 12, fontWeight: 600, color: r.broken ? "#B91C1C" : "var(--mut)" }}>#{r.seq}</div>
            <div className={s.mono} style={{ fontSize: 11, color: "var(--ink2)" }}>{r.ts}</div>
            <div style={{ fontSize: 12, display: "flex", alignItems: "center", gap: 7, color: r.mutated ? "#B91C1C" : "var(--ink)" }}>
              <span style={{ width: 7, height: 7, borderRadius: "50%", flex: "0 0 auto", background: r.broken ? "#DC2626" : r.actor === "soar" ? "#0D9488" : "#CBD5E1" }} />
              <span className={s.mono}>{r.action}{r.mutated ? " · REWRITTEN" : ""}</span>
            </div>
            <div className={s.mono} style={{ fontSize: 10.5, color: r.mutated ? "#B91C1C" : "#64748B" }}>{r.mutated ? "REWRITTEN" : r.decision ?? "—"}</div>
            <div className={s.mono} style={{ fontSize: 11, color: "var(--mut)" }}>{r.actor}</div>
            <div className={s.mono} style={{ fontSize: 11, letterSpacing: "-0.02em", color: r.broken ? "#DC2626" : "var(--mut)" }}>{r.hashText}</div>
          </div>
        ))}
      </div>
    </div>
  );
}
