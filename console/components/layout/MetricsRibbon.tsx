import { StatTile } from "@/components/ui/StatTile";
import type { MetricsSlate } from "@/lib/api";

export function MetricsRibbon({ slate }: { slate: MetricsSlate }) {
  const mttr = slate.mttr.auto_containment_latency_seconds;
  return (
    <div className="grid grid-cols-2 gap-2 sm:grid-cols-4 lg:grid-cols-7">
      <StatTile
        label="UEBA ROC-AUC"
        value={slate.ueba.roc_auc.toFixed(4)}
        tone="accent"
        sub={`${slate.ueba.malicious} mal / ${slate.ueba.benign} benign`}
      />
      <StatTile
        label="Recall @ 1% FPR"
        value={`${Math.round(slate.ueba.recall_at_1pct_fpr * 100)}%`}
        tone="accent"
        sub="weak-signal detection"
      />
      <StatTile
        label="Technique Acc"
        value={`${slate.attribution.technique_accuracy_pct}%`}
        tone="accent"
        sub={`${slate.attribution.false_attributions} false-attrib`}
      />
      <StatTile
        label="Automation"
        value={`${slate.soar.automation_coverage_pct}%`}
        tone="accent"
        sub={`${slate.soar.auto} auto / ${slate.soar.gated} gated`}
      />
      <StatTile
        label="MTTD"
        value={`${slate.mttd.mttd_days_after_foothold}d`}
        tone="amber"
        sub={`vs ~${slate.mttd.industry_mean_dwell_days}d industry`}
      />
      <StatTile
        label="MTTR"
        value={mttr < 1 ? "<1s" : `${mttr.toFixed(1)}s`}
        tone="success"
        sub="auto-containment"
      />
      <StatTile
        label="Audit"
        value={slate.auditability.chain_verified ? "✓" : "✗"}
        tone={slate.auditability.chain_verified ? "success" : "red"}
        sub={`${slate.auditability.ledger_entries}-entry chain`}
      />
    </div>
  );
}
