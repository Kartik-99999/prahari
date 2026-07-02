#!/usr/bin/env python3
"""PRAHARÍ OT/ICS evaluation — frozen UEBA + graph fusion on the PLC attack.

Runs the FROZEN loop on the OT scenario and reports, honestly:
  * single-event UEBA detection (ROC/PR, recall at FPR budgets) — limited because
    the IT-centric features cannot see the Modbus function code, so setpoint
    WRITES look like the benign 24/7 read polling;
  * graph FUSION + incident assembly — PRAHARÍ's contribution: it correlates the
    weak write events with the strongly-anomalous engineering-tool / pivot events
    (shared host within the window) and recovers them into one incident.

Writes an `ot` section into metrics_slate.json and a dark-theme PNG.
Self-contained (--no-write everywhere); never touches the scenario-1 Neo4j graph.
"""

from __future__ import annotations

import json
import os
import sys
from datetime import datetime
from pathlib import Path

_REPO_ROOT = Path(__file__).resolve().parents[2]
if str(_REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(_REPO_ROOT))

os.environ.setdefault(
    "PRAHARI_SCENARIO_YAML",
    str(_REPO_ROOT / "packages" / "scenario" / "ot_scenario.yaml"),
)

import matplotlib  # noqa: E402

matplotlib.use("Agg")
import matplotlib.pyplot as plt  # noqa: E402
import numpy as np  # noqa: E402
import pandas as pd  # noqa: E402
from sklearn.metrics import (  # noqa: E402
    average_precision_score,
    roc_auc_score,
    roc_curve,
)

from services.graph import incidents as inc_mod  # noqa: E402
from services.graph.fuse import (  # noqa: E402
    build_similarity_graph,
    compute_idf,
    graph_entities,
    load_event_data,
    run_fusion,
)
from services.graph.schema import load_host_map  # noqa: E402

OT = _REPO_ROOT / "data" / "ot"
EVENTS, SCORES, GT = (
    OT / "events.jsonl",
    OT / "ueba_scores.csv",
    OT / "ground_truth.json",
)
SLATE = _REPO_ROOT / "data" / "metrics_slate.json"
PNG = _REPO_ROOT / "docs" / "ot_detection.png"
LATERAL_PORTS = {445, 3389, 5985, 5986, 502}
# Which slate section to write (baseline runs use "ot_it_only") and whether to
# skip the PNG (baseline runs don't own the committed figure).
SECTION = os.environ.get("PRAHARI_OT_SLATE_SECTION", "ot")
SKIP_PNG = os.environ.get("PRAHARI_OT_PNG") == "skip"

BG, PANEL, GRID, TEXT = "#0A0E14", "#121823", "#243044", "#E2E8F0"
TEAL, RED, AMBER = "#2DD4BF", "#EF4444", "#FACC15"


def _lateral_pairs(events, hm):
    pairs = set()
    for e in events:
        a = (e.get("actor") or {}).get("host")
        sip, dip = (e.get("src") or {}).get("ip"), (e.get("dst") or {}).get("ip")
        dport = (e.get("dst") or {}).get("port")
        if e["activity"] == "auth":
            sh = hm.resolve_host(sip)
            if sh and a and sh != a and hm.is_internal(sip):
                pairs.add(frozenset({sh, a}))
        if e["activity"] == "network" and dport in LATERAL_PORTS:
            dh = hm.resolve_host(dip)
            if dh and a and dh != a:
                pairs.add(frozenset({a, dh}))
    return pairs


def _plot(df, y, caught, roc, prauc, recall1):
    fpr, tpr, _ = roc_curve(y, df["anomaly_score"].to_numpy())
    fig, (ax1, ax2) = plt.subplots(1, 2, figsize=(13, 5.2))
    fig.patch.set_facecolor(BG)
    for ax in (ax1, ax2):
        ax.set_facecolor(PANEL)
        ax.tick_params(colors=TEXT)
        for s in ax.spines.values():
            s.set_color(GRID)
        ax.grid(True, color=GRID, alpha=0.4, lw=0.6)

    ax1.plot(fpr, tpr, color=TEAL, lw=2.2, label=f"UEBA ROC (AUC={roc:.3f})")
    ax1.plot([0, 1], [0, 1], color=GRID, ls="--", lw=1)
    ax1.set_xlabel("False positive rate", color=TEXT)
    ax1.set_ylabel("True positive rate", color=TEXT)
    ax1.set_title("Single-event UEBA, frozen (cross-domain)", color=TEXT)
    ax1.legend(facecolor=PANEL, edgecolor=GRID, labelcolor=TEXT, loc="lower right")

    t0 = df["ts_dt"].min()
    hrs = (df["ts_dt"] - t0).dt.total_seconds() / 3600.0
    ben = ~y
    ax2.scatter(
        hrs[ben], df["anomaly_score"][ben], s=8, c=GRID, alpha=0.5, label="benign"
    )
    is_caught = df["event_id"].isin(caught).to_numpy()
    rec = y & is_caught
    mis = y & ~is_caught
    ax2.scatter(
        hrs[mis],
        df["anomaly_score"][mis],
        s=42,
        c=AMBER,
        marker="x",
        label="malicious — missed @1% FPR",
    )
    ax2.scatter(
        hrs[rec],
        df["anomaly_score"][rec],
        s=52,
        c=RED,
        edgecolor="white",
        lw=0.5,
        label="malicious — alarms @1% FPR",
    )
    ax2.set_xlabel("hours since start", color=TEXT)
    ax2.set_ylabel("UEBA anomaly_score", color=TEXT)
    ax2.set_title(f"Attack events alarmed (recall@1%FPR {recall1:.0%})", color=TEXT)
    ax2.legend(
        facecolor=PANEL, edgecolor=GRID, labelcolor=TEXT, loc="upper right", fontsize=8
    )

    fig.suptitle(
        "PRAHARÍ — OT/ICS PLC setpoint attack (held-out, frozen)",
        color=TEXT,
        fontsize=14,
        fontweight="bold",
    )
    fig.tight_layout(rect=[0, 0, 1, 0.96])
    PNG.parent.mkdir(parents=True, exist_ok=True)
    fig.savefig(PNG, dpi=130, facecolor=BG)
    plt.close(fig)


def main() -> None:
    hm = load_host_map()
    events = [
        json.loads(line) for line in EVENTS.read_text().splitlines() if line.strip()
    ]
    gt = json.loads(GT.read_text())
    mal = {e["event_id"] for e in gt["events"]}

    # feature mode: did this run include the OT-native columns? (G7 vs baseline)
    feat = pd.read_csv(OT / "ueba_features.csv")
    ot_mode = "ot_modbus_write" in feat.columns

    # Modbus WRITE events (wire-observable: port 502 + write function code)
    write_ids = {
        e["event_id"]
        for e in events
        if e["activity"] == "network"
        and (e.get("dst") or {}).get("port") == 502
        and "write" in (((e.get("raw") or {}).get("detail")) or "")
    }
    mal_writes = write_ids & mal
    benign_writes = write_ids - mal

    df, entities = load_event_data(EVENTS, SCORES)
    g = build_similarity_graph(
        df, graph_entities(entities), compute_idf(graph_entities(entities), len(df))
    )
    fused = run_fusion(g, df)

    lat = _lateral_pairs(events, hm)
    inc_mod._has_lateral = lambda hosts: any(p <= set(hosts) for p in lat)  # type: ignore
    incidents = inc_mod.assemble(fused, entities, g)
    mal_counts = [len(set(i["member_event_ids"]) & mal) for i in incidents]
    top_i = (
        max(range(len(incidents)), key=lambda i: mal_counts[i]) if incidents else None
    )
    top = incidents[top_i] if top_i is not None else {"member_event_ids": [], "id": "-"}
    members = set(top["member_event_ids"])
    union = (
        set().union(*[set(i["member_event_ids"]) for i in incidents])
        if incidents
        else set()
    )

    sdf = pd.read_csv(SCORES)
    sdf["y"] = sdf["event_id"].isin(mal)
    y, sc = sdf["y"].to_numpy(), sdf["anomaly_score"].to_numpy()
    roc, prauc = float(roc_auc_score(y, sc)), float(average_precision_score(y, sc))
    det = {}
    for tf in (0.01, 0.05):
        thr = float(np.quantile(sc[~y], 1 - tf))
        det[f"{int(tf*100)}pct"] = round(
            float(((sc >= thr) & y).sum() / max(1, y.sum())), 4
        )

    tp = len(members & mal)
    inc_recall = tp / len(mal) if mal else 0.0
    union_recall = len(union & mal) / len(mal) if mal else 0.0

    # UEBA detection set @1% FPR + which ICS stages it surfaces + detection latency
    thr1 = float(np.quantile(sc[~y], 0.99))
    alarm_ids = set(sdf.loc[sc >= thr1, "event_id"])
    caught = set(sdf.loc[(sc >= thr1) & sdf["y"], "event_id"])
    write_caught = len(mal_writes & caught)
    benign_write_alarms = len(benign_writes & alarm_ids)
    tech_of = {e["event_id"]: e["mitre_technique"] for e in gt["events"]}
    name_of = {e["mitre_technique"]: e["mitre_name"] for e in gt["events"]}
    surfaced = sorted({tech_of[e] for e in caught})
    missed_tech = sorted({tech_of[e] for e in mal} - set(surfaced))
    tsmap = dict(zip(fused["event_id"], fused["ts_dt"]))
    first_mal = min(datetime.fromisoformat(e["timestamp"]) for e in gt["events"])
    caught_times = sorted(tsmap[e] for e in caught)
    mttd_h = (
        (caught_times[0].to_pydatetime() - first_mal).total_seconds() / 3600.0
        if caught_times
        else None
    )

    if not SKIP_PNG:
        _plot(fused, y, caught, roc, prauc, len(caught) / len(mal) if mal else 0.0)

    feat_y = feat["event_id"].isin(mal)
    benign_offhours = round(float(feat.loc[~feat_y, "is_offhours"].mean()), 3)

    recovered = len((members & mal) - caught)
    if ot_mode:
        ueba_note = (
            "OT-native behavioural features active (write-function-code + "
            f"first-writer→PLC novelty): {write_caught}/{len(mal_writes)} malicious "
            f"Modbus writes alarm at 1% FPR (benign operator writes alarmed: "
            f"{benign_write_alarms}/{len(benign_writes)} — routine writer→PLC pairs "
            "are learned normal). The program-download tool and SCADA pivot alarm "
            "as before."
        )
    else:
        ueba_note = (
            "IT-only baseline: the program-download tool (T0843) and the SCADA "
            f"pivot alarm, but only {write_caught}/{len(mal_writes)} malicious "
            "Modbus setpoint WRITES do — function-code (read vs write) is not an "
            "IT feature, so writes look like the benign 24/7 polling."
        )

    result = {
        "scenario": "OT/ICS Modbus-SCADA, unauthorized PLC setpoint/logic write (held-out)",
        "frozen_from": (
            "scenario-1 core (UEBA weights, IForest 200/rs42, fusion TAU=0.90 — unchanged)"
            + (
                " + OT-native behavioural features (G7)"
                if ot_mode
                else " — IT-only features (baseline)"
            )
        ),
        "feature_mode": "ot_native" if ot_mode else "it_only_baseline",
        "events": len(sdf),
        "malicious": int(y.sum()),
        "ics_techniques": gt["distinct_techniques"],
        "benign_offhours_fraction": benign_offhours,
        "modbus_writes": {
            "malicious_total": len(mal_writes),
            "malicious_alarmed_at_1pct_fpr": write_caught,
            "benign_total": len(benign_writes),
            "benign_alarmed_at_1pct_fpr": benign_write_alarms,
        },
        "ueba_single_event": {
            "roc_auc": round(roc, 4),
            "pr_auc": round(prauc, 4),
            "recall_at_1pct_fpr": det["1pct"],
            "recall_at_5pct_fpr": det["5pct"],
            "ics_techniques_surfaced_at_1pct_fpr": [
                f"{t} ({name_of.get(t)})" for t in surfaced
            ],
            "ics_techniques_missed": [f"{t} ({name_of.get(t)})" for t in missed_tech],
            "note": ueba_note,
        },
        "fusion_incident": {
            "incidents_raised": len(incidents),
            "top_incident": top.get("id"),
            "top_incident_recall": round(inc_recall, 4),
            "union_recall_across_incidents": round(union_recall, 4),
            "events_recovered_beyond_1pct_alarms": recovered,
            "note": (
                f"fusion recovers {recovered} additional events beyond the 1%-FPR "
                "alarm set at the frozen TAU=0.90. Design context: this attack is a "
                "single rogue engineer; the similarity graph excludes the user pivot "
                "(to avoid benign drag in IT cases), so correlation leans on "
                "host/time adjacency here. User-pivoted OT correlation remains "
                "future work."
            ),
        },
        "mttd_hours_after_first_malicious": (
            round(mttd_h, 2) if mttd_h is not None else None
        ),
        "attribution_note": (
            "ATT&CK-for-ICS techniques (T0859/T0843/T0836/T0855) are out "
            "of scope for the enterprise (T10xx) mapper; OT attribution is "
            "an honest gap. Detection here is behavioural + correlation."
        ),
        "png": str(PNG.relative_to(_REPO_ROOT)),
    }
    slate = json.loads(SLATE.read_text()) if SLATE.exists() else {}
    slate[SECTION] = result
    SLATE.write_text(json.dumps(slate, indent=2))

    print("=" * 76)
    mode_str = "OT-NATIVE FEATURES (G7)" if ot_mode else "IT-ONLY BASELINE"
    print(f"  PRAHARÍ — OT/ICS DETECTION (held-out, {mode_str})")
    print("=" * 76)
    print(
        f"  {len(sdf)} events, {int(y.sum())} malicious | ICS techs: {', '.join(gt['distinct_techniques'])}"
    )
    print(
        f"  single-event UEBA: ROC {roc:.3f}  PR {prauc:.3f}  "
        f"recall@1%FPR {det['1pct']*100:.0f}%  @5%FPR {det['5pct']*100:.0f}%"
    )
    print(
        f"     benign off-hours fraction {benign_offhours} -> off-hours alone is weak (24/7 polling)"
    )
    print(
        f"     ICS stages SURFACED @1%FPR: {surfaced or '—'}  | MISSED: {missed_tech or '—'}"
    )
    print(
        f"  MTTD (first attack alarm): {result['mttd_hours_after_first_malicious']} h after first malicious"
    )
    print(
        f"     Modbus writes: malicious {write_caught}/{len(mal_writes)} alarmed @1%FPR"
        f" | benign {benign_write_alarms}/{len(benign_writes)} alarmed"
    )
    print(
        f"  FUSION/incident (frozen TAU): {len(incidents)} raised, top {top.get('id')} "
        f"recall {tp}/{len(mal)} ({inc_recall*100:.0f}%), +{recovered} beyond 1%-FPR alarms"
    )
    print(f"  wrote '{SECTION}' section -> {SLATE}")
    if not SKIP_PNG:
        print(f"  wrote {PNG}")


if __name__ == "__main__":
    main()
