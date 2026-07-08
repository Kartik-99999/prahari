#!/usr/bin/env python3
"""Prahari UEBA feature extraction (behavioural only — NO severity, NO labels).

Processes events in strict TIMESTAMP order and emits one feature row per event.
All novelty/rarity/velocity features use streaming "seen-sets" and rolling
windows updated *after* each event is scored, so a feature reflects only what
was known strictly before (plus the current event) — there is no lookahead.

INTEGRITY: this module never reads ``severity`` or ``raw.label``/``gt_*``.
Detection inputs are purely behavioural. ``FEATURE_COLUMNS`` is the exact set of
numeric columns fed to the models downstream.

Cold-start note: during the first simulated day every (user,host), process and
destination is genuinely unseen, so novelty features fire for benign events too.
That is realistic baseline-learning behaviour and is expected to contribute
early false positives until per-entity baselines warm up.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import sys
from collections import Counter, defaultdict, deque
from datetime import datetime, timedelta
from pathlib import Path

import pandas as pd

_REPO_ROOT = Path(__file__).resolve().parents[2]
if str(_REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(_REPO_ROOT))

from services.graph.schema import load_host_map  # noqa: E402

DEFAULT_EVENTS = _REPO_ROOT / "data" / "events.jsonl"
DEFAULT_OUT = _REPO_ROOT / "data" / "ueba_features.csv"

OFFHOURS_START, OFFHOURS_END = 8, 19  # "normal" window is 08:00-19:00
WINDOW = timedelta(hours=24)

# The exact behavioural feature columns fed to the detector. NB: no `severity`,
# no `gt_*`, no label. (Boolean features are emitted as 0/1 ints.)
FEATURE_COLUMNS = [
    "hour_of_day",
    "is_offhours",
    "is_weekend",
    "new_user_host",
    "new_process_on_host",
    "new_external_dst_for_host",
    "first_external_auth_src",
    "process_global_rarity",
    "user_host_rarity",
    "distinct_hosts_touched",
    "distinct_external_dsts",
    "external_dst",
    "external_auth_src",
]

# OT-native behavioural features (G7). Emitted ONLY when the event stream
# actually contains Modbus traffic (dst.port 502), so IT-only runs produce a
# bit-identical feature matrix. Disable explicitly with PRAHARI_OT_FEATURES=0
# (used to measure the IT-only baseline on OT data).
# INTEGRITY: derived from dst.port + the wire-observable protocol text in
# raw["detail"] (function code). raw["label"] / gt_* are never read.
OT_FEATURE_COLUMNS = [
    "ot_modbus_write",  # write function-code (5/6/15/16) — benign writes exist
    "ot_new_write_pair",  # first Modbus WRITE ever from this host to this dst
    "ot_write_pair_rarity",  # 1/(1+count): rare writer→PLC pairs stay elevated
]
MODBUS_PORT = 502
MODBUS_WRITE_FCS = {5, 6, 15, 16}
_FC_RE = re.compile(r"\bfc=(\d+)\b")

# ML-2 sequence feature (opt-in, PRAHARI_SEQ_FEATURES=1). Low-and-slow attacks are
# SEQUENCE anomalies: the individual events look benign, but the *order* per entity
# is unusual. A streaming order-1 Markov model scores each event by the rarity of
# the (previous_token -> current_token) transition for that entity — O(1)/event,
# no lookahead, no labels. Default OFF => the feature matrix is bit-identical.
SEQ_FEATURE_COLUMNS = ["seq_transition_rarity"]

# Metadata columns carried alongside features (NOT model inputs).
META_COLUMNS = ["event_id", "entity", "ts", "activity"]


def _read_events(path: Path) -> list[dict]:
    rows = []
    with path.open() as f:
        for line in f:
            line = line.strip()
            if line:
                rows.append(json.loads(line))
    # Stable sort by timestamp (then event_id) to guarantee deterministic order.
    rows.sort(key=lambda e: (e["timestamp"], e["event_id"]))
    return rows


class FeatureBuilder:
    def __init__(self, host_internal_ips: set[str]):
        self.internal_ips = host_internal_ips
        # streaming seen-sets / counters (state = everything before current event)
        self.seen_user_host: set[tuple] = set()
        self.seen_proc_host: set[tuple] = set()
        self.seen_ext_dst_host: set[tuple] = set()
        self.seen_ext_auth_src: set[str] = set()
        self.proc_count: Counter = Counter()
        self.uh_count: Counter = Counter()
        self.host_window: dict[str, deque] = defaultdict(
            deque
        )  # user -> deque[(ts,host)]
        self.extdst_window: dict[str, deque] = defaultdict(
            deque
        )  # user -> deque[(ts,ip)]
        # OT: (host, dst_ip) pairs that have issued a Modbus WRITE before
        self.seen_write_pair: set[tuple] = set()
        self.write_pair_count: Counter = Counter()
        self.saw_modbus = False
        # ML-2: per-entity order-1 Markov transition counts (streaming).
        self.last_token: dict[str, str] = {}
        self.trans_count: Counter = Counter()  # (entity, prev, curr) -> n
        self.from_count: Counter = Counter()  # (entity, prev) -> n

    def is_external(self, ip: str | None) -> bool:
        return bool(ip) and ip not in self.internal_ips

    def _evict(self, dq: deque, now: datetime) -> None:
        cutoff = now - WINDOW
        while dq and dq[0][0] < cutoff:
            dq.popleft()

    def row(self, ev: dict) -> dict:
        ts = datetime.fromisoformat(ev["timestamp"])
        activity = ev["activity"]
        actor = ev.get("actor") or {}
        user = actor.get("user")
        host = actor.get("host")
        entity = user or host or "unknown"
        proc = ev.get("process") or {}
        pname = proc.get("name")
        dst = ev.get("dst") or {}
        src = ev.get("src") or {}
        dst_ip = dst.get("ip")
        src_ip = src.get("ip")

        dst_ext = self.is_external(dst_ip)
        src_ext_auth = activity == "auth" and self.is_external(src_ip)

        # --- OT / Modbus (wire-observable only: port + function code) ---
        # INTEGRITY: reads ONLY raw["detail"] (protocol text); never raw["label"].
        is_modbus = activity == "network" and (dst.get("port") == MODBUS_PORT)
        ot_write = 0
        if is_modbus:
            self.saw_modbus = True
            m = _FC_RE.search((ev.get("raw") or {}).get("detail") or "")
            if m and int(m.group(1)) in MODBUS_WRITE_FCS:
                ot_write = 1
        ot_new_write_pair = int(
            bool(ot_write) and (host, dst_ip) not in self.seen_write_pair
        )
        # rarity decays with observed writes (routine HMI pairs -> ~0), like the
        # existing process/user-host rarity features
        ot_write_pair_rarity = (
            1.0 / (self.write_pair_count[(host, dst_ip)] + 1) if ot_write else 0.0
        )

        # --- novelty (pre-update state) ---
        new_user_host = int((user, host) not in self.seen_user_host)
        new_proc = int(
            activity == "process"
            and pname is not None
            and (host, pname) not in self.seen_proc_host
        )
        new_ext_dst = int(dst_ext and (host, dst_ip) not in self.seen_ext_dst_host)
        first_ext_auth = int(src_ext_auth and src_ip not in self.seen_ext_auth_src)

        # --- rarity (pre-update counts) ---
        proc_rarity = (
            (1.0 / (self.proc_count[pname] + 1))
            if (activity == "process" and pname)
            else 0.0
        )
        uh_rarity = 1.0 / (self.uh_count[(user, host)] + 1)

        # --- velocity (24h rolling per entity; include current) ---
        hw = self.host_window[entity]
        if host:
            hw.append((ts, host))
        self._evict(hw, ts)
        distinct_hosts = len({h for _, h in hw})

        ew = self.extdst_window[entity]
        if dst_ext:
            ew.append((ts, dst_ip))
        self._evict(ew, ts)
        distinct_ext = len({ip for _, ip in ew})

        # --- ML-2 sequence transition rarity (pre-update counts, no lookahead) ---
        # token folds the external flag into the activity so e.g. an "auth then
        # external-network" pivot reads as a distinct transition from benign flows.
        token = activity + ("|ext" if (dst_ext or src_ext_auth) else "")
        prev = self.last_token.get(entity)
        seq_rarity = 0.0  # neutral for an entity's first event / unseen from-state
        if prev is not None:
            denom = self.from_count[(entity, prev)]
            if denom > 0:
                p = self.trans_count[(entity, prev, token)] / denom
                seq_rarity = 1.0 - p

        feats = {
            "hour_of_day": ts.hour,
            "is_offhours": int(ts.hour < OFFHOURS_START or ts.hour >= OFFHOURS_END),
            "is_weekend": int(ts.weekday() >= 5),
            "new_user_host": new_user_host,
            "new_process_on_host": new_proc,
            "new_external_dst_for_host": new_ext_dst,
            "first_external_auth_src": first_ext_auth,
            "process_global_rarity": round(proc_rarity, 6),
            "user_host_rarity": round(uh_rarity, 6),
            "distinct_hosts_touched": distinct_hosts,
            "distinct_external_dsts": distinct_ext,
            "external_dst": int(dst_ext),
            "external_auth_src": int(src_ext_auth),
            "ot_modbus_write": ot_write,
            "ot_new_write_pair": ot_new_write_pair,
            "ot_write_pair_rarity": round(ot_write_pair_rarity, 6),
            "seq_transition_rarity": round(seq_rarity, 6),
        }

        # --- update state AFTER feature computation (no lookahead) ---
        if prev is not None:
            self.trans_count[(entity, prev, token)] += 1
            self.from_count[(entity, prev)] += 1
        self.last_token[entity] = token
        if ot_write:
            self.seen_write_pair.add((host, dst_ip))
            self.write_pair_count[(host, dst_ip)] += 1
        self.seen_user_host.add((user, host))
        if activity == "process" and pname:
            self.seen_proc_host.add((host, pname))
            self.proc_count[pname] += 1
        if dst_ext:
            self.seen_ext_dst_host.add((host, dst_ip))
        if src_ext_auth:
            self.seen_ext_auth_src.add(src_ip)
        self.uh_count[(user, host)] += 1

        return {
            "event_id": ev["event_id"],
            "entity": entity,
            "ts": ev["timestamp"],
            "activity": activity,
            **feats,
        }


def build_features(events_path: Path = DEFAULT_EVENTS) -> pd.DataFrame:
    hm = load_host_map()
    builder = FeatureBuilder(hm.internal_ips)
    rows = [builder.row(ev) for ev in _read_events(events_path)]
    # OT columns only when the stream contains Modbus traffic (and not disabled):
    # IT-only streams yield a bit-identical matrix to the pre-G7 pipeline.
    include_ot = builder.saw_modbus and os.environ.get("PRAHARI_OT_FEATURES") != "0"
    include_seq = os.environ.get("PRAHARI_SEQ_FEATURES") == "1"
    cols = (
        META_COLUMNS
        + FEATURE_COLUMNS
        + (OT_FEATURE_COLUMNS if include_ot else [])
        + (SEQ_FEATURE_COLUMNS if include_seq else [])
    )
    df = pd.DataFrame(rows, columns=cols)
    if builder.saw_modbus:
        mode = "ENABLED" if include_ot else "DISABLED (PRAHARI_OT_FEATURES=0)"
        print(f"[features] Modbus traffic detected — OT-native features {mode}")
    if include_seq:
        print("[features] ML-2 sequence transition-rarity feature ENABLED")
    return df


def assert_no_leakage(columns: list[str]) -> None:
    """Hard guardrail: the feature matrix must contain neither severity nor any
    ground-truth/label column."""
    banned_exact = {
        "severity",
        "label",
        "is_malicious",
        "attack_stage",
        "stage_name",
        "mitre_technique",
        "mitre_name",
    }
    for c in columns:
        cl = c.lower()
        assert cl not in banned_exact, f"LEAKAGE: forbidden column '{c}'"
        assert not cl.startswith("gt_"), f"LEAKAGE: ground-truth column '{c}'"
        assert "malicious" not in cl, f"LEAKAGE: label-like column '{c}'"


def main() -> None:
    ap = argparse.ArgumentParser(description="Extract UEBA behavioural features.")
    ap.add_argument("--events", type=Path, default=DEFAULT_EVENTS)
    ap.add_argument("--out", type=Path, default=DEFAULT_OUT)
    args = ap.parse_args()

    assert_no_leakage(FEATURE_COLUMNS)
    df = build_features(args.events)
    assert_no_leakage(list(df.columns))  # belt-and-suspenders on the emitted frame
    args.out.parent.mkdir(parents=True, exist_ok=True)
    df.to_csv(args.out, index=False)

    model_cols = [c for c in df.columns if c not in META_COLUMNS]
    print(f"Wrote {len(df)} feature rows -> {args.out}")
    print(f"Feature columns ({len(model_cols)}): {model_cols}")
    print("\nfeature summary (numeric):")
    print(df[model_cols].describe().round(3).T.to_string())


if __name__ == "__main__":
    main()
