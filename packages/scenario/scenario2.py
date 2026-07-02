#!/usr/bin/env python3
"""PRAHARÍ scenario 2 generator — malicious INSIDER exfiltration (NO external C2).

A held-out generalization scenario with a kill chain PRAHARÍ was NOT built
around. A trusted analyst (``data.analyst``) with valid credentials slowly
exfiltrates the exam-records database to a removable USB drive over ~3 weeks —
entirely INTERNAL, no external command-and-control. This removes scenario-1's
strongest signals (external destinations / external auth sources), forcing the
FROZEN UEBA weights + fusion thresholds to detect via behaviour alone:
off-hours, new user->host pairings, rare processes, and velocity.

Reuses the frozen ``Generator.generate_benign()`` unchanged (so the benign
baseline is directly comparable); only the attack overlay is new.

Kill chain (distinct ATT&CK techniques):
  T1078 Valid Accounts          — off-hours logons to DB-EXAMS the analyst never uses
  T1087 Account/Dir Discovery   — enumerates the exam-records store
  T1005 Data from Local System  — low-and-slow bulk reads of exam-records (many nights)
  T1074 Data Staged             — copies records to a FILESVR staging share
  T1560 Archive Collected Data  — 7-Zip archive of the staged data
  T1052 Exfil over Physical Med. — writes the archive to a removable USB drive (E: drive)
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path
from typing import Any

_REPO_ROOT = Path(__file__).resolve().parents[2]
if str(_REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(_REPO_ROOT))

from packages.scenario.generator import (  # noqa: E402
    Generator,
    mal_label,
    write_outputs,
)

SCENARIO2_YAML = Path(__file__).resolve().parent / "scenario2.yaml"
DEFAULT_EVENTS = _REPO_ROOT / "data" / "scenario2" / "events.jsonl"
DEFAULT_GT = _REPO_ROOT / "data" / "scenario2" / "ground_truth.json"

INSIDER = "data.analyst"
INSIDER_WS = "WS05"
RECORDS = [
    "/var/lib/exam-records/candidates_2026.csv",
    "/var/lib/exam-records/marks_class10.csv",
    "/var/lib/exam-records/marks_class12.csv",
    "/var/lib/exam-records/answer_keys.csv",
    "/var/lib/exam-records/centre_allotment.csv",
    "/var/lib/exam-records/results_master.csv",
]


def _stage(
    stage: int, name: str, tech: str, tech_name: str, desc: str
) -> dict[str, Any]:
    return {
        "stage": stage,
        "name": name,
        "mitre_technique": tech,
        "mitre_name": tech_name,
        "description": desc,
    }


class InsiderGenerator(Generator):
    def __init__(self, seed: int = 77) -> None:
        super().__init__(seed=seed, scenario_path=SCENARIO2_YAML)

    def generate_attack(self) -> None:  # override: insider overlay (no C2)
        ws_ip = self.host_ip[INSIDER_WS]
        db_ip = self.host_ip["DB-EXAMS"]
        fs_ip = self.host_ip["FILESVR"]

        # bulk-read campaign nights (low and slow, dead of night)
        read_nights = [(6, 23), (9, 0), (12, 1), (16, 2), (20, 23)]

        # --- T1078: off-hours logon to DB-EXAMS the analyst never normally uses
        for i, (day, hour) in enumerate(read_nights):
            st = _stage(
                1,
                "anomalous_valid_account",
                "T1078",
                "Valid Accounts",
                "off-hours logon by a trusted analyst to the exam-records DB server",
            )
            self.add(
                ts=self.ts(day, hour, 5, 0),
                source="auth@DB-EXAMS",
                activity="auth",
                severity=70,
                user=INSIDER,
                host="DB-EXAMS",
                src_ip=ws_ip,
                dst_ip=db_ip,
                dst_port=3389,
                label=mal_label(st),
                detail="insider off-hours RDP to DB-EXAMS",
            )
            # --- T1087/T1083: discovery on the first night
            if i == 0:
                sd = _stage(
                    2,
                    "discovery",
                    "T1087",
                    "Account/Directory Discovery",
                    "enumerates accounts and the exam-records directory tree",
                )
                self.add(
                    ts=self.ts(day, hour, 9, 0),
                    source="edr@DB-EXAMS",
                    activity="process",
                    severity=60,
                    user=INSIDER,
                    host="DB-EXAMS",
                    pname="net.exe",
                    pid=self.rng.randint(2000, 9000),
                    cmdline='net group "Domain Admins" /domain',
                    label=mal_label(sd),
                    detail="account discovery",
                )
                self.add(
                    ts=self.ts(day, hour, 12, 0),
                    source="edr@DB-EXAMS",
                    activity="process",
                    severity=60,
                    user=INSIDER,
                    host="DB-EXAMS",
                    pname="cmd.exe",
                    pid=self.rng.randint(2000, 9000),
                    cmdline="dir /s /b \\\\DB-EXAMS\\exam-records",
                    label=mal_label(sd),
                    detail="directory discovery",
                )
            # --- T1005: bulk read of exam-records (several files each night)
            sr = _stage(
                3,
                "bulk_data_read",
                "T1005",
                "Data from Local System",
                "low-and-slow bulk read of exam-records by the insider",
            )
            for j, rec in enumerate(RECORDS):
                self.add(
                    ts=self.ts(day, hour, 20 + j * 3, 0),
                    source="edr@DB-EXAMS",
                    activity="file",
                    severity=55,
                    user=INSIDER,
                    host="DB-EXAMS",
                    fpath=rec,
                    label=mal_label(sr),
                    detail="bulk exam-records read",
                )

        # --- T1074: stage the collected data to a FILESVR share
        ss = _stage(
            4,
            "data_staged",
            "T1074",
            "Data Staged",
            "copies harvested records to a staging share on FILESVR",
        )
        self.add(
            ts=self.ts(22, 1, 10, 0),
            source="netflow@WS05",
            activity="network",
            severity=58,
            user=INSIDER,
            host=INSIDER_WS,
            src_ip=ws_ip,
            dst_ip=fs_ip,
            dst_port=445,
            label=mal_label(ss),
            detail="SMB copy WS05->FILESVR staging",
        )
        self.add(
            ts=self.ts(22, 1, 12, 0),
            source="edr@WS05",
            activity="process",
            severity=58,
            user=INSIDER,
            host=INSIDER_WS,
            pname="robocopy.exe",
            pid=self.rng.randint(2000, 9000),
            cmdline="robocopy C:\\Temp\\rec \\\\FILESVR\\staging\\exam-records /E",
            label=mal_label(ss),
            detail="staging copy",
        )
        for rec in RECORDS[:3]:
            self.add(
                ts=self.ts(22, 1, 15, 0),
                source="edr@FILESVR",
                activity="file",
                severity=55,
                user=INSIDER,
                host="FILESVR",
                fpath="\\\\FILESVR\\staging\\exam-records\\" + Path(rec).name,
                label=mal_label(ss),
                detail="staged record",
            )

        # --- T1560: archive the staged data on FILESVR
        sa = _stage(
            5,
            "archive_collected_data",
            "T1560",
            "Archive Collected Data",
            "compresses the staged exam-records into a single archive",
        )
        self.add(
            ts=self.ts(24, 2, 5, 0),
            source="edr@FILESVR",
            activity="process",
            severity=62,
            user=INSIDER,
            host="FILESVR",
            pname="7z.exe",
            pid=self.rng.randint(2000, 9000),
            cmdline="7z a -mx9 exam-records.7z \\\\FILESVR\\staging\\exam-records",
            label=mal_label(sa),
            detail="archive collected data",
        )
        self.add(
            ts=self.ts(24, 2, 7, 0),
            source="edr@FILESVR",
            activity="file",
            severity=60,
            user=INSIDER,
            host="FILESVR",
            fpath="\\\\FILESVR\\staging\\exam-records.7z",
            label=mal_label(sa),
            detail="staged archive created",
        )

        # --- T1052: exfiltrate to a removable USB drive (NO network egress)
        se = _stage(
            6,
            "exfil_physical_usb",
            "T1052",
            "Exfiltration Over Physical Medium",
            "writes the archive to a removable USB drive — no external C2",
        )
        self.add(
            ts=self.ts(25, 1, 30, 0),
            source="edr@WS05",
            activity="file",
            severity=66,
            user=INSIDER,
            host=INSIDER_WS,
            fpath="E:\\exfil\\exam-records.7z",
            label=mal_label(se),
            detail="copy archive to removable USB drive",
        )


def main() -> None:
    ap = argparse.ArgumentParser(description="Generate PRAHARÍ scenario-2 (insider).")
    ap.add_argument("--seed", type=int, default=77)
    ap.add_argument("--out", type=Path, default=DEFAULT_EVENTS)
    ap.add_argument("--ground-truth", type=Path, default=DEFAULT_GT)
    args = ap.parse_args()

    gen = InsiderGenerator(seed=args.seed)
    events = gen.generate()
    gt = write_outputs(events, args.seed, args.out, args.ground_truth)
    print(
        f"[scenario2] {gt['total_events']} events "
        f"(benign={gt['benign_count']}, malicious={gt['malicious_count']}) seed={args.seed}"
    )
    print(f"  span {events[0].timestamp.date()} .. {events[-1].timestamp.date()}")
    print(f"  techniques: {', '.join(gt['distinct_techniques'])}")
    print(f"  wrote {args.out}")


if __name__ == "__main__":
    main()
