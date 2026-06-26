#!/usr/bin/env python3
"""Prahari synthetic telemetry generator.

Emits a deterministic, timestamp-ordered stream of normalized ``SecurityEvent``s
for the government-examinations scenario defined in ``scenario.yaml``:

  (a) a BENIGN business-hours baseline for every entity (with natural off-hours
      and weekend noise so that naive time-based detection is non-trivial), and
  (b) a low-and-slow ATTACK overlay that injects the 6-stage kill chain at its
      scheduled offsets.

Every event is labeled in ``raw["label"]`` with is_malicious / attack_stage /
mitre_technique so the downstream consumer can tally ground truth. The full
ground-truth manifest (malicious event_ids + stage + technique) is written to
``data/ground_truth.json`` for later detection-rate / attribution scoring.

Determinism: all randomness derives from ``random.Random(seed)`` and event_ids
are drawn from that same RNG, so a given --seed reproduces identical event_ids.
"""

from __future__ import annotations

import argparse
import json
import random
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any
from uuid import UUID

import yaml

# Make the repo root importable whether run via `-m` or directly.
_REPO_ROOT = Path(__file__).resolve().parents[2]
if str(_REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(_REPO_ROOT))

from packages.schema import SecurityEvent  # noqa: E402

SCENARIO_PATH = Path(__file__).resolve().parent / "scenario.yaml"
DEFAULT_EVENTS_OUT = _REPO_ROOT / "data" / "events.jsonl"
DEFAULT_GROUND_TRUTH = _REPO_ROOT / "data" / "ground_truth.json"

# Benign content palettes.
PROC_GENERIC = [
    "explorer.exe",
    "outlook.exe",
    "chrome.exe",
    "winword.exe",
    "excel.exe",
    "teams.exe",
    "onedrive.exe",
]
PROC_ADMIN = ["mmc.exe", "powershell.exe", "cmd.exe", "rdpclip.exe", "taskmgr.exe"]
PROC_DB = ["postgres", "pg_dump", "vacuumdb", "backup.sh"]
BENIGN_FILES = [
    r"C:\\Users\\{u}\\Documents\\timetable.xlsx",
    r"C:\\Users\\{u}\\Documents\\results_draft.docx",
    r"C:\\Users\\{u}\\Downloads\\circular.pdf",
    "/var/lib/exam-records/daily_report.csv",
]


def _uuid(rng: random.Random) -> UUID:
    """Deterministic v4 UUID drawn from the seeded RNG."""
    return UUID(int=rng.getrandbits(128), version=4)


def benign_label() -> dict[str, Any]:
    return {
        "is_malicious": False,
        "attack_stage": None,
        "stage_name": None,
        "mitre_technique": None,
        "mitre_name": None,
        "description": "benign baseline",
    }


def mal_label(stage: dict[str, Any], description: str | None = None) -> dict[str, Any]:
    return {
        "is_malicious": True,
        "attack_stage": stage["stage"],
        "stage_name": stage["name"],
        "mitre_technique": stage["mitre_technique"],
        "mitre_name": stage.get("mitre_name"),
        "description": (description or stage.get("description", "")).strip(),
    }


class Generator:
    def __init__(self, seed: int, scenario_path: Path = SCENARIO_PATH) -> None:
        self.seed = seed
        self.rng = random.Random(seed)
        self.scn = yaml.safe_load(scenario_path.read_text())
        self.net = self.scn["network"]
        self.sim = self.scn["simulation"]
        self.start = datetime.fromisoformat(self.sim["start_date"])
        self.days = int(self.sim["days"])
        self.workdays = set(self.net["business_hours"]["workdays"])
        self.bh_start = int(self.net["business_hours"]["start_hour"])
        self.bh_end = int(self.net["business_hours"]["end_hour"])
        self.c2_ip = self.net["external_c2_ip"]
        self.users = self.scn["users"]
        self.hosts = {h["name"]: h for h in self.scn["hosts"]}
        self.host_ip = {h["name"]: h["ip"] for h in self.scn["hosts"]}
        self.events: list[SecurityEvent] = []

    # ---- helpers -------------------------------------------------------
    def ts(
        self, day: int, hour: int, minute: int | None = None, second: int | None = None
    ) -> datetime:
        minute = self.rng.randint(0, 59) if minute is None else minute
        second = self.rng.randint(0, 59) if second is None else second
        return self.start + timedelta(
            days=day, hours=hour, minutes=minute, seconds=second
        )

    def add(
        self,
        *,
        ts: datetime,
        source: str,
        activity: str,
        severity: int,
        user: str | None = None,
        host: str | None = None,
        src_ip: str | None = None,
        src_port: int | None = None,
        dst_ip: str | None = None,
        dst_port: int | None = None,
        pname: str | None = None,
        pid: int | None = None,
        cmdline: str | None = None,
        fpath: str | None = None,
        label: dict[str, Any] | None = None,
        detail: str | None = None,
    ) -> None:
        raw: dict[str, Any] = {"label": label or benign_label()}
        if detail:
            raw["detail"] = detail
        ev = SecurityEvent(
            event_id=_uuid(self.rng),
            timestamp=ts,
            source=source,
            activity=activity,  # type: ignore[arg-type]
            severity=severity,
            actor={"user": user, "host": host},
            src={"ip": src_ip, "port": src_port},
            dst={"ip": dst_ip, "port": dst_port},
            process={"name": pname, "pid": pid, "cmdline": cmdline},
            file={"path": fpath},
            raw=raw,
        )
        self.events.append(ev)

    # ---- benign baseline ----------------------------------------------
    def _benign_day_for_user(
        self, u: dict[str, Any], day: int, is_workday: bool
    ) -> None:
        b = self.sim["benign"]
        host = u["primary_host"]
        ip = self.host_ip[host]
        uname = u["name"]
        role = u["role"]
        # Weekend / non-workday: usually idle, occasional legit work.
        if not is_workday and self.rng.random() > b["weekend_activity_prob"]:
            # off-hours admins may still pop in; otherwise nothing today.
            if not (
                u.get("off_hours_admin")
                and self.rng.random() < b["offhours_admin_prob"]
            ):
                return

        def jitter(rate: int) -> int:
            return max(0, rate + self.rng.randint(-1, 2))

        # auth: domain logon at start of day
        for _ in range(jitter(b["auth_events_per_user_per_day"])):
            h = self.rng.randint(self.bh_start, self.bh_end - 1)
            self.add(
                ts=self.ts(day, h),
                source=f"auth@{host}",
                activity="auth",
                severity=self.rng.randint(5, 20),
                user=uname,
                host=host,
                src_ip=ip,
                dst_ip=self.host_ip["DC01"],
                dst_port=88,
                detail="kerberos logon",
            )
        # process: routine execution
        palette = (
            PROC_DB
            if role == "service_account"
            else (
                PROC_GENERIC + PROC_ADMIN
                if role in ("domain_admin", "helpdesk")
                else PROC_GENERIC
            )
        )
        for _ in range(jitter(b["process_events_per_user_per_day"])):
            h = self.rng.randint(self.bh_start, self.bh_end - 1)
            pname = self.rng.choice(palette)
            self.add(
                ts=self.ts(day, h),
                source=f"edr@{host}",
                activity="process",
                severity=self.rng.randint(5, 25),
                user=uname,
                host=host,
                pname=pname,
                pid=self.rng.randint(1000, 9000),
                cmdline=f"{pname}",
                detail="routine process",
            )
        # network: internal flows (clerks/registrars touch the exam DB normally)
        for _ in range(jitter(b["network_events_per_user_per_day"])):
            h = self.rng.randint(self.bh_start, self.bh_end - 1)
            if role in ("exams_clerk", "registrar", "service_account"):
                dst_ip, dst_port = (
                    self.host_ip["DB-EXAMS"],
                    5432,
                )  # normal exam-records access
                det = "exam-records query"
            else:
                dst_ip, dst_port = self.host_ip["DC01"], self.rng.choice([389, 445])
                det = "internal share/ldap"
            self.add(
                ts=self.ts(day, h),
                source=f"netflow@{host}",
                activity="network",
                severity=self.rng.randint(5, 20),
                user=uname,
                host=host,
                src_ip=ip,
                dst_ip=dst_ip,
                dst_port=dst_port,
                detail=det,
            )
        # file: light document activity
        for _ in range(jitter(b["file_events_per_user_per_day"])):
            h = self.rng.randint(self.bh_start, self.bh_end - 1)
            self.add(
                ts=self.ts(day, h),
                source=f"edr@{host}",
                activity="file",
                severity=self.rng.randint(5, 15),
                user=uname,
                host=host,
                fpath=self.rng.choice(BENIGN_FILES).format(u=uname),
                detail="file access",
            )
        # natural off-hours admin noise (legit) -> the decoy for stage 2
        if u.get("off_hours_admin") and self.rng.random() < b["offhours_admin_prob"]:
            h = self.rng.choice([19, 20, 21, 22, 6, 7])
            self.add(
                ts=self.ts(day, h),
                source=f"auth@{host}",
                activity="auth",
                severity=self.rng.randint(15, 30),
                user=uname,
                host=host,
                src_ip=ip,
                dst_ip=self.host_ip["DC01"],
                dst_port=88,
                detail="legit off-hours admin logon",
            )

    def generate_benign(self) -> None:
        for day in range(self.days):
            current = self.start + timedelta(days=day)
            is_workday = current.weekday() in self.workdays
            for u in self.users:
                self._benign_day_for_user(u, day, is_workday)

    # ---- attack overlay ------------------------------------------------
    @staticmethod
    def _hm(t: str) -> tuple[int, int]:
        hh, mm = t.split(":")
        return int(hh), int(mm)

    def _emit_stage(self, stage: dict[str, Any]) -> None:
        sid = stage["stage"]
        if sid == 1:  # T1566 Phishing -> foothold (process + C2 beacon)
            h, m = self._hm(stage["time"])
            t = self.ts(stage["day_offset"], h, m)
            self.add(
                ts=t,
                source="edr@WS03",
                activity="process",
                severity=82,
                user="exam.clerk",
                host="WS03",
                pname="powershell.exe",
                pid=self.rng.randint(4000, 9000),
                cmdline="powershell.exe -enc SQBFAFgA... (spawned by winword.exe)",
                label=mal_label(stage, "winword.exe macro spawns powershell beacon"),
                detail="phishing macro child process",
            )
            self.add(
                ts=t + timedelta(seconds=12),
                source="netflow@WS03",
                activity="network",
                severity=80,
                user="exam.clerk",
                host="WS03",
                src_ip=self.host_ip["WS03"],
                dst_ip=self.c2_ip,
                dst_port=443,
                label=mal_label(stage, "initial C2 beacon to external host"),
                detail="C2 beacon",
            )
        elif sid == 2:  # T1078 Valid Accounts -> off-hours reused-cred login
            h, m = self._hm(stage["time"])
            t = self.ts(stage["day_offset"], h, m)
            self.add(
                ts=t,
                source="auth@WS03",
                activity="auth",
                severity=78,
                user="exam.clerk",
                host="WS03",
                src_ip=self.c2_ip,
                dst_ip=self.host_ip["WS03"],
                dst_port=3389,
                label=mal_label(stage, "off-hours logon with reused clerk credentials"),
                detail="reused-credential RDP logon at 02:13",
            )
        elif sid == 3:  # T1003 OS Credential Dumping (process + dumped file)
            h, m = self._hm(stage["time"])
            t = self.ts(stage["day_offset"], h, m)
            self.add(
                ts=t,
                source="edr@WS03",
                activity="process",
                severity=90,
                user="exam.clerk",
                host="WS03",
                pname="rundll32.exe",
                pid=self.rng.randint(4000, 9000),
                cmdline="rundll32.exe comsvcs.dll, MiniDump lsass.exe out.dmp",
                label=mal_label(stage, "LSASS memory dump for credential theft"),
                detail="credential dumping",
            )
            self.add(
                ts=t + timedelta(seconds=8),
                source="edr@WS03",
                activity="file",
                severity=85,
                user="exam.clerk",
                host="WS03",
                fpath=r"C:\\Windows\\Temp\\out.dmp",
                label=mal_label(stage, "LSASS dump written to disk"),
                detail="dropped credential dump",
            )
        elif sid == 4:  # T1021 Lateral Movement -> multiple hops over several days
            for hop in stage["hops"]:
                h, m = self._hm(hop["time"])
                t = self.ts(hop["day_offset"], h, m)
                s_host, d_host = hop["source"]["host"], hop["target"]["host"]
                self.add(
                    ts=t,
                    source=f"auth@{d_host}",
                    activity="auth",
                    severity=84,
                    user="admin.it",
                    host=d_host,
                    src_ip=self.host_ip[s_host],
                    dst_ip=self.host_ip[d_host],
                    dst_port=3389,
                    label=mal_label(stage, hop["description"]),
                    detail=f"lateral logon {s_host}->{d_host}",
                )
                self.add(
                    ts=t + timedelta(seconds=20),
                    source=f"netflow@{s_host}",
                    activity="network",
                    severity=72,
                    user="admin.it",
                    host=s_host,
                    src_ip=self.host_ip[s_host],
                    dst_ip=self.host_ip[d_host],
                    dst_port=445,
                    label=mal_label(stage, hop["description"]),
                    detail=f"SMB lateral {s_host}->{d_host}",
                )
        elif sid == 5:  # T1560 Archive Collected Data on DB-EXAMS
            h, m = self._hm(stage["time"])
            t = self.ts(stage["day_offset"], h, m)
            self.add(
                ts=t,
                source="edr@DB-EXAMS",
                activity="process",
                severity=88,
                user="admin.it",
                host="DB-EXAMS",
                pname="7z.exe",
                pid=self.rng.randint(4000, 9000),
                cmdline="7z a -p exam-records.7z /var/lib/exam-records/",
                label=mal_label(stage, "exam-records dumped and archived for staging"),
                detail="archive collected data",
            )
            self.add(
                ts=t + timedelta(seconds=45),
                source="edr@DB-EXAMS",
                activity="file",
                severity=80,
                user="admin.it",
                host="DB-EXAMS",
                fpath="/tmp/exam-records.7z",
                label=mal_label(stage, "staged exfil archive created"),
                detail="staged archive",
            )
        elif sid == 6:  # T1041 Exfiltration over C2
            h, m = self._hm(stage["time"])
            t = self.ts(stage["day_offset"], h, m)
            for i in range(2):  # two outbound chunks
                self.add(
                    ts=t + timedelta(seconds=i * 30),
                    source="netflow@DB-EXAMS",
                    activity="network",
                    severity=95,
                    user="admin.it",
                    host="DB-EXAMS",
                    src_ip=self.host_ip["DB-EXAMS"],
                    dst_ip=self.c2_ip,
                    dst_port=443,
                    label=mal_label(stage, "exam-records archive exfiltrated over C2"),
                    detail=f"exfil chunk {i + 1}/2",
                )

    def generate_attack(self) -> None:
        for stage in self.scn["attack_timeline"]:
            self._emit_stage(stage)

    # ---- orchestration -------------------------------------------------
    def generate(self) -> list[SecurityEvent]:
        self.generate_benign()
        self.generate_attack()
        self.events.sort(key=lambda e: e.timestamp)
        return self.events


def build_ground_truth(events: list[SecurityEvent], seed: int) -> dict[str, Any]:
    mal = [e for e in events if e.raw.get("label", {}).get("is_malicious")]
    techniques = sorted({e.raw["label"]["mitre_technique"] for e in mal})
    gt_events = []
    for e in mal:
        lbl = e.raw["label"]
        gt_events.append(
            {
                "event_id": str(e.event_id),
                "timestamp": e.timestamp.isoformat(),
                "attack_stage": lbl["attack_stage"],
                "stage_name": lbl["stage_name"],
                "mitre_technique": lbl["mitre_technique"],
                "mitre_name": lbl["mitre_name"],
                "activity": e.activity,
                "actor_host": e.actor.host,
                "description": lbl["description"],
            }
        )
    gt_events.sort(key=lambda r: r["timestamp"])
    return {
        "scenario": "state-examinations-authority",
        "seed": seed,
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "total_events": len(events),
        "benign_count": len(events) - len(mal),
        "malicious_count": len(mal),
        "distinct_techniques": techniques,
        "stages_present": sorted({e["attack_stage"] for e in gt_events}),
        "events": gt_events,
    }


def write_outputs(
    events: list[SecurityEvent],
    seed: int,
    events_out: Path = DEFAULT_EVENTS_OUT,
    gt_out: Path = DEFAULT_GROUND_TRUTH,
) -> dict[str, Any]:
    events_out.parent.mkdir(parents=True, exist_ok=True)
    with events_out.open("w") as f:
        for e in events:
            f.write(e.model_dump_json() + "\n")
    gt = build_ground_truth(events, seed)
    gt_out.write_text(json.dumps(gt, indent=2))
    return gt


def main() -> None:
    ap = argparse.ArgumentParser(description="Generate Prahari synthetic telemetry.")
    ap.add_argument("--seed", type=int, default=42, help="deterministic seed")
    ap.add_argument(
        "--out", type=Path, default=DEFAULT_EVENTS_OUT, help="events.jsonl output path"
    )
    ap.add_argument(
        "--ground-truth",
        type=Path,
        default=DEFAULT_GROUND_TRUTH,
        help="ground_truth.json output path",
    )
    args = ap.parse_args()

    gen = Generator(seed=args.seed)
    events = gen.generate()
    gt = write_outputs(events, args.seed, args.out, args.ground_truth)

    span_lo = events[0].timestamp.date().isoformat()
    span_hi = events[-1].timestamp.date().isoformat()
    print(
        f"Generated {gt['total_events']} events "
        f"(benign={gt['benign_count']}, malicious={gt['malicious_count']}) "
        f"seed={args.seed}"
    )
    print(f"Date span: {span_lo} .. {span_hi}")
    print(f"Techniques: {', '.join(gt['distinct_techniques'])}")
    print(f"Stages present: {gt['stages_present']}")
    print(f"Wrote {args.out} and {args.ground_truth}")


if __name__ == "__main__":
    main()
