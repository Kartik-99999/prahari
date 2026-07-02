#!/usr/bin/env python3
"""PRAHARÍ OT/ICS scenario — unauthorized PLC setpoint/logic manipulation.

Held-out IT+OT heterogeneity test. A Modbus/SCADA substation network is modelled
as OCSF SecurityEvents (network=Modbus/TCP:502, process=engineering tool,
file=PLC logic download, auth=operator/engineer logon). The benign baseline has
the historian and SCADA server polling PLCs 24/7, so off-hours Modbus is NORMAL;
the FROZEN detector must catch the attack on behaviour (rare engineering tool,
new user->host pairings, velocity) rather than time-of-day.

Hardened baseline (G7): operators on the HMIs also issue routine setpoint
WRITES (fc=6) during their shifts, so benign traffic contains legitimate Modbus
writes — a write-function-code feature alone cannot separate the attack; the
behavioural signal is a *new writer* (host that never wrote to that PLC before).

Attack: a compromised engineering account (eng.1) performs an unauthorized
program download + setpoint writes to the PLCs over several nights — the classic
ICS manipulation-of-control threat. ATT&CK-for-ICS techniques (T0859 Valid
Accounts, T0843 Program Download, T0836 Modify Parameter, T0855 Unauthorized
Command Message) are recorded in ground truth for reference (the enterprise
mapper does not cover ICS techniques — see docs/RESULTS.md).
"""

from __future__ import annotations

import argparse
import sys
from datetime import timedelta
from pathlib import Path
from typing import Any

_REPO_ROOT = Path(__file__).resolve().parents[2]
if str(_REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(_REPO_ROOT))

from packages.scenario.generator import (
    Generator,
    mal_label,
    write_outputs,
)  # noqa: E402

OT_YAML = Path(__file__).resolve().parent / "ot_scenario.yaml"
DEFAULT_EVENTS = _REPO_ROOT / "data" / "ot" / "events.jsonl"
DEFAULT_GT = _REPO_ROOT / "data" / "ot" / "ground_truth.json"

PLCS = ["PLC-01", "PLC-02", "PLC-03"]
NORMAL_ENG_TOOLS = ["hmi_config.exe", "plc_read.exe", "scada_view.exe", "trend.exe"]


def _stage(stage: int, name: str, tech: str, tname: str, desc: str) -> dict[str, Any]:
    return {
        "stage": stage,
        "name": name,
        "mitre_technique": tech,
        "mitre_name": tname,
        "description": desc,
    }


class OTGenerator(Generator):
    def __init__(self, seed: int = 1337) -> None:
        super().__init__(seed=seed, scenario_path=OT_YAML)

    # ---- benign OT baseline (24/7 polling; engineering only in business hours) --
    def generate_benign(self) -> None:
        b = self.sim["benign"]
        for day in range(self.days):
            current = self.start + timedelta(days=day)
            workday = current.weekday() in self.workdays

            # historian + SCADA poll PLCs round-the-clock (off-hours Modbus is NORMAL)
            for host, user, n in (
                ("HIST01", "hist.svc", b["historian_polls_per_day"]),
                ("SCADA01", "scada.svc", b["scada_polls_per_day"]),
            ):
                for _ in range(n):
                    self._modbus(
                        day,
                        self.rng.randint(0, 23),
                        user,
                        host,
                        self.rng.choice(PLCS),
                        fc=3,
                        det="read_holding_registers",
                    )

            # HMIs polled during operator shifts (op.1 day, op.2 night)
            for host, user, hours in (
                ("HMI01", "op.1", range(self.bh_start, self.bh_end)),
                ("HMI02", "op.2", list(range(19, 24)) + list(range(0, 7))),
            ):
                for _ in range(b["poll_per_hmi_per_day"]):
                    self._modbus(
                        day,
                        self.rng.choice(list(hours)),
                        user,
                        host,
                        self.rng.choice(PLCS),
                        fc=3,
                        det="read_holding_registers",
                    )
                # operators also ADJUST setpoints routinely (fc=6 writes) — benign
                # writes exist by design, so "is a Modbus write" alone can never be
                # a label proxy; the detectable signal is WHO/WHERE writes come from.
                for _ in range(b.get("operator_setpoint_writes_per_day", 3)):
                    self._modbus(
                        day,
                        self.rng.choice(list(hours)),
                        user,
                        host,
                        self.rng.choice(PLCS),
                        fc=6,
                        det="write_single_register setpoint adjust (operator)",
                    )
                for _ in range(b["operator_auth_per_day"]):
                    h = self.rng.choice(list(hours))
                    self.add(
                        ts=self.ts(day, h),
                        source=f"auth@{host}",
                        activity="auth",
                        severity=self.rng.randint(5, 18),
                        user=user,
                        host=host,
                        src_ip=self.host_ip[host],
                        dst_ip=self.host_ip["SCADA01"],
                        dst_port=3389,
                        detail="operator HMI logon",
                    )

            # engineer works business hours on weekdays: normal tools + occasional PLC read
            if workday:
                for _ in range(b["engineer_proc_per_day"]):
                    h = self.rng.randint(self.bh_start, self.bh_end - 1)
                    pn = self.rng.choice(NORMAL_ENG_TOOLS)
                    self.add(
                        ts=self.ts(day, h),
                        source="edr@EWS01",
                        activity="process",
                        severity=self.rng.randint(5, 20),
                        user="eng.1",
                        host="EWS01",
                        pname=pn,
                        pid=self.rng.randint(1000, 9000),
                        cmdline=pn,
                        detail="routine engineering tool",
                    )
                if self.rng.random() < 0.6:
                    self._modbus(
                        day,
                        self.rng.randint(self.bh_start, self.bh_end - 1),
                        "eng.1",
                        "EWS01",
                        self.rng.choice(PLCS),
                        fc=3,
                        det="engineer read_holding_registers",
                    )

    def _modbus(
        self,
        day: int,
        hour: int,
        user: str,
        host: str,
        plc: str,
        fc: int,
        det: str,
        sev: int = 10,
        label: dict | None = None,
    ) -> None:
        self.add(
            ts=self.ts(day, hour),
            source=f"netflow@{host}",
            activity="network",
            severity=sev,
            user=user,
            host=host,
            src_ip=self.host_ip[host],
            dst_ip=self.host_ip[plc],
            dst_port=502,
            label=label,
            detail=f"modbus/tcp fc={fc} {det} -> {plc}",
        )

    # ---- attack: unauthorized PLC program download + setpoint writes ------------
    def generate_attack(self) -> None:
        nights = [9, 11, 13, 15]
        for i, day in enumerate(nights):
            hour = 2 + (i % 2)  # 02:00 / 03:00 — off-hours, but so is benign polling

            # T0859 — compromised engineer logs into EWS01 off-hours
            s1 = _stage(
                1,
                "ics_valid_account",
                "T0859",
                "Valid Accounts",
                "off-hours logon with compromised engineering credentials",
            )
            self.add(
                ts=self.ts(day, hour, 2, 0),
                source="auth@EWS01",
                activity="auth",
                severity=80,
                user="eng.1",
                host="EWS01",
                src_ip=self.host_ip["EWS01"],
                dst_ip=self.host_ip["SCADA01"],
                dst_port=3389,
                label=mal_label(s1),
                detail="off-hours engineering logon",
            )

            # T0843 — runs an unauthorized programming tool (rare, never-seen process)
            s2 = _stage(
                2,
                "program_download",
                "T0843",
                "Program Download",
                "unauthorized PLC logic/program download tool executed",
            )
            self.add(
                ts=self.ts(day, hour, 6, 0),
                source="edr@EWS01",
                activity="process",
                severity=88,
                user="eng.1",
                host="EWS01",
                pname="plc_programmer.exe",
                pid=self.rng.randint(2000, 9000),
                cmdline="plc_programmer.exe --download ladder_v2.bin --force",
                label=mal_label(s2),
                detail="unauthorized engineering tool",
            )

            # T0855/T0836 — Modbus WRITE (setpoint manipulation) to each PLC
            s3 = _stage(
                3,
                "modify_parameter",
                "T0836",
                "Modify Parameter",
                "unauthorized Modbus write of control setpoints to PLCs",
            )
            for j, plc in enumerate(PLCS):
                self._modbus(
                    day,
                    hour,
                    "eng.1",
                    "EWS01",
                    plc,
                    fc=16,
                    det=f"write_multiple_registers setpoint 4000{j+1}",
                    sev=90,
                    label=mal_label(s3),
                )

            # T0843 — logic file downloaded onto a PLC
            s4 = _stage(
                2,
                "program_download",
                "T0843",
                "Program Download",
                "malicious ladder-logic written to PLC",
            )
            self.add(
                ts=self.ts(day, hour, 22, 0),
                source="edr@EWS01",
                activity="file",
                severity=85,
                user="eng.1",
                host="EWS01",
                fpath=f"\\\\{PLCS[i % 3]}\\logic\\ladder_v2.bin",
                label=mal_label(s4),
                detail="PLC program file download",
            )

            # on alternate nights: pivot to SCADA01 (new user->host) + writes from there
            if i % 2 == 1:
                s5 = _stage(
                    4,
                    "unauthorized_command",
                    "T0855",
                    "Unauthorized Command Message",
                    "engineer account on the SCADA server issuing control writes",
                )
                self.add(
                    ts=self.ts(day, hour, 35, 0),
                    source="auth@SCADA01",
                    activity="auth",
                    severity=86,
                    user="eng.1",
                    host="SCADA01",
                    src_ip=self.host_ip["EWS01"],
                    dst_ip=self.host_ip["SCADA01"],
                    dst_port=3389,
                    label=mal_label(s5),
                    detail="engineer logon to SCADA server (unusual)",
                )
                for plc in PLCS[:2]:
                    self._modbus(
                        day,
                        hour,
                        "eng.1",
                        "SCADA01",
                        plc,
                        fc=16,
                        det="write_multiple_registers setpoint override",
                        sev=92,
                        label=mal_label(s5),
                    )


def main() -> None:
    ap = argparse.ArgumentParser(description="Generate PRAHARÍ OT/ICS scenario.")
    ap.add_argument("--seed", type=int, default=1337)
    ap.add_argument("--out", type=Path, default=DEFAULT_EVENTS)
    ap.add_argument("--ground-truth", type=Path, default=DEFAULT_GT)
    args = ap.parse_args()

    gen = OTGenerator(seed=args.seed)
    events = gen.generate()
    gt = write_outputs(events, args.seed, args.out, args.ground_truth)
    print(
        f"[ot] {gt['total_events']} events "
        f"(benign={gt['benign_count']}, malicious={gt['malicious_count']}) seed={args.seed}"
    )
    print(f"  span {events[0].timestamp.date()} .. {events[-1].timestamp.date()}")
    print(f"  ICS techniques: {', '.join(gt['distinct_techniques'])}")
    print(f"  wrote {args.out}")


if __name__ == "__main__":
    main()
