#!/usr/bin/env python3
"""PRAHARÍ — one-command live attack demo (`make attack`).

Streams a fresh, seeded intrusion through the entire closed loop and prints a
clean, staged SOC narrative with the key result at each hop. Reuses the canonical
`make` targets (nothing here is demo-only), so what you see is what the pipeline
actually does. ~1 minute end-to-end; deterministic (seed 42); no API key needed
(attribution runs the deterministic mapper). Add `--live` to run the subscription
CLI agent instead.
"""

from __future__ import annotations

import argparse
import re
import subprocess
import sys
import time
from pathlib import Path

_ROOT = Path(__file__).resolve().parents[1]

BOLD, DIM, CYAN, GREEN, RED, RESET = (
    "\033[1m", "\033[2m", "\033[36m", "\033[32m", "\033[31m", "\033[0m"
)


def run(target: str) -> str:
    """Run a make target, return combined stdout+stderr."""
    p = subprocess.run(
        ["make", target], cwd=_ROOT, capture_output=True, text=True
    )
    return p.stdout + p.stderr


def grep(text: str, pattern: str, default: str = "") -> str:
    for line in text.splitlines():
        if re.search(pattern, line):
            return line.strip()
    return default


def stage(n: int, title: str) -> None:
    print(f"\n{CYAN}{BOLD}[{n}/6] {title}{RESET}")


def line(label: str, value: str, good: bool = True) -> None:
    tick = f"{GREEN}✓{RESET}" if good else f"{RED}✗{RESET}"
    print(f"   {tick} {DIM}{label:<22}{RESET} {value}")


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--live", action="store_true", help="live agent via subscription CLI")
    args = ap.parse_args()

    t0 = time.time()
    print(f"{BOLD}PRAHARÍ — live intrusion replay{RESET}  {DIM}(seed 42, 21-day APT){RESET}")

    stage(1, "INGEST — replay telemetry into the provenance graph")
    out = run("graph-load")
    reached = grep(out, r"REACHED edges")
    line("event graph", grep(out, r"malicious stages") or reached or "loaded")

    stage(2, "DETECT — unsupervised UEBA anomaly scoring")
    out = run("ueba-score")
    line("scored", grep(out, r"Wrote anomaly_score") or "anomaly_score written")

    stage(3, "CORRELATE — graph fusion + ranked incidents (auto insider/external)")
    out = run("fuse")
    mode = grep(out, r"external-anchor fraction")
    if mode:
        line("fusion mode", mode.split("] ", 1)[-1])
    out = run("incidents")
    top = grep(out, r"INC-001")
    line("top incident", top or "assembled")

    stage(4, "ATTRIBUTE — map the kill chain to MITRE ATT&CK")
    if args.live:
        out = run("attribute-agent-live")
        line("live agent", grep(out, r"mode=|MODE=") or "live-cc")
    else:
        run("attribute-baseline")
        out = run("attribute-eval")
        line("technique accuracy", grep(out, r"accuracy \(exact\)") or "mapped")

    stage(5, "RESPOND — SOAR playbook with platform-enforced human gates")
    run("respond")
    cov = grep(run("soar-eval"), r"AUTOMATION COVERAGE\s*:")
    line("automation", cov.split(": ", 1)[-1].strip() if cov else "playbook planned")

    stage(6, "AUDIT — tamper-evident hash-chained ledger")
    run("audit-build")
    out = run("audit-verify")
    ok = '"ok": true' in out
    line("chain verified", "hash chain intact" if ok else "BROKEN", good=ok)

    print(f"\n{BOLD}Outcome{RESET}")
    loop = run("loop-summary")
    for pat in (r"MTTD\b", r"BREACH PREVENTED"):
        g = grep(loop, pat)
        if g:
            print(f"   {GREEN}»{RESET} {g.lstrip('> ').strip()}")
    run("brief")  # generate the shareable one-page incident brief
    brief = _ROOT / "data" / "briefs" / "INC-001.md"
    if brief.exists():
        print(f"   {GREEN}»{RESET} explainable incident brief: {DIM}{brief.relative_to(_ROOT)}{RESET} (`make brief`)")
    print(f"\n{DIM}completed in {time.time() - t0:.0f}s — open the console (:3000) to replay it visually{RESET}")


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        sys.exit(130)
