#!/usr/bin/env python3
"""PRAHARÍ threat-intel corpus + attribution-agent status (G3).

Reports, verifiably and regenerably: the advisory corpus size, the RAG store
document count, a few retrieval probes proving the corpus grounds the scenario-2
insider techniques, and the LIVE Claude agent status — READY via ANTHROPIC_API_KEY
(Messages API) or via the `claude` CLI (Claude Code subscription, no key), OFFLINE
when PRAHARI_OFFLINE=1 forces zero-egress fallback, else FALLBACK-ONLY — plus the
mode of the last attribution run on disk. Writes a `threat_intel` section into
metrics_slate.json.

No API calls are made here (only key/CLI presence is checked).
"""

from __future__ import annotations

import json
import os
import sys
from pathlib import Path

_REPO_ROOT = Path(__file__).resolve().parents[2]
if str(_REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(_REPO_ROOT))

from dotenv import load_dotenv  # noqa: E402

load_dotenv(_REPO_ROOT / ".env")

from services.attribution.rag import THREAT_INTEL_DIR, retrieve  # noqa: E402

SLATE = _REPO_ROOT / "data" / "metrics_slate.json"

# probe query -> the advisory we expect the expanded corpus to surface for scenario 2
PROBES = {
    "trusted analyst off-hours logon to a database server they never use": "advisory_insider_valid_accounts.md",
    "repeated bulk reads of sensitive record files low and slow over weeks": "advisory_data_local_system.md",
    "copy archive of sensitive data to a removable USB drive, no external C2": "advisory_exfil_usb.md",
    "enumerate domain accounts and list a sensitive records share": "advisory_account_discovery.md",
}


def _live_agent_status() -> dict:
    """Honest live-agent status: capability (key OR subscription CLI OR forced
    offline) + the mode of the last run actually on disk."""
    import shutil

    key_present = bool(os.getenv("ANTHROPIC_API_KEY", "").strip())
    cli_present = shutil.which("claude") is not None
    offline = os.getenv("PRAHARI_OFFLINE") == "1"

    report = _REPO_ROOT / "data" / "attribution_report.json"
    last_mode = None
    if report.exists():
        try:
            last_mode = json.loads(report.read_text()).get("mode")
        except Exception:  # noqa: BLE001
            pass

    if offline:
        status, reason = "OFFLINE", (
            "PRAHARI_OFFLINE=1 — zero-egress mode; agents forced to deterministic "
            "fallback by design (see docs/AIR_GAPPED.md)."
        )
    elif key_present:
        status, reason = "READY", (
            "ANTHROPIC_API_KEY present — `make attribute-agent` runs the live "
            "tool-using Claude agent (Messages API)."
        )
    elif cli_present:
        status, reason = "READY", (
            "No API key, but the `claude` CLI is on PATH — `make "
            "attribute-agent-live` runs the live agent through a Claude Code "
            "subscription (no key needed)."
        )
    else:
        status, reason = "FALLBACK-ONLY", (
            "No ANTHROPIC_API_KEY and no `claude` CLI — the agent runs in "
            "deterministic FALLBACK mode (the loop never breaks)."
        )

    out = {"status": status, "reason": reason}
    if last_mode:
        out["last_run_mode"] = last_mode
        if str(last_mode).startswith("live"):
            out["verified"] = (
                "live end-to-end run completed and scored — transcript + honest "
                "scoring in docs/LIVE_AGENT_RUN.md"
            )
    return out


def main() -> None:
    advisories = sorted(p.name for p in THREAT_INTEL_DIR.glob("*.md"))

    probe_results = []
    hits = 0
    for q, expected in PROBES.items():
        top = retrieve(q, k=3)
        srcs = [h.get("source") for h in top if h.get("source")]
        top_label = (
            (top[0].get("source") or top[0].get("technique_id")) if top else None
        )
        ok = expected in srcs  # expected advisory appears in the top-3
        hits += int(ok)
        probe_results.append(
            {
                "query": q,
                "expected_advisory_in_top3": expected,
                "top_hit": top_label,
                "advisories_in_top3": srcs,
                "match": ok,
            }
        )

    section = {
        "advisory_corpus_files": advisories,
        "advisory_count": len(advisories),
        "corpus_provenance": (
            "CERT-In (cert-in.org.in) is reachable but its advisory listing is a "
            "JavaScript servlet and individual advisories are PDFs, so it is not "
            "cleanly machine-ingestable via static fetch (verified). The corpus is "
            "therefore curated and clearly labelled REPRESENTATIVE/ILLUSTRATIVE, "
            "grounded in public MITRE ATT&CK technique descriptions and CERT-In's "
            "public 'Guidelines on Information Security Practices for Government "
            "Entities'. Replace with the live CERT-In feed in production."
        ),
        "rag_retrieval_probes": probe_results,
        "rag_probe_accuracy": f"{hits}/{len(PROBES)}",
        "live_agent": {
            **_live_agent_status(),
            "scenarios_wired": [
                "scenario-1 (data/incidents.json)",
                "scenario-2 (data/scenario2/incidents.json, --no-write)",
            ],
        },
    }

    slate = json.loads(SLATE.read_text()) if SLATE.exists() else {}
    slate["threat_intel"] = section
    SLATE.write_text(json.dumps(slate, indent=2))

    print("=" * 72)
    print("  PRAHARÍ — THREAT-INTEL CORPUS + AGENT STATUS (G3)")
    print("=" * 72)
    print(f"  advisory corpus: {len(advisories)} files")
    for a in advisories:
        print(f"    - {a}")
    print(
        f"\n  RAG retrieval probes (expanded corpus grounds scenario-2 techniques): "
        f"{hits}/{len(PROBES)} matched (expected advisory in top-3)"
    )
    for pr in probe_results:
        flag = "✓" if pr["match"] else "✗"
        print(f"    {flag} top={pr['top_hit']}  <- {pr['query'][:50]}")
    print(
        f"\n  LIVE agent: {section['live_agent']['status']} — {section['live_agent']['reason']}"
    )
    print(f"\n  wrote threat_intel section -> {SLATE}")


if __name__ == "__main__":
    main()
