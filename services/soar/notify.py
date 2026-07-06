#!/usr/bin/env python3
"""PRAHARÍ SOAR — webhook notification connector (REAL, but SAFE-by-default).

Unlike the six simulated containment connectors (services/soar/connectors.py),
this is a REAL egress connector: it posts an incident summary to a Slack/Discord/
Teams-compatible incoming webhook. It is guarded so it can NEVER fire by accident:

  * DRY-RUN is the default — it prints the exact JSON payload and exits without
    any network call.
  * A real POST happens ONLY when BOTH (a) the env var PRAHARI_WEBHOOK_URL is set
    AND (b) the explicit --send flag is passed. Missing either => dry-run.
  * The destination is taken from the env var only (never hard-coded), uses a
    short timeout, and only transmits a concise incident summary (no raw events,
    no secrets).

This keeps the auto-orchestrator fully simulated (no surprise egress) while
demonstrating one production-real, opt-in outbound integration.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime, timezone
from pathlib import Path

_REPO_ROOT = Path(__file__).resolve().parents[2]
DEFAULT_INCIDENTS = _REPO_ROOT / "data" / "incidents.json"
DEFAULT_REPORT = _REPO_ROOT / "data" / "attribution_report.json"
DEFAULT_PLAYBOOK = _REPO_ROOT / "data" / "response_playbook.json"
ENV_URL = "PRAHARI_WEBHOOK_URL"


def build_payload(incidents_path: Path, report_path: Path, playbook_path: Path) -> dict:
    incidents = json.loads(incidents_path.read_text())
    inc = incidents[0] if incidents else {}
    techs: list[str] = []
    summary = ""
    if report_path.exists():
        rep = json.loads(report_path.read_text())
        attr = rep.get("attribution", {})
        techs = sorted({t["technique_id"] for t in attr.get("techniques", [])})
        summary = attr.get("campaign_assessment", {}).get("summary", "")
    actions = []
    if playbook_path.exists():
        pb = json.loads(playbook_path.read_text())
        actions = [
            f"{s['action']}({s['target']}) [{s['blast_radius']}]"
            for s in pb.get("playbook", [])
        ]

    lines = [
        f"*PRAHARÍ incident {inc.get('id', '?')}* — score {inc.get('incident_score', '?')}",
        f"hosts: {', '.join(inc.get('hosts', []) or ['—'])}",
        f"users: {', '.join(inc.get('users', []) or ['—'])}",
        f"external IPs: {', '.join(inc.get('external_ips', []) or ['—'])}",
        f"ATT&CK: {', '.join(techs) or '—'}",
        f"span: {inc.get('span_days', '?')} d, {inc.get('n_events', '?')} events, "
        f"lateral={inc.get('has_lateral_path')}",
    ]
    if summary:
        lines.append(f"assessment: {summary[:300]}")
    if actions:
        lines.append("recommended containment: " + "; ".join(actions[:6]))
    text = "\n".join(lines)
    # Slack/Discord/Teams incoming webhooks all accept a top-level {"text": ...}.
    return {
        "text": text,
        "prahari": {
            "incident_id": inc.get("id"),
            "incident_score": inc.get("incident_score"),
            "hosts": inc.get("hosts"),
            "techniques": techs,
            "generated_at": datetime.now(timezone.utc).isoformat(),
        },
    }


def post(url: str, payload: dict, timeout: float = 8.0) -> tuple[int, str]:
    data = json.dumps(payload).encode("utf-8")
    req = urllib.request.Request(
        url, data=data, headers={"Content-Type": "application/json"}, method="POST"
    )
    with urllib.request.urlopen(
        req, timeout=timeout
    ) as resp:  # noqa: S310 (url from env, opt-in)
        return resp.status, resp.read(200).decode("utf-8", "replace")


def main() -> None:
    ap = argparse.ArgumentParser(
        description="PRAHARÍ webhook notifier (safe-by-default)."
    )
    ap.add_argument("--incidents", type=Path, default=DEFAULT_INCIDENTS)
    ap.add_argument("--report", type=Path, default=DEFAULT_REPORT)
    ap.add_argument("--playbook", type=Path, default=DEFAULT_PLAYBOOK)
    ap.add_argument(
        "--send",
        action="store_true",
        help=f"actually POST (requires {ENV_URL} env var); otherwise dry-run",
    )
    args = ap.parse_args()

    if not args.incidents.exists():
        print(
            f"no incidents file at {args.incidents} — run the pipeline first.",
            file=sys.stderr,
        )
        sys.exit(1)

    payload = build_payload(args.incidents, args.report, args.playbook)
    url = os.getenv(ENV_URL, "").strip()

    print("=" * 72)
    print("  PRAHARÍ SOAR — webhook notifier")
    print("=" * 72)
    print(payload["text"])
    print("-" * 72)
    print("payload JSON:")
    print(json.dumps(payload, indent=2))
    print("-" * 72)

    if os.getenv("PRAHARI_OFFLINE") == "1":
        print(
            "MODE: DRY-RUN — PRAHARI_OFFLINE=1 blocks all egress (air-gap). "
            "No network call made regardless of --send.",
            file=sys.stderr,
        )
        return
    if not args.send:
        print(
            "MODE: DRY-RUN (default) — no network call made. "
            f"To send: set {ENV_URL} and pass --send."
        )
        return
    if not url:
        print(
            f"--send given but {ENV_URL} is not set — refusing to egress. "
            "MODE: DRY-RUN.",
            file=sys.stderr,
        )
        return
    # explicit opt-in + URL present -> real POST
    host = urllib.parse.urlparse(url).hostname or "?"
    print(f"MODE: SEND — POSTing incident summary to {ENV_URL} (host {host})")
    try:
        status, body = post(url, payload)
        print(f"webhook responded HTTP {status}: {body[:120]}")
    except (urllib.error.URLError, urllib.error.HTTPError, ValueError, OSError) as e:
        print(f"webhook POST failed: {e}", file=sys.stderr)
        sys.exit(2)


if __name__ == "__main__":
    main()
