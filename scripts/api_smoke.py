#!/usr/bin/env python3
"""Prahari BFF smoke test: hit every GET endpoint + one POST decision.

Prints status code + a short body snippet per endpoint, exercises the
approve-a-gated-action round-trip (showing the ledger grow by one and the chain
stay verified), and greps every response body for 'gt_' to prove no ground
truth leaks.
"""

from __future__ import annotations

import json
import sys

import httpx

BASE = "http://127.0.0.1:8000"
IID = "INC-001"
GATED_IDX = 6  # isolate_host(DB-EXAMS) — a HIGH, human-gated action


def snip(obj, n=150) -> str:
    s = json.dumps(obj, separators=(",", ":")) if not isinstance(obj, str) else obj
    return s[:n] + ("…" if len(s) > n else "")


def main() -> None:
    bodies: list[tuple[str, str]] = []  # (label, raw_text) for the gt_ grep
    with httpx.Client(base_url=BASE, timeout=30) as c:
        print("=" * 72)
        print("  PRAHARI BFF SMOKE TEST")
        print("=" * 72)

        gets = [
            "/api/health",
            "/api/metrics/slate",
            "/api/incidents",
            f"/api/incidents/{IID}",
            f"/api/incidents/{IID}/graph",
            f"/api/incidents/{IID}/playbook",
            "/api/audit",
        ]
        for path in gets:
            r = c.get(path)
            bodies.append((path, r.text))
            body = r.json()
            if path == f"/api/incidents/{IID}/graph":
                extra = f"nodes={len(body['nodes'])} edges={len(body['edges'])}"
            elif path == "/api/incidents":
                extra = f"{len(body)} incidents; top={body[0]['id']} score={body[0]['score']}"
            elif path == "/api/audit":
                extra = f"entries={len(body['entries'])} verify={body['verify']['ok']}"
            elif path == f"/api/incidents/{IID}/playbook":
                extra = f"{len(body)} actions; gated={[a['idx'] for a in body if a['gate']=='human']}"
            else:
                extra = snip(body)
            print(f"\nGET  {path}\n     -> {r.status_code}  {extra}")

        # --- POST decision round-trip ---
        # Read the entry count from the top-level list (always present), NOT from
        # the verify dict — verify_chain() omits 'entries' when the chain is broken
        # (e.g. if audit-tamper-demo ran first), which would crash this smoke test.
        audit_before = c.get("/api/audit").json()
        before_n = len(audit_before.get("entries", []))
        before_head = (
            audit_before["entries"][-1]["entry_hash"][:12]
            if audit_before.get("entries")
            else "-"
        )
        print("\n" + "-" * 72)
        print(
            f"POST /api/incidents/{IID}/actions/{GATED_IDX}/decision  "
            f"(approve, approver=soc-lead@exams.gov.local)"
        )
        print(f"     ledger BEFORE: entries={before_n} head={before_head}")
        r = c.post(
            f"/api/incidents/{IID}/actions/{GATED_IDX}/decision",
            json={"decision": "approve", "approver": "soc-lead@exams.gov.local"},
        )
        bodies.append(("POST decision", r.text))
        d = r.json()
        acted = next(a for a in d["playbook"] if a["idx"] == GATED_IDX)
        print(f"     -> {r.status_code}")
        print(
            f"     action[{GATED_IDX}] {acted['action']}({acted['target']}) "
            f"status now: {acted['status']} (approver {acted['approver']})"
        )
        print(
            f"     ledger AFTER : entries={d['ledger_entries']} "
            f"head={d['ledger_head_hash']} verify={d['chain_verified']}"
        )
        grew = d["ledger_entries"] == before_n + 1
        print(
            f"     ledger grew by 1: {grew}   chain still verified: {d['chain_verified']}"
        )

        # --- gt_ leak grep across all bodies ---
        print("\n" + "-" * 72)
        leaks = [(lbl, t.count("gt_")) for lbl, t in bodies if "gt_" in t]
        if leaks:
            print(f"  GT-LEAK CHECK: FAIL — 'gt_' found in: {leaks}")
            sys.exit(1)
        print(
            f"  GT-LEAK CHECK: PASS — 'gt_' appears in 0 of "
            f"{len(bodies)} response bodies"
        )


if __name__ == "__main__":
    main()
