#!/usr/bin/env python3
"""Prahari ATT&CK knowledge base.

Loads MITRE ATT&CK Enterprise techniques, preferring the live STIX bundle
(cached under data/attack/, gitignored) and falling back to the committed
curated subset packages/attack_subset.json when the network fetch is
unavailable. Exposes lookups: technique_by_id, techniques_by_tactic, search.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
import urllib.request
from dataclasses import dataclass, field
from pathlib import Path

_REPO_ROOT = Path(__file__).resolve().parents[2]


def offline_mode() -> bool:
    """True when PRAHARI_OFFLINE=1 — forces the KB to skip the live STIX fetch and
    resolve from the local cache/subset only (air-gapped / zero-egress mode)."""
    return os.getenv("PRAHARI_OFFLINE") == "1"

ATTACK_URL = (
    "https://raw.githubusercontent.com/mitre-attack/attack-stix-data/"
    "master/enterprise-attack/enterprise-attack.json"
)
CACHE_DIR = _REPO_ROOT / "data" / "attack"
CACHE_FILE = CACHE_DIR / "enterprise-attack.json"
SUBSET_FILE = _REPO_ROOT / "packages" / "attack_subset.json"
FETCH_TIMEOUT = 60


@dataclass
class Technique:
    id: str
    name: str
    tactics: list[str]
    description: str
    detection: str = ""
    mitigations: list[str] = field(default_factory=list)
    is_subtechnique: bool = False

    @property
    def parent_id(self) -> str:
        return self.id.split(".")[0]

    def doc(self) -> str:
        """Text used for RAG embedding."""
        return (
            f"{self.id} {self.name}. Tactics: {', '.join(self.tactics)}. "
            f"{self.description} Detection: {self.detection}"
        )


class AttackKB:
    def __init__(self, techniques: list[Technique], source: str) -> None:
        self.by_id: dict[str, Technique] = {t.id: t for t in techniques}
        self.source = source

    def __len__(self) -> int:
        return len(self.by_id)

    def technique_by_id(self, tid: str) -> Technique | None:
        if tid in self.by_id:
            return self.by_id[tid]
        # fall back to parent technique if a sub-technique id was given
        return self.by_id.get(tid.split(".")[0])

    def techniques_by_tactic(self, tactic: str) -> list[Technique]:
        return [t for t in self.by_id.values() if tactic in t.tactics]

    def parent_techniques(self) -> list[Technique]:
        return [t for t in self.by_id.values() if not t.is_subtechnique]

    def search(self, text: str, k: int = 5) -> list[Technique]:
        terms = [w for w in text.lower().split() if len(w) > 2]
        scored = []
        for t in self.by_id.values():
            hay = f"{t.name} {t.description} {t.detection}".lower()
            score = sum(hay.count(term) for term in terms)
            if score:
                scored.append((score, t))
        scored.sort(key=lambda x: (-x[0], x[1].id))
        return [t for _, t in scored[:k]]


def _parse_stix(bundle: dict) -> list[Technique]:
    objects = bundle.get("objects", [])
    coa_name: dict[str, str] = {}
    mitigates: dict[str, list[str]] = {}
    patterns: dict[str, dict] = {}

    for obj in objects:
        ot = obj.get("type")
        if ot == "course-of-action":
            coa_name[obj["id"]] = obj.get("name", "")
        elif ot == "attack-pattern":
            patterns[obj["id"]] = obj

    for obj in objects:
        if (
            obj.get("type") == "relationship"
            and obj.get("relationship_type") == "mitigates"
        ):
            tgt = obj.get("target_ref", "")
            src = obj.get("source_ref", "")
            if tgt in patterns and src in coa_name:
                mitigates.setdefault(tgt, []).append(coa_name[src])

    techniques: list[Technique] = []
    for sid, obj in patterns.items():
        if obj.get("revoked") or obj.get("x_mitre_deprecated"):
            continue
        ext = next(
            (
                r
                for r in obj.get("external_references", [])
                if r.get("source_name") == "mitre-attack"
            ),
            None,
        )
        if not ext or not ext.get("external_id", "").startswith("T"):
            continue
        tactics = [
            p["phase_name"]
            for p in obj.get("kill_chain_phases", [])
            if p.get("kill_chain_name") == "mitre-attack"
        ]
        techniques.append(
            Technique(
                id=ext["external_id"],
                name=obj.get("name", ""),
                tactics=tactics,
                description=(obj.get("description") or "").strip(),
                detection=(obj.get("x_mitre_detection") or "").strip(),
                mitigations=sorted(set(mitigates.get(sid, []))),
                is_subtechnique=bool(obj.get("x_mitre_is_subtechnique")),
            )
        )
    return techniques


def _load_subset() -> list[Technique]:
    data = json.loads(SUBSET_FILE.read_text())
    return [
        Technique(
            id=t["id"],
            name=t["name"],
            tactics=t["tactics"],
            description=t["description"],
            detection=t.get("detection", ""),
            mitigations=t.get("mitigations", []),
            is_subtechnique="." in t["id"],
        )
        for t in data["techniques"]
    ]


def load_kb(prefer_live: bool = True, refresh: bool = False) -> AttackKB:
    # 1. cached bundle
    if CACHE_FILE.exists() and not refresh:
        try:
            techs = _parse_stix(json.loads(CACHE_FILE.read_text()))
            if techs:
                return AttackKB(techs, "cache")
        except Exception as e:  # noqa: BLE001
            print(f"[warn] cache parse failed: {e}", file=sys.stderr)
    # 2. live fetch (never attempted in offline mode)
    if prefer_live and not offline_mode():
        try:
            CACHE_DIR.mkdir(parents=True, exist_ok=True)
            print(f"[attack-kb] fetching {ATTACK_URL} ...", file=sys.stderr)
            with urllib.request.urlopen(ATTACK_URL, timeout=FETCH_TIMEOUT) as resp:
                raw = resp.read()
            CACHE_FILE.write_bytes(raw)
            techs = _parse_stix(json.loads(raw))
            if techs:
                return AttackKB(techs, "live")
        except Exception as e:  # noqa: BLE001
            print(
                f"[warn] live ATT&CK fetch failed ({e}); using subset fallback",
                file=sys.stderr,
            )
    # 3. committed subset
    return AttackKB(_load_subset(), "subset")


_KB: AttackKB | None = None


def get_kb() -> AttackKB:
    global _KB
    if _KB is None:
        _KB = load_kb()
    return _KB


def main() -> None:
    ap = argparse.ArgumentParser(description="Build/inspect the ATT&CK KB.")
    ap.add_argument("--refresh", action="store_true", help="force re-fetch")
    ap.add_argument("--offline", action="store_true", help="skip live fetch")
    args = ap.parse_args()

    kb = load_kb(prefer_live=not (args.offline or offline_mode()), refresh=args.refresh)
    parents = kb.parent_techniques()
    print(f"ATT&CK KB loaded: source={kb.source}")
    print(f"  techniques total : {len(kb)}")
    print(f"  parent techniques: {len(parents)}")
    print("  key techniques present:")
    for tid in [
        "T1566",
        "T1078",
        "T1003",
        "T1021",
        "T1059",
        "T1071",
        "T1560",
        "T1005",
        "T1041",
        "T1070",
        "T1486",
    ]:
        t = kb.technique_by_id(tid)
        print(f"    {tid}: {t.name if t else 'MISSING'}")
    print(
        "  sample search('lsass credential dump'):",
        [t.id for t in kb.search("lsass credential dump", k=3)],
    )


if __name__ == "__main__":
    main()
