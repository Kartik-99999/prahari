#!/usr/bin/env python3
"""Prahari threat-intel RAG.

Builds a Chroma vector store over (a) ATT&CK technique docs (from attack_kb)
and (b) a curated, clearly-labelled representative CERT-In-style advisory corpus
(data/threat_intel/*.md). Exposes retrieve(query, k) returning the top
technique/advisory chunks for behavioural-fact queries used by the mapper.
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

import chromadb

_REPO_ROOT = Path(__file__).resolve().parents[2]
if str(_REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(_REPO_ROOT))

from services.attribution.attack_kb import get_kb  # noqa: E402

CHROMA_DIR = _REPO_ROOT / "data" / "chroma"
THREAT_INTEL_DIR = _REPO_ROOT / "data" / "threat_intel"
COLLECTION = "prahari_intel"


def _client() -> chromadb.ClientAPI:
    CHROMA_DIR.mkdir(parents=True, exist_ok=True)
    return chromadb.PersistentClient(path=str(CHROMA_DIR))


def build() -> int:
    """(Re)build the vector store; returns the number of documents indexed."""
    client = _client()
    try:
        client.delete_collection(COLLECTION)
    except Exception:  # noqa: BLE001
        pass
    col = client.create_collection(COLLECTION, metadata={"hnsw:space": "cosine"})

    ids, docs, metas = [], [], []
    # (a) ATT&CK technique docs (parent-technique granularity)
    kb = get_kb()
    for t in kb.parent_techniques():
        ids.append(f"tech:{t.id}")
        docs.append(t.doc())
        metas.append({"type": "technique", "technique_id": t.id, "name": t.name})
    # (b) representative advisory corpus
    for md in sorted(THREAT_INTEL_DIR.glob("*.md")):
        ids.append(f"adv:{md.stem}")
        docs.append(md.read_text())
        metas.append({"type": "advisory", "source": md.name})

    # batch add (keeps memory + payload sizes sane)
    B = 256
    for i in range(0, len(ids), B):
        col.add(
            ids=ids[i : i + B], documents=docs[i : i + B], metadatas=metas[i : i + B]
        )
    return len(ids)


def _collection():
    return _client().get_collection(COLLECTION)


def retrieve(query: str, k: int = 5) -> list[dict]:
    res = _collection().query(query_texts=[query], n_results=k)
    out = []
    for i in range(len(res["ids"][0])):
        meta = res["metadatas"][0][i]
        doc = res["documents"][0][i]
        out.append(
            {
                "id": res["ids"][0][i],
                "type": meta.get("type"),
                "technique_id": meta.get("technique_id"),
                "source": meta.get("source"),
                "name": meta.get("name"),
                "distance": round(res["distances"][0][i], 4),
                "snippet": doc[:160].replace("\n", " "),
            }
        )
    return out


def main() -> None:
    ap = argparse.ArgumentParser(description="Build the threat-intel RAG store.")
    ap.add_argument("--no-build", action="store_true", help="skip rebuild")
    ap.add_argument(
        "--query", default="powershell beacon to external host after malicious macro"
    )
    args = ap.parse_args()

    if not args.no_build:
        n = build()
        print(f"Indexed {n} documents into Chroma collection '{COLLECTION}'.")

    print(f"\nsanity query: {args.query!r}\nTop-3 hits:")
    for h in retrieve(args.query, k=3):
        label = h["technique_id"] or h["source"]
        print(
            f"  [{h['type']:<9}] {label:<14} dist={h['distance']}  {h['snippet'][:90]}"
        )


if __name__ == "__main__":
    main()
