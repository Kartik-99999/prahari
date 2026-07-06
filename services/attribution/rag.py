#!/usr/bin/env python3
"""Prahari threat-intel RAG.

Builds a Chroma vector store over (a) ATT&CK technique docs (from attack_kb)
and (b) a curated, clearly-labelled representative CERT-In-style advisory corpus
(data/threat_intel/*.md). Exposes retrieve(query, k) returning the top
technique/advisory chunks for behavioural-fact queries used by the mapper.
"""

from __future__ import annotations

import argparse
import pickle
import sys
from pathlib import Path

import chromadb
import numpy as np
from chromadb.config import Settings
from sklearn.feature_extraction.text import TfidfVectorizer

_REPO_ROOT = Path(__file__).resolve().parents[2]
if str(_REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(_REPO_ROOT))

from services.attribution.attack_kb import get_kb  # noqa: E402

CHROMA_DIR = _REPO_ROOT / "data" / "chroma"
THREAT_INTEL_DIR = _REPO_ROOT / "data" / "threat_intel"
COLLECTION = "prahari_intel"
VEC_FILE = CHROMA_DIR / "tfidf.pkl"


class OfflineTfidfEmbedding:
    """Fully-local Chroma embedding function — ZERO network, ZERO model download.

    Chroma's *default* embedder pulls an ~80 MB ONNX MiniLM model from S3 on first
    use, which is fatal in an air-gapped / zero-egress deployment. This replaces it
    with a scikit-learn TF-IDF vectorizer (already a project dependency) **fitted
    once on the local corpus at build time** and pickled next to the store, so
    indexing and querying embed through the identical fitted vocabulary with no
    download and no external call. Lexical rather than neural, but well-matched to
    this small, keyword-rich curated corpus (ATT&CK techniques + advisories) — it
    reliably surfaces the right advisory for exfil/phishing/lateral-movement facts.
    """

    def __init__(self, vectorizer: TfidfVectorizer | None = None) -> None:
        self._v = vectorizer if vectorizer is not None else self._load()

    @staticmethod
    def _load() -> TfidfVectorizer:
        with VEC_FILE.open("rb") as f:
            return pickle.load(f)  # noqa: S301 (our own artifact, local only)

    def _embed(self, texts) -> list[np.ndarray]:
        mat = self._v.transform(list(texts)).astype(np.float32).toarray()
        return [row for row in mat]

    def __call__(self, input) -> list[np.ndarray]:  # noqa: A002 (chroma's param name)
        return self._embed(input)

    def embed_documents(self, input) -> list[np.ndarray]:  # noqa: A002
        return self._embed(input)

    def embed_query(self, input) -> list[np.ndarray]:  # noqa: A002
        return self._embed(input)

    @staticmethod
    def name() -> str:
        return "prahari_offline_tfidf"

    def get_config(self) -> dict:
        return {}

    @classmethod
    def build_from_config(cls, config: dict) -> "OfflineTfidfEmbedding":
        return cls()


def _fit_and_persist(docs: list[str]) -> OfflineTfidfEmbedding:
    """Fit the TF-IDF vocabulary on the local corpus and pickle it for reuse."""
    vec = TfidfVectorizer(
        ngram_range=(1, 2),
        sublinear_tf=True,
        stop_words="english",
        min_df=1,
        max_features=4096,
    )
    vec.fit(docs)
    CHROMA_DIR.mkdir(parents=True, exist_ok=True)
    with VEC_FILE.open("wb") as f:
        pickle.dump(vec, f)
    return OfflineTfidfEmbedding(vec)


def _client() -> chromadb.ClientAPI:
    CHROMA_DIR.mkdir(parents=True, exist_ok=True)
    # anonymized_telemetry=False stops Chroma's default egress to its telemetry sink.
    return chromadb.PersistentClient(
        path=str(CHROMA_DIR), settings=Settings(anonymized_telemetry=False)
    )


def build() -> int:
    """(Re)build the vector store; returns the number of documents indexed."""
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

    # fit the local TF-IDF vocabulary on this exact corpus, then index through it
    embed = _fit_and_persist(docs)
    client = _client()
    try:
        client.delete_collection(COLLECTION)
    except Exception:  # noqa: BLE001
        pass
    col = client.create_collection(
        COLLECTION, embedding_function=embed, metadata={"hnsw:space": "cosine"}
    )

    # batch add (keeps memory + payload sizes sane)
    B = 256
    for i in range(0, len(ids), B):
        col.add(
            ids=ids[i : i + B], documents=docs[i : i + B], metadatas=metas[i : i + B]
        )
    return len(ids)


def _collection():
    return _client().get_collection(COLLECTION, embedding_function=OfflineTfidfEmbedding())


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
