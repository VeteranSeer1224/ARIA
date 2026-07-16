import hashlib
import os
import chromadb
from schema import Finding
from typing import List, Dict, Any

_DB_PATH = os.path.join(
    os.path.dirname(os.path.abspath(__file__)),
    "chroma_store"
)

# Lazy singleton — connection is made on first use, not at import time.
# This prevents ChromaDB from being touched by test imports or modules
# that only need schema types from this file.
_client: chromadb.PersistentClient | None = None
_collection = None


def _get_collection():
    global _client, _collection
    if _collection is None:
        _client = chromadb.PersistentClient(path=_DB_PATH)
        _collection = _client.get_or_create_collection(name="aria_findings")
    return _collection


def _content_id(finding: Finding) -> str:
    """Deterministic ID from title+evidence — matches memory.ChromaStore._content_id.
    Using content hash instead of uuid4 means content-identical findings written
    through db.add_finding or memory.ChromaStore.store_finding are idempotent.
    """
    sig = f"{finding.title}:{finding.evidence}"
    return hashlib.sha256(sig.encode()).hexdigest()


# Keep the module-level name for code that does `from db import collection`
# (reporting_agent.py). It will be None until first use — callers should
# use _get_collection() internally.
collection = None  # populated on first _get_collection() call


def add_finding(finding: Finding) -> None:
    """Writes a parsed Finding object into ChromaDB via content-keyed upsert."""
    col = _get_collection()
    doc_id = _content_id(finding)
    col.upsert(
        documents=[finding.description],
        metadatas=[{
            "id": finding.id,
            "task_id": finding.task_id,
            "surface": finding.surface,
            "title": finding.title,
            "severity": finding.severity,
            "evidence": finding.evidence,
            "remediation": finding.remediation,
            "timestamp": finding.timestamp.isoformat()
        }],
        ids=[doc_id]
    )
    print(f"[ChromaDB] Added finding: {finding.title}")


def query_findings(query_text: str, n_results: int = 5) -> Dict[str, Any]:
    """Retrieves relevant findings for cross-surface correlation."""
    col = _get_collection()
    count = col.count()
    if count == 0:
        return {"ids": [], "documents": [], "metadatas": []}
    results = col.query(
        query_texts=[query_text],
        n_results=min(n_results, count)
    )
    return results


def query_credentials(n_results: int = 5) -> List[str]:
    """Returns evidence strings from findings most likely to contain credentials or payloads."""
    col = _get_collection()
    count = col.count()
    if count == 0:
        return []
    results = col.query(
        query_texts=["credential password hash admin login bypass injection"],
        n_results=min(n_results, count)
    )
    evidence_list = []
    if results.get("metadatas") and results["metadatas"][0]:
        for meta in results["metadatas"][0]:
            evidence = meta.get("evidence", "")
            if evidence:
                evidence_list.append(evidence)
    return evidence_list


def clear_findings() -> None:
    """Deletes all findings from ChromaDB. Used by demo to ensure a clean run."""
    col = _get_collection()
    count = col.count()
    if count > 0:
        ids = col.get(limit=count)["ids"]
        col.delete(ids=ids)

def get_task_context(task_id: str) -> Dict[str, Any]:
    """Retrieves all findings associated with a specific task."""
    results = _get_collection().get(
        where={"task_id": task_id}
    )
    return results
