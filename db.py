import os
import chromadb
from schema import Finding
from typing import List, Dict, Any

_DB_PATH = os.path.join(
    os.path.dirname(os.path.abspath(__file__)),
    "chroma_store"
)

chroma_client = chromadb.PersistentClient(path=_DB_PATH)
collection = chroma_client.get_or_create_collection(name="aria_findings")


def add_finding(finding: Finding) -> None:
    """Writes a parsed Finding object into ChromaDB."""
    collection.upsert(
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
        ids=[finding.id]
    )
    print(f"[ChromaDB] Added finding: {finding.title}")


def query_findings(query_text: str, n_results: int = 5) -> Dict[str, Any]:
    """Retrieves relevant findings for cross-surface correlation."""
    count = collection.count()
    if count == 0:
        return {"ids": [], "documents": [], "metadatas": []}
    results = collection.query(
        query_texts=[query_text],
        n_results=min(n_results, count)
    )
    return results


def query_credentials(n_results: int = 5) -> List[str]:
    """Returns evidence strings from findings most likely to contain credentials or payloads."""
    count = collection.count()
    if count == 0:
        return []
    results = collection.query(
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
    count = collection.count()
    if count > 0:
        ids = collection.get(limit=count)["ids"]
        collection.delete(ids=ids)

def get_task_context(task_id: str) -> Dict[str, Any]:
    """Retrieves all findings associated with a specific task."""
    results = collection.get(
        where={"task_id": task_id}
    )
    return results
