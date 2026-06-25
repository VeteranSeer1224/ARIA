import os
import chromadb
from schema import Finding
from typing import List, Dict, Any

<<<<<<< HEAD
<<<<<<< HEAD
# Initialize ChromaDB client 
chroma_client = chromadb.Client()
collection = chroma_client.get_or_create_collection(name="aria_findings") # [cite: 23]
=======
_DB_PATH = os.path.join(
    os.path.dirname(os.path.abspath(__file__)),
    "chroma_store"
)
>>>>>>> origin/main
=======
# Initialize ChromaDB client 
chroma_client = chromadb.Client()
collection = chroma_client.get_or_create_collection(name="aria_findings") # [cite: 23]
>>>>>>> d7b09bd77237d9a109218e5d7207740fe0fca8f5

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

def query_findings(query_text: str, n_results: int = 5) -> List[Dict[str, Any]]: # [cite: 26]
    """Retrieves relevant findings for cross-surface correlation."""
    results = collection.query(
        query_texts=[query_text],
        n_results=n_results
    )
    return results

def get_task_context(task_id: str) -> List[Dict[str, Any]]: # [cite: 26]
    """Retrieves all findings associated with a specific task."""
    results = collection.get(
        where={"task_id": task_id}
    )
    return results