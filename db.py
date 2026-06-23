import chromadb
from schema import Finding
from typing import List, Dict, Any

# Initialize ChromaDB client
chroma_client = chromadb.PersistentClient(path="./chroma_store") 
collection = chroma_client.get_or_create_collection(name="aria_findings") # [cite: 23]

def add_finding(finding: Finding) -> None: # [cite: 26]
    """Writes a parsed Finding object into ChromaDB."""
    collection.add(
        documents=[finding.description], 
        metadatas=[{
            "id": finding.id,
            "task_id": finding.task_id,
            "surface": finding.surface,
            "title": finding.title,
            "severity": finding.severity
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
