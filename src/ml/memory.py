"""
PRD 02 — Shared Memory: ChromaDB backend, embeddings, and semantic retrieval.
"""

import hashlib
import os
from datetime import datetime
from typing import List

import chromadb

from .models import Finding, classify_finding_type

# Shared persistent store — must match db.py so the ML memory and the rest of
# the pipeline read/write the SAME ChromaDB (both use collection 'aria_findings').
# db.py resolves this to <repo_root>/chroma_store; memory.py lives in src/ml/,
# so the repo root is two directories up.
_SHARED_DB_PATH = os.path.join(
    os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))),
    "chroma_store",
)


# ── Embedding Model ──────────────────────────────────────────────

class EmbeddingModel:
    """SentenceTransformer embeddings with offline-safe hash fallback."""
    def __init__(self, use_offline_hash=False):
        self.use_offline_hash = use_offline_hash
        if not use_offline_hash:
            try:
                from sentence_transformers import SentenceTransformer
                self.model = SentenceTransformer('all-MiniLM-L6-v2')
            except ImportError:
                print("SentenceTransformer not installed, falling back to hash embeddings.")
                self.use_offline_hash = True

    # MiniLM output dimension — hash mode must match to avoid Chroma errors.
    EMBEDDING_DIM = 384

    def embed(self, text: str) -> List[float]:
        if self.use_offline_hash:
            dims = []
            for i in range(12):
                hi = hashlib.sha256(f"{text}_{i}".encode()).digest()
                dims.extend([float(b) / 255.0 for b in hi])
            vec = dims[:self.EMBEDDING_DIM]
        else:
            vec = self.model.encode([text])[0].tolist()
        # Guard: every vector in a collection must share one dimension, else
        # Chroma raises at query time. Catches a model swap that changes width.
        if len(vec) != self.EMBEDDING_DIM:
            raise ValueError(
                f"Embedding width {len(vec)} != expected {self.EMBEDDING_DIM}. "
                "Update EMBEDDING_DIM to match the active model and re-index."
            )
        return vec

    def embed_documents(self, texts: List[str]) -> List[List[float]]:
        return [self.embed(t) for t in texts]


# ── ChromaDB Store ───────────────────────────────────────────────

class ChromaStore:
    """Persistent ChromaDB backend with store, retrieve, delete, update."""
    def __init__(self, persist_dir=None):
        # Default to the shared store so ML memory and the pipeline see the
        # same data. Callers can still override (e.g. tests use a temp dir).
        self.client = chromadb.PersistentClient(path=persist_dir or _SHARED_DB_PATH)
        self.collection = self.client.get_or_create_collection(
            name="aria_findings",
            metadata={"hnsw:space": "cosine"}
        )
        self.embedder = EmbeddingModel()

    def _prepare_document(self, finding: Finding) -> str:
        """Document composition: title + description + evidence + remediation + tags."""
        doc = f"{finding.title} {finding.description} {finding.evidence} {finding.remediation}"
        if finding.tags:
            doc += " " + " ".join(finding.tags)
        return doc

    def _prepare_metadata(self, finding: Finding) -> dict:
        """Normalize metadata for ChromaDB (str, int, float, bool only)."""
        meta = finding.dict(exclude={"title", "description", "evidence", "remediation", "tags"})
        cleaned = {}
        for k, v in meta.items():
            if v is not None:
                if isinstance(v, list):
                    cleaned[k] = ",".join(str(i) for i in v)
                elif isinstance(v, dict):
                    cleaned[k] = str(v)
                elif isinstance(v, datetime):
                    cleaned[k] = v.isoformat()
                else:
                    cleaned[k] = v
        return cleaned

    @staticmethod
    def _content_id(finding: Finding) -> str:
        """Deterministic ID from title+evidence so content-identical findings dedupe."""
        sig = f"{finding.title}:{finding.evidence}"
        return hashlib.sha256(sig.encode()).hexdigest()

    def store_finding(self, finding: Finding, check_duplicate: bool = False) -> bool:
        """Store a finding with content-level duplicate suppression via upsert.

        Args:
            finding: The finding to store.
            check_duplicate: When True, performs a get() before the upsert to
                return whether the record already existed.  Costs an extra
                Chroma round-trip, so leave False (the default) unless you
                actually need the return value (e.g. audit logs or tests).

        Returns:
            True if the finding already existed (only meaningful when
            check_duplicate=True; always False otherwise).
        """
        # Ensure finding_type is always set so RAG metadata filters
        # (get_credentials/host_relationships) work regardless of whether the
        # producing agent bothered to set it.
        if not finding.finding_type:
            finding.finding_type = classify_finding_type(finding)

        doc = self._prepare_document(finding)
        emb = self.embedder.embed(doc)
        meta = self._prepare_metadata(finding)
        content_id = self._content_id(finding)

        is_duplicate = False
        if check_duplicate:
            existing = self.collection.get(ids=[content_id], include=[])
            is_duplicate = len(existing["ids"]) > 0

        self.collection.upsert(
            ids=[content_id],
            documents=[doc],
            embeddings=[emb],
            metadatas=[meta]
        )
        return is_duplicate

    def retrieve(self, query: str, k: int = 5, where: dict = None) -> list:
        """Top-k semantic search with optional metadata filtering."""
        emb = self.embedder.embed(query)
        # Clamp to collection size — some Chroma versions raise when
        # n_results exceeds the number of stored items.
        count = self.collection.count()
        if count == 0:
            return {"ids": [[]], "documents": [[]], "metadatas": [[]], "distances": [[]]}
        kwargs = {
            "query_embeddings": [emb],
            "n_results": min(k, count),
        }
        if where:
            kwargs["where"] = where

        results = self.collection.query(**kwargs)
        return results

    def delete(self, finding_id: str):
        """Delete a finding by ID."""
        self.collection.delete(ids=[finding_id])

    def update(self, finding: Finding):
        """
        Update an existing finding. Keyed by content id (title+evidence), the
        same scheme store_finding uses — keying on finding.id (uuid4) would
        never match a stored record and would orphan the write.
        """
        if not finding.finding_type:
            finding.finding_type = classify_finding_type(finding)
        doc = self._prepare_document(finding)
        emb = self.embedder.embed(doc)
        meta = self._prepare_metadata(finding)

        self.collection.update(
            ids=[self._content_id(finding)],
            documents=[doc],
            embeddings=[emb],
            metadatas=[meta]
        )


# ── Retrieval Engine ─────────────────────────────────────────────

class RetrievalEngine:
    """High-level retrieval interface on top of ChromaStore."""
    def __init__(self, store: ChromaStore):
        self.store = store

    def retrieve(self, query: str, k: int = 5, filter_meta: dict = None):
        """Top-k semantic search with optional metadata filtering."""
        return self.store.retrieve(query, k=k, where=filter_meta)

    def get_credentials(self, k: int = 5):
        """Credential lookup to support cross-surface attack chaining."""
        return self.store.retrieve(
            query="credentials passwords hashes keys",
            k=k,
            where={"finding_type": "credential"}
        )

    def host_relationships(self, host: str, k: int = 5):
        """Host relationship queries."""
        return self.store.retrieve(
            query=f"relationships network connections active directory {host}",
            k=k,
            where={"asset": host}
        )
