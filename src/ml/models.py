"""
Shared models for all ML subsystems.
Covers: TargetScope, TaskQueue, Finding (with ML metadata fields).
"""

from pydantic import BaseModel, Field
from typing import List, Literal, Optional
from datetime import datetime
import uuid
import heapq

from schema import Task


# ── PRD 01: Orchestrator Models ──────────────────────────────────

class TargetScope(BaseModel):
    """Input scope for the Orchestrator."""
    domains: List[str]
    ip_ranges: List[str]
    exclusions: List[str] = Field(default_factory=list)


class TaskQueue:
    """Heap-backed priority queue of Task objects for the Orchestrator."""

    PRIORITY_MAP = {"web": 1, "network": 2, "ad": 3}

    def __init__(self):
        self._heap: list = []
        self._counter: int = 0

    def enqueue(self, task: Task):
        priority = self.PRIORITY_MAP.get(task.type, 99)
        heapq.heappush(self._heap, (priority, self._counter, task))
        self._counter += 1

    def dequeue(self) -> Task:
        if self._heap:
            return heapq.heappop(self._heap)[2]
        return None

    def __len__(self):
        return len(self._heap)


# ── PRD 02: Memory / Finding Schema ─────────────────────────────

class Finding(BaseModel):
    """Extended Finding schema for RAG retrieval and model supervision."""
    # Core report fields
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    title: str
    description: str
    severity: str
    evidence: str
    remediation: str

    # Routing and provenance
    task_id: str
    surface: Literal["web", "network", "ad"]
    source_tool: Optional[str] = None
    asset: Optional[str] = None

    # Retrieval labels
    finding_type: Optional[str] = None
    tags: List[str] = Field(default_factory=list)
    credential_material: Optional[str] = None

    # Ranking and filtering
    protocol: Optional[str] = None
    port: Optional[int] = None
    confidence: Optional[float] = None
    timestamp: datetime = Field(default_factory=datetime.utcnow)
