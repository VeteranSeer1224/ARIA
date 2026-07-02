"""
Shared models for all ML subsystems.
Covers: TargetScope, TaskQueue, Finding (with ML metadata fields).
"""

from pydantic import BaseModel, Field
from typing import List, Literal, Optional
from datetime import datetime
import uuid
import sys
import os

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '../..')))
from schema import Task


# ── PRD 01: Orchestrator Models ──────────────────────────────────

class TargetScope(BaseModel):
    """Input scope for the Orchestrator."""
    domains: List[str]
    ip_ranges: List[str]
    exclusions: List[str] = Field(default_factory=list)


class TaskQueue:
    """FIFO queue of Task objects for the Orchestrator."""
    def __init__(self):
        self.tasks: List[Task] = []

    def enqueue(self, task: Task):
        self.tasks.append(task)

    def dequeue(self) -> Task:
        if self.tasks:
            return self.tasks.pop(0)
        return None

    def __len__(self):
        return len(self.tasks)


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
