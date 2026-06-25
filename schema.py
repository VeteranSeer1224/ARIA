from pydantic import BaseModel, Field
from typing import Literal, Optional
from datetime import datetime
import uuid

class Task(BaseModel):
    """Task object routed to specialist agents."""
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    type: Literal["web", "network", "ad"] # [cite: 22]
    target: str # [cite: 22]
    status: Literal["pending", "in_progress", "completed", "failed"] = "pending" # [cite: 22]
    assigned_agent: Optional[str] = None # [cite: 22]
    created_at: datetime = Field(default_factory=datetime.utcnow) # [cite: 22]
    completed_at: Optional[datetime] = None # [cite: 22]

class Finding(BaseModel):
    """Vulnerability or credential found by an agent."""
    id: str = Field(default_factory=lambda: str(uuid.uuid4())) # [cite: 23]
    task_id: str # [cite: 23]
    surface: Literal["web", "network", "ad"] # [cite: 23]
    title: str # [cite: 23]
    description: str # [cite: 23]
    severity: str  # e.g., CVSS v3.1 string [cite: 23]
    evidence: str # [cite: 23]
    remediation: str # [cite: 23]
    timestamp: datetime = Field(default_factory=datetime.utcnow) # [cite: 23]