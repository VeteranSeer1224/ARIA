"""
src/ml — All ML subsystems for ARIA.

PRD 01: Orchestrator (orchestrator.py)
PRD 02: Shared Memory (memory.py)
PRD 03: Specialist Agents (agents.py)
PRD 04: Evaluation & Benchmark (evaluation.py)
PRD 05: Fine-Tuning (finetune.py)
"""

# Models
from .models import TargetScope, TaskQueue, Finding, classify_finding_type

# Orchestrator (openai) and Memory (chromadb) pull heavy runtime deps. Guard
# them so the ML-only workstream (finetune, evaluation, scoring) imports on a
# box without the full pipeline stack. Names stay defined (None) if absent.
try:
    from .orchestrator import OrchestratorState, Planner, Scheduler, Router
except ImportError:
    OrchestratorState = Planner = Scheduler = Router = None

try:
    from .memory import EmbeddingModel, ChromaStore, RetrievalEngine
except ImportError:
    EmbeddingModel = ChromaStore = RetrievalEngine = None

# Agents
from .agents import BaseAgent, WebAgent, NetworkAgent, ReportingAgent

# Evaluation
from .evaluation import (
    MetricsCalculator, Scorer, BenchmarkEnvironment, ExperimentPipeline,
    SimulatedRunner, compute_rqs, CONDITIONS, SCENARIOS,
)

# Fine-tuning (heavy deps imported lazily inside finetune functions)
from .finetune import FineTuneConfig, TunedModel, train, load_dataset, deps_available

__all__ = [
    # Models
    "TargetScope", "TaskQueue", "Finding", "classify_finding_type",
    # Orchestrator
    "OrchestratorState", "Planner", "Scheduler", "Router",
    # Memory
    "EmbeddingModel", "ChromaStore", "RetrievalEngine",
    # Agents
    "BaseAgent", "WebAgent", "NetworkAgent", "ReportingAgent",
    # Evaluation
    "MetricsCalculator", "Scorer", "BenchmarkEnvironment", "ExperimentPipeline",
    "SimulatedRunner", "compute_rqs", "CONDITIONS", "SCENARIOS",
    # Fine-tuning
    "FineTuneConfig", "TunedModel", "train", "load_dataset", "deps_available",
]
