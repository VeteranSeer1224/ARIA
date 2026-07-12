"""
End-to-end tests for all ML PRD modules under src/ml.
Converted to pytest for CI integration.
"""

import os
import shutil
import tempfile

import pytest

import sys
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))


# ================================================================
# PRD 01: ORCHESTRATOR
# ================================================================

class TestOrchestrator:
    """PRD 01 — Orchestrator: models, planner, scheduler, router."""

    def test_import_orchestrator_components(self):
        from src.ml.models import TargetScope, TaskQueue
        from src.ml.orchestrator import OrchestratorState, Planner, Scheduler, Router

    def test_target_scope_creation(self):
        from src.ml.models import TargetScope
        scope = TargetScope(domains=["http://dvwa.local"], ip_ranges=["192.168.1.0/24"], exclusions=["192.168.1.1"])
        assert scope.domains == ["http://dvwa.local"]
        assert scope.exclusions == ["192.168.1.1"]

    def test_target_scope_default_exclusions(self):
        from src.ml.models import TargetScope
        scope = TargetScope(domains=["a.com"], ip_ranges=["10.0.0.0/8"])
        assert scope.exclusions == []

    def test_task_queue_enqueue_dequeue(self):
        from src.ml.models import TaskQueue
        from schema import Task
        q = TaskQueue()
        t1 = Task(type="web", target="http://a.com")
        t2 = Task(type="network", target="10.0.0.1")
        q.enqueue(t1)
        q.enqueue(t2)
        assert len(q) == 2
        popped = q.dequeue()
        assert popped.id == t1.id
        assert len(q) == 1

    def test_task_queue_empty_dequeue(self):
        from src.ml.models import TaskQueue
        q = TaskQueue()
        assert q.dequeue() is None

    def test_orchestrator_state_duplicate_detection(self):
        from src.ml.orchestrator import OrchestratorState
        from schema import Task
        state = OrchestratorState()
        t = Task(type="web", target="http://test.com")
        assert not state.has_task_run(t)
        state.mark_task_run(t)
        assert state.has_task_run(t)

    def test_planner_deterministic_fallback(self):
        from src.ml.models import TargetScope
        from src.ml.orchestrator import OrchestratorState, Planner
        planner = Planner(api_key="dummy_key_that_wont_work")
        state = OrchestratorState()
        scope = TargetScope(domains=["http://dvwa.local"], ip_ranges=["192.168.1.0/24"])
        planner.create_plan(scope, state)
        assert len(state.queue) >= 2, f"Expected >=2 tasks from fallback, got {len(state.queue)}"

    def test_planner_prevents_duplicates(self):
        from src.ml.models import TargetScope
        from src.ml.orchestrator import OrchestratorState, Planner
        planner = Planner(api_key="dummy_key_that_wont_work")
        state = OrchestratorState()
        scope = TargetScope(domains=["http://dvwa.local"], ip_ranges=["192.168.1.0/24"])
        planner.create_plan(scope, state)
        before = len(state.queue)
        planner.create_plan(scope, state)
        after = len(state.queue)
        assert after == before, f"Duplicate tasks created: {before} -> {after}"

    def test_scheduler_priority_ordering(self):
        from schema import Task
        from src.ml.orchestrator import OrchestratorState, Scheduler
        state = OrchestratorState()
        t_net = Task(type="network", target="10.0.0.1")
        t_web = Task(type="web", target="http://a.com")
        t_ad = Task(type="ad", target="dc.local")
        state.queue.enqueue(t_net)
        state.queue.enqueue(t_web)
        state.queue.enqueue(t_ad)
        sched = Scheduler(state)
        first = sched.next_task()
        assert first.type == "web", f"Expected web first, got {first.type}"
        second = sched.next_task()
        assert second.type == "network", f"Expected network second, got {second.type}"
        third = sched.next_task()
        assert third.type == "ad", f"Expected ad third, got {third.type}"

    def test_scheduler_empty_returns_none(self):
        from src.ml.orchestrator import OrchestratorState, Scheduler
        state = OrchestratorState()
        sched = Scheduler(state)
        assert sched.next_task() is None


# ================================================================
# PRD 02: SHARED MEMORY
# ================================================================

class TestSharedMemory:
    """PRD 02 — Shared Memory: embeddings, ChromaDB store, retrieval."""

    def test_import_memory_components(self):
        from src.ml.models import Finding
        from src.ml.memory import EmbeddingModel, ChromaStore, RetrievalEngine

    def test_finding_schema_all_fields(self):
        from src.ml.models import Finding
        f = Finding(
            task_id="t1", surface="web", title="SQLi", description="desc",
            severity="High", evidence="err", remediation="fix",
            finding_type="credential", credential_material="admin:pass",
            tags=["sqli", "cred"], confidence=0.9, port=80, protocol="http"
        )
        assert f.id is not None
        assert f.credential_material == "admin:pass"
        assert f.tags == ["sqli", "cred"]

    def test_embedding_model_offline_hash(self):
        from src.ml.memory import EmbeddingModel
        emb = EmbeddingModel(use_offline_hash=True)
        vec = emb.embed("test string")
        assert len(vec) == 384, f"Expected 384 dims, got {len(vec)}"
        vec2 = emb.embed("test string")
        assert vec == vec2, "Hash embedding not deterministic"

    @pytest.fixture
    def chroma_store(self):
        """Provide a ChromaStore in a temporary directory, cleaned up after test."""
        test_db = tempfile.mkdtemp(prefix="aria_test_chroma_")
        from src.ml.memory import ChromaStore
        store = ChromaStore(persist_dir=test_db)
        yield store
        shutil.rmtree(test_db, ignore_errors=True)

    def test_store_and_retrieve(self, chroma_store):
        from src.ml.models import Finding
        f1 = Finding(
            task_id="t1", surface="web", title="SQL Injection in login",
            description="Blind SQLi in username param", severity="High",
            evidence="admin' OR 1=1--", remediation="Use parameterized queries",
            finding_type="credential", credential_material="admin:hunter2",
            tags=["sqli"], confidence=0.95
        )
        chroma_store.store_finding(f1)
        results = chroma_store.retrieve("SQL injection credential", k=1)
        assert len(results["ids"][0]) == 1, "Expected 1 result"

    def test_duplicate_suppression(self, chroma_store):
        from src.ml.models import Finding
        f1 = Finding(
            task_id="t1", surface="web", title="SQL Injection in login",
            description="Blind SQLi in username param", severity="High",
            evidence="admin' OR 1=1--", remediation="Use parameterized queries",
            finding_type="credential", credential_material="admin:hunter2",
            tags=["sqli"], confidence=0.95
        )
        chroma_store.store_finding(f1)
        was_dup = chroma_store.store_finding(f1)
        assert was_dup is True, f"Expected True for duplicate, got {was_dup}"
        results = chroma_store.retrieve("SQL injection", k=10)
        assert len(results["ids"][0]) == 1, "Duplicate was inserted instead of upserted"

    def test_delete_finding(self, chroma_store):
        from src.ml.models import Finding
        from src.ml.memory import ChromaStore
        f1 = Finding(
            task_id="t1", surface="web", title="To Delete",
            description="Will be deleted", severity="High",
            evidence="delete me", remediation="N/A"
        )
        chroma_store.store_finding(f1)
        content_id = ChromaStore._content_id(f1)
        chroma_store.delete(content_id)
        results = chroma_store.retrieve("delete", k=1)
        assert len(results["ids"][0]) == 0, "Finding not deleted"

    def test_update_finding(self, chroma_store):
        from src.ml.models import Finding
        f2 = Finding(
            task_id="t2", surface="network", title="Open SMB",
            description="Port 445 open", severity="Low",
            evidence="445/tcp open", remediation="Restrict access",
            finding_type="service"
        )
        chroma_store.store_finding(f2)
        f2.title = "Open SMB (Updated)"
        f2.description = "Port 445 open with signing disabled"
        chroma_store.update(f2)

    def test_retrieval_engine_credentials(self, chroma_store):
        from src.ml.models import Finding
        from src.ml.memory import RetrievalEngine
        re = RetrievalEngine(chroma_store)
        f3 = Finding(
            task_id="t3", surface="web", title="Extracted cred",
            description="SQLmap extracted domain cred", severity="High",
            evidence="jsmith:Password123!", remediation="Rotate creds",
            finding_type="credential", credential_material="jsmith:Password123!"
        )
        chroma_store.store_finding(f3)
        creds = re.get_credentials(k=1)
        assert len(creds["ids"][0]) >= 1

    def test_retrieval_engine_metadata_filter(self, chroma_store):
        from src.ml.models import Finding
        from src.ml.memory import RetrievalEngine
        re = RetrievalEngine(chroma_store)
        f = Finding(
            task_id="t4", surface="network", title="Open port",
            description="Port 22 open", severity="Low",
            evidence="22/tcp open", remediation="Restrict"
        )
        chroma_store.store_finding(f)
        filtered = re.retrieve("open port", k=5, filter_meta={"surface": "network"})
        # Should not raise
        assert filtered is not None


# ================================================================
# PRD 03: SPECIALIST AGENTS
# ================================================================

class TestSpecialistAgents:
    """PRD 03 — Specialist Agents: base, web, network, reporting."""

    def test_import_agent_components(self):
        from src.ml.agents import BaseAgent, WebAgent, NetworkAgent, ReportingAgent

    def test_base_agent_is_abstract(self):
        from src.ml.agents import BaseAgent
        with pytest.raises(TypeError):
            BaseAgent("test")

    def test_web_agent_run(self):
        from schema import Task
        from src.ml.agents import WebAgent
        wa = WebAgent()
        task = Task(type="web", target="http://test.local")
        findings = wa.run(task)
        assert isinstance(findings, list)
        assert len(findings) > 0
        assert findings[0].surface == "web"

    def test_network_agent_run(self):
        from schema import Task
        from src.ml.agents import NetworkAgent
        na = NetworkAgent()
        task = Task(type="network", target="10.0.0.1")
        findings = na.run(task)
        assert isinstance(findings, list)
        assert len(findings) > 0
        assert findings[0].surface in ["network", "ad"]

    def test_reporting_agent_deduplicate(self):
        from src.ml.agents import ReportingAgent
        from src.ml.models import Finding
        ra = ReportingAgent()
        dup1 = Finding(task_id="t1", surface="web", title="SQLi", description="d", severity="H", evidence="e1", remediation="r")
        dup2 = Finding(task_id="t1", surface="web", title="SQLi", description="d", severity="H", evidence="e1", remediation="r")
        dup3 = Finding(task_id="t2", surface="web", title="XSS", description="d", severity="M", evidence="e2", remediation="r")
        deduped = ra.deduplicate([dup1, dup2, dup3])
        assert len(deduped) == 2, f"Expected 2 unique, got {len(deduped)}"

    def test_reporting_agent_generate_report(self):
        from src.ml.agents import ReportingAgent
        from src.ml.models import Finding
        ra = ReportingAgent()
        f1 = Finding(task_id="t1", surface="web", title="SQLi", description="d", severity="H", evidence="e1", remediation="r")
        f2 = Finding(task_id="t2", surface="web", title="XSS", description="d", severity="M", evidence="e2", remediation="r")
        report = ra.generate_report([f1, f1, f2])
        assert "Executive Summary" in report
        assert "SQLi" in report
        assert "XSS" in report

    def test_agent_validate_graceful(self):
        from src.ml.agents import WebAgent
        wa = WebAgent()
        assert wa.validate(None) is False
        assert wa.validate({"data": "ok"}) is True


# ================================================================
# PRD 04: EVALUATION
# ================================================================

class TestEvaluation:
    """PRD 04 — Evaluation & Benchmark: metrics, scoring, experiment pipeline."""

    def test_import_evaluation_components(self):
        from src.ml.evaluation import MetricsCalculator, Scorer, BenchmarkEnvironment, ExperimentPipeline

    def test_metrics_calculator_formulas(self):
        from src.ml.evaluation import MetricsCalculator
        assert MetricsCalculator.calculate_tcr(8, 10) == pytest.approx(0.8)
        assert MetricsCalculator.calculate_tcr(0, 0) == 0.0
        assert MetricsCalculator.calculate_ttc(0, 150.5) == 150.5
        assert MetricsCalculator.calculate_asc(4, 4) == pytest.approx(1.0)
        assert MetricsCalculator.calculate_asc(0, 0) == 0.0
        assert MetricsCalculator.calculate_far(2, 50) == pytest.approx(0.04)
        assert MetricsCalculator.calculate_far(0, 0) == 0.0

    def test_scorer_produces_all_keys(self):
        from src.ml.evaluation import Scorer
        gt = {"total_nodes": 4}
        scorer = Scorer(gt)
        data = {
            "tasks_completed": 10, "total_tasks": 10,
            "start_time": 0, "compromise_time": 150.5,
            "discovered_nodes": 4, "false_actions": 2, "total_actions": 50
        }
        scores = scorer.score_run(data)
        assert all(k in scores for k in ["TCR", "TTC", "ASC", "FAR", "RQS"])

    def test_benchmark_environment(self):
        from src.ml.evaluation import BenchmarkEnvironment
        bench = BenchmarkEnvironment()
        env = bench.load()
        oracle = bench.get_oracle()
        assert "total_nodes" in oracle
        assert len(env["components"]) == 4

    def test_experiment_pipeline_execute(self, tmp_path):
        """Run the full pipeline and verify output files are created."""
        from src.ml.evaluation import ExperimentPipeline
        pipe = ExperimentPipeline()
        pipe.execute()

        output_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), "output")
        assert os.path.exists(os.path.join(output_dir, "evaluation_metrics.csv")), "CSV not created"
        assert os.path.exists(os.path.join(output_dir, "evaluation_findings.json")), "JSON not created"
        assert os.path.exists(os.path.join(output_dir, "evaluation_summary.md")), "MD not created"
