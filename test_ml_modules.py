"""
End-to-end test for all ML PRD modules under src/ml.
"""

import sys
import os
import time
import shutil

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

PASS = 0
FAIL = 0
ERRORS = []

def log_pass(name):
    global PASS
    PASS += 1
    print(f"  ✅ PASS: {name}")

def log_fail(name, err):
    global FAIL
    FAIL += 1
    ERRORS.append((name, str(err)))
    print(f"  ❌ FAIL: {name} -> {err}")

# ================================================================
# PRD 01: ORCHESTRATOR
# ================================================================
print("\n" + "="*60)
print("PRD 01: ORCHESTRATOR")
print("="*60)

try:
    from src.ml.models import TargetScope, TaskQueue
    from src.ml.orchestrator import OrchestratorState, Planner, Scheduler, Router
    log_pass("Import orchestrator components")
except Exception as e:
    log_fail("Import orchestrator components", e)

try:
    scope = TargetScope(domains=["http://dvwa.local"], ip_ranges=["192.168.1.0/24"], exclusions=["192.168.1.1"])
    assert scope.domains == ["http://dvwa.local"]
    assert scope.exclusions == ["192.168.1.1"]
    log_pass("TargetScope model creation & validation")
except Exception as e:
    log_fail("TargetScope model creation & validation", e)

try:
    scope_no_excl = TargetScope(domains=["a.com"], ip_ranges=["10.0.0.0/8"])
    assert scope_no_excl.exclusions == []
    log_pass("TargetScope default exclusions=[]")
except Exception as e:
    log_fail("TargetScope default exclusions=[]", e)

try:
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
    log_pass("TaskQueue enqueue/dequeue/len")
except Exception as e:
    log_fail("TaskQueue enqueue/dequeue/len", e)

try:
    q_empty = TaskQueue()
    result = q_empty.dequeue()
    assert result is None
    log_pass("TaskQueue dequeue on empty returns None")
except Exception as e:
    log_fail("TaskQueue dequeue on empty returns None", e)

try:
    state = OrchestratorState()
    t = Task(type="web", target="http://test.com")
    assert not state.has_task_run(t)
    state.mark_task_run(t)
    assert state.has_task_run(t)
    log_pass("OrchestratorState duplicate task detection")
except Exception as e:
    log_fail("OrchestratorState duplicate task detection", e)

try:
    planner = Planner(api_key="dummy_key_that_wont_work")
    state = OrchestratorState()
    scope = TargetScope(domains=["http://dvwa.local"], ip_ranges=["192.168.1.0/24"])
    planner.create_plan(scope, state)
    assert len(state.queue) >= 2, f"Expected >=2 tasks from fallback, got {len(state.queue)}"
    log_pass("Planner deterministic fallback (no API)")
except Exception as e:
    log_fail("Planner deterministic fallback (no API)", e)

try:
    before = len(state.queue)
    planner.create_plan(scope, state)
    after = len(state.queue)
    assert after == before, f"Duplicate tasks created: {before} -> {after}"
    log_pass("Planner prevents duplicate tasks on re-plan")
except Exception as e:
    log_fail("Planner prevents duplicate tasks on re-plan", e)

try:
    state2 = OrchestratorState()
    t_net = Task(type="network", target="10.0.0.1")
    t_web = Task(type="web", target="http://a.com")
    t_ad = Task(type="ad", target="dc.local")
    state2.queue.enqueue(t_net)
    state2.queue.enqueue(t_web)
    state2.queue.enqueue(t_ad)
    sched = Scheduler(state2)
    first = sched.next_task()
    assert first.type == "web", f"Expected web first, got {first.type}"
    second = sched.next_task()
    assert second.type == "network", f"Expected network second, got {second.type}"
    third = sched.next_task()
    assert third.type == "ad", f"Expected ad third, got {third.type}"
    log_pass("Scheduler priority ordering (web > network > ad)")
except Exception as e:
    log_fail("Scheduler priority ordering (web > network > ad)", e)

try:
    empty_state = OrchestratorState()
    sched_empty = Scheduler(empty_state)
    assert sched_empty.next_task() is None
    log_pass("Scheduler returns None when queue empty")
except Exception as e:
    log_fail("Scheduler returns None when queue empty", e)


# ================================================================
# PRD 02: SHARED MEMORY
# ================================================================
print("\n" + "="*60)
print("PRD 02: SHARED MEMORY")
print("="*60)

try:
    from src.ml.models import Finding as MemFinding
    from src.ml.memory import EmbeddingModel, ChromaStore, RetrievalEngine
    log_pass("Import memory components")
except Exception as e:
    log_fail("Import memory components", e)

try:
    f = MemFinding(
        task_id="t1", surface="web", title="SQLi", description="desc",
        severity="High", evidence="err", remediation="fix",
        finding_type="credential", credential_material="admin:pass",
        tags=["sqli", "cred"], confidence=0.9, port=80, protocol="http"
    )
    assert f.id is not None
    assert f.credential_material == "admin:pass"
    assert f.tags == ["sqli", "cred"]
    log_pass("Finding schema with all ML fields")
except Exception as e:
    log_fail("Finding schema with all ML fields", e)

try:
    emb = EmbeddingModel(use_offline_hash=True)
    vec = emb.embed("test string")
    assert len(vec) == 256, f"Expected 256 dims, got {len(vec)}"
    vec2 = emb.embed("test string")
    assert vec == vec2, "Hash embedding not deterministic"
    log_pass("EmbeddingModel offline hash (256-dim, deterministic)")
except Exception as e:
    log_fail("EmbeddingModel offline hash (256-dim, deterministic)", e)

try:
    test_db = "/tmp/aria_test_chroma"
    if os.path.exists(test_db):
        shutil.rmtree(test_db)
    store = ChromaStore(persist_dir=test_db)

    f1 = MemFinding(
        task_id="t1", surface="web", title="SQL Injection in login",
        description="Blind SQLi in username param", severity="High",
        evidence="admin' OR 1=1--", remediation="Use parameterized queries",
        finding_type="credential", credential_material="admin:hunter2",
        tags=["sqli"], confidence=0.95
    )
    store.store_finding(f1)

    results = store.retrieve("SQL injection credential", k=1)
    assert len(results["ids"][0]) == 1, "Expected 1 result"
    log_pass("ChromaStore store + retrieve")
except Exception as e:
    log_fail("ChromaStore store + retrieve", e)

try:
    was_dup = store.store_finding(f1)
    assert was_dup == True, f"Expected True for duplicate, got {was_dup}"
    results_dup = store.retrieve("SQL injection", k=10)
    assert len(results_dup["ids"][0]) == 1, "Duplicate was inserted instead of upserted"
    log_pass("ChromaStore duplicate suppression (upsert, no dup rows)")
except Exception as e:
    log_fail("ChromaStore duplicate suppression", e)

try:
    store.delete(f1.id)
    results_after = store.retrieve("SQL injection", k=1)
    assert len(results_after["ids"][0]) == 0, "Finding not deleted"
    log_pass("ChromaStore delete")
except Exception as e:
    log_fail("ChromaStore delete", e)

try:
    f2 = MemFinding(
        task_id="t2", surface="network", title="Open SMB",
        description="Port 445 open", severity="Low",
        evidence="445/tcp open", remediation="Restrict access",
        finding_type="service"
    )
    store.store_finding(f2)
    f2.title = "Open SMB (Updated)"
    f2.description = "Port 445 open with signing disabled"
    store.update(f2)
    log_pass("ChromaStore update")
except Exception as e:
    log_fail("ChromaStore update", e)

try:
    re = RetrievalEngine(store)
    f3 = MemFinding(
        task_id="t3", surface="web", title="Extracted cred",
        description="SQLmap extracted domain cred", severity="High",
        evidence="jsmith:Password123!", remediation="Rotate creds",
        finding_type="credential", credential_material="jsmith:Password123!"
    )
    store.store_finding(f3)
    creds = re.get_credentials(k=1)
    assert len(creds["ids"][0]) >= 1
    log_pass("RetrievalEngine credential lookup")
except Exception as e:
    log_fail("RetrievalEngine credential lookup", e)

try:
    filtered = re.retrieve("open port", k=5, filter_meta={"surface": "network"})
    log_pass("RetrievalEngine metadata filtering")
except Exception as e:
    log_fail("RetrievalEngine metadata filtering", e)

try:
    shutil.rmtree(test_db, ignore_errors=True)
except:
    pass


# ================================================================
# PRD 03: SPECIALIST AGENTS
# ================================================================
print("\n" + "="*60)
print("PRD 03: SPECIALIST AGENTS")
print("="*60)

try:
    from src.ml.agents import BaseAgent, WebAgent, NetworkAgent, ReportingAgent
    log_pass("Import agent components")
except Exception as e:
    log_fail("Import agent components", e)

try:
    agent = BaseAgent("test")
    log_fail("BaseAgent is abstract", "Should not be instantiable")
except TypeError:
    log_pass("BaseAgent is abstract (cannot instantiate)")
except Exception as e:
    log_fail("BaseAgent is abstract", e)

try:
    wa = WebAgent()
    task = Task(type="web", target="http://test.local")
    findings = wa.run(task)
    assert isinstance(findings, list)
    assert len(findings) > 0
    assert findings[0].surface == "web"
    log_pass("WebAgent.run returns Finding list")
except Exception as e:
    log_fail("WebAgent.run returns Finding list", e)

try:
    na = NetworkAgent()
    task_net = Task(type="network", target="10.0.0.1")
    findings_net = na.run(task_net)
    assert isinstance(findings_net, list)
    assert len(findings_net) > 0
    assert findings_net[0].surface in ["network", "ad"]
    log_pass("NetworkAgent.run returns Finding list")
except Exception as e:
    log_fail("NetworkAgent.run returns Finding list", e)

try:
    ra = ReportingAgent()
    from schema import Finding as SchemaFinding
    dup1 = SchemaFinding(task_id="t1", surface="web", title="SQLi", description="d", severity="H", evidence="e1", remediation="r")
    dup2 = SchemaFinding(task_id="t1", surface="web", title="SQLi", description="d", severity="H", evidence="e1", remediation="r")
    dup3 = SchemaFinding(task_id="t2", surface="web", title="XSS", description="d", severity="M", evidence="e2", remediation="r")
    deduped = ra.deduplicate([dup1, dup2, dup3])
    assert len(deduped) == 2, f"Expected 2 unique, got {len(deduped)}"
    log_pass("ReportingAgent.deduplicate")
except Exception as e:
    log_fail("ReportingAgent.deduplicate", e)

try:
    report = ra.generate_report([dup1, dup2, dup3])
    assert "Executive Summary" in report
    assert "SQLi" in report
    assert "XSS" in report
    log_pass("ReportingAgent.generate_report")
except Exception as e:
    log_fail("ReportingAgent.generate_report", e)

try:
    wa2 = WebAgent()
    result = wa2.validate(None)
    assert result == False
    result2 = wa2.validate({"data": "ok"})
    assert result2 == True
    log_pass("Agent.validate graceful handling")
except Exception as e:
    log_fail("Agent.validate graceful handling", e)


# ================================================================
# PRD 04: EVALUATION
# ================================================================
print("\n" + "="*60)
print("PRD 04: EVALUATION")
print("="*60)

try:
    from src.ml.evaluation import MetricsCalculator, Scorer, BenchmarkEnvironment, ExperimentPipeline
    log_pass("Import evaluation components")
except Exception as e:
    log_fail("Import evaluation components", e)

try:
    assert MetricsCalculator.calculate_tcr(8, 10) == 80.0
    assert MetricsCalculator.calculate_tcr(0, 0) == 0.0
    assert MetricsCalculator.calculate_ttc(0, 150.5) == 150.5
    assert MetricsCalculator.calculate_asc(4, 4) == 100.0
    assert MetricsCalculator.calculate_asc(0, 0) == 0.0
    assert MetricsCalculator.calculate_far(2, 50) == 4.0
    assert MetricsCalculator.calculate_far(0, 0) == 0.0
    log_pass("MetricsCalculator all formulas correct")
except Exception as e:
    log_fail("MetricsCalculator all formulas correct", e)

try:
    gt = {"total_nodes": 4}
    scorer = Scorer(gt)
    data = {
        "tasks_completed": 10, "total_tasks": 10,
        "start_time": 0, "compromise_time": 150.5,
        "discovered_nodes": 4, "false_actions": 2, "total_actions": 50
    }
    scores = scorer.score_run(data)
    assert all(k in scores for k in ["TCR", "TTC", "ASC", "FAR", "RQS"])
    log_pass("Scorer produces all 5 metric keys")
except Exception as e:
    log_fail("Scorer produces all 5 metric keys", e)

try:
    bench = BenchmarkEnvironment()
    env = bench.load()
    oracle = bench.get_oracle()
    assert "total_nodes" in oracle
    assert len(env["components"]) == 4
    log_pass("BenchmarkEnvironment load + oracle")
except Exception as e:
    log_fail("BenchmarkEnvironment load + oracle", e)

try:
    pipe = ExperimentPipeline()
    pipe.execute()
    assert os.path.exists("evaluation_metrics.csv"), "CSV not created"
    assert os.path.exists("evaluation_findings.json"), "JSON not created"
    assert os.path.exists("evaluation_summary.md"), "MD not created"
    log_pass("ExperimentPipeline full execute + exports")
    os.remove("evaluation_metrics.csv")
    os.remove("evaluation_findings.json")
    os.remove("evaluation_summary.md")
except Exception as e:
    log_fail("ExperimentPipeline full execute + exports", e)


# ================================================================
# SUMMARY
# ================================================================
print("\n" + "="*60)
print(f"RESULTS: {PASS} passed, {FAIL} failed")
print("="*60)
if ERRORS:
    print("\nFAILURES:")
    for name, err in ERRORS:
        print(f"  ❌ {name}: {err}")
print()
