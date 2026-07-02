"""
PRD 01 — Orchestrator: planning, scheduling, routing, and state management.
The Orchestrator reasons, delegates, and coordinates. It never executes offensive tools.
"""

import json
import os
import sys
from datetime import datetime
from typing import List

from openai import OpenAI

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '../..')))
from schema import Task, Finding

from .models import TargetScope, TaskQueue


# ── State ────────────────────────────────────────────────────────

class OrchestratorState:
    """Tracks the task queue, completed/failed tasks, findings, and history."""
    def __init__(self):
        self.queue = TaskQueue()
        self.completed_tasks: List[Task] = []
        self.failed_tasks: List[Task] = []
        self.findings: List[Finding] = []
        self.task_history = set()

    def add_finding(self, finding: Finding):
        self.findings.append(finding)

    def has_task_run(self, task: Task) -> bool:
        """Prevent duplicate work and loops."""
        task_sig = f"{task.type}:{task.target}"
        return task_sig in self.task_history

    def mark_task_run(self, task: Task):
        task_sig = f"{task.type}:{task.target}"
        self.task_history.add(task_sig)


# ── Planner ──────────────────────────────────────────────────────

class Planner:
    """Parses target scope, builds attack plans, and triggers replanning."""
    def __init__(self, api_key: str = None):
        self.client = OpenAI(
            api_key=api_key or os.getenv("DEEPSEEK_API_KEY", "dummy"),
            base_url="https://api.deepseek.com"
        )
        self.model = "deepseek-chat"

    def create_plan(self, scope: TargetScope, state: OrchestratorState):
        """Build attack plan and decompose into tasks."""
        print(f"[Planner] Creating plan for scope with domains: {scope.domains}, IPs: {scope.ip_ranges}")

        system_prompt = (
            "You are the Orchestrator Planner for ARIA, an automated penetration testing pipeline. "
            "Given a target scope, output a JSON object with a single key named 'tasks'. "
            "The value of 'tasks' must be an array of task objects to be routed to specialist agents. "
            "Each task must strictly follow this JSON schema: "
            "{ 'type': 'web' | 'network' | 'ad', "
            "'target': 'string representing IP or URL' }. "
            "Return ONLY the JSON object."
        )

        try:
            response = self.client.chat.completions.create(
                model=self.model,
                messages=[
                    {"role": "system", "content": system_prompt},
                    {"role": "user", "content": f"Scope domains: {scope.domains}, IPs: {scope.ip_ranges}, Exclusions: {scope.exclusions}"}
                ],
                response_format={"type": "json_object"}
            )
            content = response.choices[0].message.content
            payload = json.loads(content)

            for rt in payload.get("tasks", []):
                task = Task(type=rt["type"], target=rt["target"])
                if not state.has_task_run(task):
                    state.queue.enqueue(task)
                    state.mark_task_run(task)

        except Exception as e:
            print(f"[Planner] Error during planning with LLM: {e}. Falling back to deterministic planning.")
            for domain in scope.domains:
                if domain not in scope.exclusions:
                    task = Task(type="web", target=domain)
                    if not state.has_task_run(task):
                        state.queue.enqueue(task)
                        state.mark_task_run(task)
            for ip in scope.ip_ranges:
                if ip not in scope.exclusions:
                    task = Task(type="network", target=ip)
                    if not state.has_task_run(task):
                        state.queue.enqueue(task)
                        state.mark_task_run(task)

    def update_plan(self, findings: list[Finding], state: OrchestratorState):
        """Trigger replanning based on new findings to prevent loops and duplicate work."""
        print(f"[Planner] Updating plan with {len(findings)} new findings.")
        for finding in findings:
            if "port 80" in finding.description.lower() or "web" in finding.description.lower():
                new_task = Task(type="web", target=finding.evidence)
                if not state.has_task_run(new_task):
                    print(f"[Planner] Discovered new web task from finding: {new_task.target}")
                    state.queue.enqueue(new_task)
                    state.mark_task_run(new_task)


# ── Scheduler ────────────────────────────────────────────────────

class Scheduler:
    """Dependency-aware task scheduling with surface-based priority."""
    def __init__(self, state: OrchestratorState):
        self.state = state

    def next_task(self, memory=None) -> Task:
        """Returns the next task, prioritized: web → network → ad."""
        if len(self.state.queue) == 0:
            return None

        priority_map = {"web": 1, "network": 2, "ad": 3}
        self.state.queue.tasks.sort(key=lambda t: priority_map.get(t.type, 99))

        return self.state.queue.dequeue()


# ── Router ───────────────────────────────────────────────────────

class Router:
    """Routes tasks to specialist agents."""
    def route(self, task: Task):
        """Route a task to the correct agent and return findings."""
        print(f"[Router] Routing task {task.id} of type {task.type} to {task.target}")
        task.status = "in_progress"

        try:
            if task.type == "web":
                from agents.web_agent import run_web_agent
                task.assigned_agent = "Web Agent (P2)"
                findings = run_web_agent(task)
                task.status = "completed"
                task.completed_at = datetime.utcnow()
                return findings
            elif task.type == "network":
                from stubs import mock_network_agent
                task.assigned_agent = "Network/AD Agent (P3)"
                findings = mock_network_agent(task, found_creds=[])
                task.status = "completed"
                task.completed_at = datetime.utcnow()
                return findings
            elif task.type == "ad":
                from stubs import mock_ad_agent
                task.assigned_agent = "Network/AD Agent (P3)"
                findings = mock_ad_agent(task)
                task.status = "completed"
                task.completed_at = datetime.utcnow()
                return findings
            else:
                print(f"[Router] Unknown task type: {task.type}")
                task.status = "failed"
                return []
        except Exception as e:
            print(f"[Router] Agent execution failed for Task {task.id}: {e}")
            task.status = "failed"
            return []
