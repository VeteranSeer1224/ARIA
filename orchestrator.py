import json
import os
from datetime import datetime
from typing import List

from openai import OpenAI

from schema import Task

# Real Web Agent (P2)
from agents.web_agent import run_web_agent

# Network stub (P3)
from stubs import mock_network_agent

from db import get_task_context, query_credentials


class AriaOrchestrator:

    def __init__(self, api_key: str = None):
        """Initialize the Orchestrator with DeepSeek API credentials."""

        self.client = OpenAI(
            api_key=api_key or os.getenv("DEEPSEEK_API_KEY"),
            base_url="https://api.deepseek.com"
        )

        self.model = "deepseek-chat"

    def plan_attack(self, target_scope: str) -> List[Task]:
        """
        Uses DeepSeek API to construct a high-level attack plan
        and decompose into Tasks.
        """

        print(f"[Orchestrator] Analyzing scope: {target_scope}")

        system_prompt = (
            "You are the Orchestrator for ARIA, an automated "
            "penetration testing pipeline. "
            "Your job is to reason, delegate, and synthesize. "
            "You do NOT execute tools. "
            "Given a target scope, output a JSON array of tasks "
            "to be routed to specialist agents. "
            "Each task must strictly follow this JSON schema: "
            "{ 'type': 'web' | 'network' | 'ad', "
            "'target': 'string representing IP or URL' }. "
            "Return ONLY the JSON array."
        )

        try:
            response = self.client.chat.completions.create(
                model=self.model,
                messages=[
                    {
                        "role": "system",
                        "content": system_prompt
                    },
                    {
                        "role": "user",
                        "content": f"Scope: {target_scope}"
                    }
                ],
                response_format={"type": "json_object"}
            )

            content = response.choices[0].message.content

            parsed = json.loads(content)
            if isinstance(parsed, list):
                raw_tasks = parsed
            elif isinstance(parsed, dict):
                # Try a 'tasks' key first, then fall back to the first list value
                if "tasks" in parsed and isinstance(parsed["tasks"], list):
                    raw_tasks = parsed["tasks"]
                else:
                    raw_tasks = next(
                        (v for v in parsed.values() if isinstance(v, list)), []
                    )
            else:
                raw_tasks = []

            tasks = []
            for rt in raw_tasks:
                task = Task(
                    type=rt["type"],
                    target=rt["target"]
                )
                tasks.append(task)

            print(f"[Orchestrator] Generated {len(tasks)} tasks.")
            return tasks

        except Exception as e:
            print(f"[Orchestrator] Error during planning: {e}")
            return []

    def route_and_execute(self, tasks: List[Task]):
        """
        Routes Task objects to the correct agent in distinct phases
        to enable cross-surface credential handoff.
        """

        web_tasks = [t for t in tasks if t.type == "web"]
        network_tasks = [t for t in tasks if t.type in ["network", "ad"]]

        for task in tasks:
            if task.type not in ("web", "network", "ad"):
                print(f"[Orchestrator] Unknown task type '{task.type}' for Task {task.id} — skipping.")
                task.status = "failed"

        print("\n[Orchestrator] === PHASE 1: WEB RECON & EXPLOITATION ===")
        for task in web_tasks:
            task.status = "in_progress"
            print(f"\n[Orchestrator] Routing Task {task.id} ({task.type}) -> {task.target}")
            try:
                task.assigned_agent = "Web Agent (P2)"
                findings = run_web_agent(task)
                task.status = "completed"
                task.completed_at = datetime.utcnow()
                print(f"[Orchestrator] Task {task.id} completed. Generated {len(findings)} findings.")
            except Exception as e:
                print(f"[Orchestrator] Agent execution failed for Task {task.id}: {e}")
                task.status = "failed"

                if task.type == "web":

                    task.assigned_agent = "Web Agent (P2)"

                    findings = run_web_agent(task)

                    task.status = "completed"
                    task.completed_at = datetime.utcnow()

                    print(
                        f"[Orchestrator] Task {task.id} "
                        f"completed. Generated "
                        f"{len(findings)} findings."
                    )

                elif task.type in ["network", "ad"]:

                    task.assigned_agent = "Network/AD Agent (P3)"

                    finding_ids = mock_network_agent(task)

                    task.status = "completed"
                    task.completed_at = datetime.utcnow()

                    print(
                        f"[Orchestrator] Task {task.id} "
                        f"completed. Generated "
                        f"{len(finding_ids)} findings."
                    )

                else:

        print("\n[Orchestrator] === PHASE 3: NETWORK & AD EXPLOITATION ===")
        for task in network_tasks:
            task.status = "in_progress"
            print(f"\n[Orchestrator] Routing Task {task.id} ({task.type}) -> {task.target}")

            if found_creds:
                print(f"[Orchestrator] Injecting {len(found_creds)} credential(s) into Network Agent.")

            try:
                task.assigned_agent = "Network/AD Agent (P3)"
                finding_ids = mock_network_agent(task, found_creds=found_creds)
                task.status = "completed"
                task.completed_at = datetime.utcnow()
                print(f"[Orchestrator] Task {task.id} completed. Generated {len(finding_ids)} findings.")
            except Exception as e:
                print(f"[Orchestrator] Agent execution failed for Task {task.id}: {e}")
                task.status = "failed"


if __name__ == "__main__":

    # Uses the DEEPSEEK_API_KEY environment variable.
    # TARGET_URL defaults to the victim service hostname set in docker-compose.yml.
    orchestrator = AriaOrchestrator()

    target_url = os.getenv("TARGET_URL", "http://victim")
    test_scope = f"web application at {target_url}"

    planned_tasks = orchestrator.plan_attack(test_scope)

    if planned_tasks:
        orchestrator.route_and_execute(planned_tasks)
