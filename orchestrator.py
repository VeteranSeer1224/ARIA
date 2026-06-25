import json
import os
from datetime import datetime
from openai import OpenAI
from typing import List

from schema import Task

# REAL WEB AGENT
from agents.web_agent import run_web_agent

# KEEP NETWORK STUB FOR P3
from stubs import mock_network_agent

from db import get_task_context


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

            if "{" in content and "tasks" not in content.lower():

                raw_tasks = json.loads(content)

                if isinstance(raw_tasks, dict):
                    raw_tasks = list(raw_tasks.values())[0]

            else:

                raw_tasks = json.loads(
                    content
                ).get("tasks", [])

            tasks = []

            for rt in raw_tasks:

                task = Task(
                    type=rt["type"],
                    target=rt["target"]
                )

                tasks.append(task)

            print(
                f"[Orchestrator] Generated "
                f"{len(tasks)} tasks."
            )

            return tasks

        except Exception as e:

            print(
                f"[Orchestrator] Error during planning: {e}"
            )

            return []

    def route_and_execute(self, tasks: List[Task]):
        """
        Routes Task objects to the correct agent.
        """

        for task in tasks:

            task.status = "in_progress"

            print(
                f"\n[Orchestrator] Routing Task "
                f"{task.id} ({task.type}) -> {task.target}"
            )

            try:

                if task.type == "web":

                    task.assigned_agent = "Web Agent (P2)"

                    findings = run_web_agent(task)

<<<<<<< HEAD
<<<<<<< HEAD
=======
                    task.status = "completed"
                    task.completed_at = datetime.utcnow()

>>>>>>> origin/main
=======
>>>>>>> d7b09bd77237d9a109218e5d7207740fe0fca8f5
                    print(
                        f"[Orchestrator] Task {task.id} "
                        f"completed. Generated "
                        f"{len(findings)} findings."
                    )

                elif task.type in ["network", "ad"]:

                    task.assigned_agent = "Network/AD Agent (P3)"

                    finding_ids = mock_network_agent(task)

<<<<<<< HEAD
<<<<<<< HEAD
=======
                    task.status = "completed"
                    task.completed_at = datetime.utcnow()

>>>>>>> origin/main
=======
>>>>>>> d7b09bd77237d9a109218e5d7207740fe0fca8f5
                    print(
                        f"[Orchestrator] Task {task.id} "
                        f"completed. Generated "
                        f"{len(finding_ids)} findings."
                    )

                else:

                    print(
                        f"[Orchestrator] Unknown task type: "
                        f"{task.type}"
                    )

                    task.status = "failed"

            except Exception as e:

                print(
                    f"[Orchestrator] Agent execution failed "
                    f"for Task {task.id}: {e}"
                )

                task.status = "failed"


if __name__ == "__main__":

    orchestrator = AriaOrchestrator(
        api_key="your_test_key_here"
    )

    test_scope = (
        "192.168.1.0/24 internal network "
        "and http://dvwa.local"
    )

    planned_tasks = orchestrator.plan_attack(
        test_scope
    )

    if planned_tasks:
        orchestrator.route_and_execute(
            planned_tasks
        )
