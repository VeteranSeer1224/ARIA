import json
import os
from openai import OpenAI
from pydantic import ValidationError
from typing import List

# Import our shared contract and stubs
from schema import Task
from stubs import mock_web_agent, mock_network_agent
from db import get_task_context

class AriaOrchestrator:
    def __init__(self, api_key: str = None):
        """Initialize the Orchestrator with DeepSeek API credentials."""
        # Standard OpenAI client configured for DeepSeek
        self.client = OpenAI(
            api_key=api_key or os.getenv("DEEPSEEK_API_KEY"),
            base_url="https://api.deepseek.com"
        )
        self.model = "deepseek-chat" # DeepSeek-V3 equivalent endpoint

    def plan_attack(self, target_scope: str) -> List[Task]:
        """Uses DeepSeek API to construct a high-level attack plan and decompose into Tasks."""
        print(f"[Orchestrator] Analyzing scope: {target_scope}")
        
        system_prompt = (
            "You are the Orchestrator for ARIA, an automated penetration testing pipeline. "
            "Your job is to reason, delegate, and synthesize. You do NOT execute tools. "
            "Given a target scope, output a JSON array of tasks to be routed to specialist agents. "
            "Each task must strictly follow this JSON schema: "
            "{ 'type': 'web' | 'network' | 'ad', 'target': 'string representing IP or URL' }. "
            "Return ONLY the JSON array."
        )

        try:
            response = self.client.chat.completions.create(
                model=self.model,
                messages=[
                    {"role": "system", "content": system_prompt},
                    {"role": "user", "content": f"Scope: {target_scope}"}
                ],
                response_format={"type": "json_object"} # Enforce JSON output
            )
            
            # Parse the LLM output
            content = response.choices[0].message.content
            # Handle potential JSON wrapping differences from the model
            if "{" in content and "tasks" not in content.lower():
                 raw_tasks = json.loads(content)
                 if isinstance(raw_tasks, dict): # Handle edge case where it returns a dict instead of array
                     raw_tasks = list(raw_tasks.values())[0] 
            else:
                 raw_tasks = json.loads(content).get("tasks", [])

            # Validate against our shared Pydantic contract
            tasks = []
            for rt in raw_tasks:
                task = Task(type=rt['type'], target=rt['target'])
                tasks.append(task)
            
            print(f"[Orchestrator] Generated {len(tasks)} tasks.")
            return tasks

        except Exception as e:
            print(f"[Orchestrator] Error during planning: {e}")
            return []

    def route_and_execute(self, tasks: List[Task]):
        """Routes Task objects to the correct agent."""
        for task in tasks:
            task.status = "in_progress"
            print(f"\n[Orchestrator] Routing Task {task.id} ({task.type}) -> {task.target}")
            
            try:
                # Route based on task type to our mock stubs
                if task.type == "web":
                    task.assigned_agent = "Web Agent (P2)"
                    finding_ids = mock_web_agent(task)
                elif task.type in ["network", "ad"]:
                    task.assigned_agent = "Network/AD Agent (P3)"
                    finding_ids = mock_network_agent(task)
                else:
                    print(f"[Orchestrator] Unknown task type: {task.type}")
                    task.status = "failed"
                    continue
                
                print(f"[Orchestrator] Task {task.id} completed. Generated {len(finding_ids)} findings.")
                
            except Exception as e:
                print(f"[Orchestrator] Agent execution failed for Task {task.id}: {e}")
                task.status = "failed"

if __name__ == "__main__":
    # Test execution using a dummy scope
    orchestrator = AriaOrchestrator(api_key="your_test_key_here")
    
    # 1. Provide scope definition
    test_scope = "192.168.1.0/24 internal network and http://dvwa.local"
    
    # 2. Decompose into typed Task objects
    planned_tasks = orchestrator.plan_attack(test_scope)
    
    # 3. Route to mock agents
    if planned_tasks:
        orchestrator.route_and_execute(planned_tasks)