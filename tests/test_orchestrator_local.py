import sys
import os

sys.path.append(
    os.path.dirname(
        os.path.dirname(
            os.path.abspath(__file__)
        )
    )
)

from orchestrator import AriaOrchestrator
from schema import Task

# Create orchestrator
orch = AriaOrchestrator(api_key="dummy")

# Create a web task manually
tasks = [
    Task(
        type="web",
        target="http://localhost"
    )
]

# Execute task
orch.route_and_execute(tasks)