import sys
import os

sys.path.append(
    os.path.dirname(
        os.path.dirname(
            os.path.abspath(__file__)
        )
    )
)

from schema import Task
from agents.web_agent_demo import run_web_agent_demo

task = Task(
    type="web",
    target="http://demo-target"
)

findings = run_web_agent_demo(task)

print("\nReturned Findings:")
print(len(findings))