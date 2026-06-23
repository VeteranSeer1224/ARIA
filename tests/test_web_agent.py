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
from agents.web_agent import run_web_agent

task = Task(
    type="web",
    target="http://localhost"
)

findings = run_web_agent(task)

print("\nReturned Findings:")
print(len(findings))