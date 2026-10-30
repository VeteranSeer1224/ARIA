"""
PRD 03 — Specialist Agents: autonomous agents that receive tasks,
execute tool wrappers, and return standardized findings.
"""

import abc
import logging
from typing import List, Any
from datetime import datetime
import traceback

from schema import Task
from .models import Finding

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')


# ── Base Agent ───────────────────────────────────────────────────

class BaseAgent(abc.ABC):
    """Abstract base for all specialist agents."""
    def __init__(self, name: str):
        self.name = name
        self.logger = logging.getLogger(self.name)

    @abc.abstractmethod
    def run(self, task: Task) -> List[Finding]:
        """Execute the agent's logic for a given task."""
        pass

    def validate(self, result: Any) -> bool:
        """Validate the output of a tool wrapper."""
        if not result:
            self.logger.warning("Empty result received.")
            return False
        return True

    def publish(self, finding: Finding) -> Finding:
        """Standardize and publish a finding."""
        self.logger.info(f"[{self.name}] Publishing Finding: {finding.title} (Severity: {finding.severity})")
        return finding


# ── Web Agent ────────────────────────────────────────────────────

def _to_ml_finding(finding, task: Task) -> Finding:
    """Map a core schema.Finding (from the P2 tool pipeline) onto the ML Finding."""
    return Finding(
        task_id=finding.task_id,
        surface=finding.surface,
        title=finding.title,
        description=finding.description,
        severity=finding.severity,
        evidence=finding.evidence,
        remediation=finding.remediation,
        asset=task.target,
    )


class WebAgent(BaseAgent):
    """Handles web recon and exploitation (FFUF, Nikto, SQLMap)."""
    def __init__(self):
        super().__init__("WebAgent")

    def run(self, task: Task) -> list[Finding]:
        """Run the real web tool pipeline and return findings parsed from it.

        Delegates to the P2 web agent so results come from actual tool output
        rather than a fabricated placeholder. Tool failures propagate (the P2
        agent raises) so a failed run is never reported as an empty success.
        """
        self.logger.info(f"Running WebAgent on {task.target}")
        from agents.web_agent import run_web_agent as run_web_tools
        raw_findings = run_web_tools(task)
        return [self.publish(_to_ml_finding(f, task)) for f in raw_findings]


def run_web_agent(task: Task) -> list[Finding]:
    """Convenience function for the WebAgent."""
    agent = WebAgent()
    return agent.run(task)


# ── Network / AD Agent ───────────────────────────────────────────

class NetworkAgent(BaseAgent):
    """Handles network/AD tasks (Nmap, Metasploit, CrackMapExec, BloodHound)."""
    def __init__(self):
        super().__init__("NetworkAgent")

    def run(self, task: Task) -> list[Finding]:
        raise NotImplementedError(
            "Real network/AD execution is not yet integrated (P3). This agent "
            "must not fabricate findings; wire the Nmap/CrackMapExec/BloodHound "
            "tooling here before using it in a benchmark run."
        )


def run_network_agent(task: Task) -> list[Finding]:
    """Convenience function for the NetworkAgent."""
    agent = NetworkAgent()
    return agent.run(task)


# ── Reporting Agent ──────────────────────────────────────────────

class ReportingAgent(BaseAgent):
    """CVSS scoring, deduplication, executive summary, and technical report."""
    def __init__(self):
        super().__init__("ReportingAgent")

    def run(self, task: Task) -> list[Finding]:
        raise NotImplementedError(
            "ReportingAgent builds a report from collected findings via "
            "generate_report(findings); it has no per-task execution step."
        )

    def deduplicate(self, findings: List[Finding]) -> List[Finding]:
        """Remove duplicate findings by title+evidence signature."""
        seen = set()
        unique = []
        for f in findings:
            sig = f"{f.title}:{f.evidence}"
            if sig not in seen:
                seen.add(sig)
                unique.append(f)
        return unique

    def generate_report(self, findings: List[Finding]) -> str:
        """Generate a Markdown penetration testing report."""
        unique_findings = self.deduplicate(findings)
        report = f"# Executive Summary\n\nARIA found {len(unique_findings)} unique issues.\n\n"
        report += "## Technical Details\n\n"
        for f in unique_findings:
            report += f"### {f.title}\n"
            report += f"- **Severity**: {f.severity}\n"
            report += f"- **Surface**: {f.surface}\n"
            report += f"- **Evidence**: {f.evidence}\n"
            report += f"- **Remediation**: {f.remediation}\n\n"
        return report
