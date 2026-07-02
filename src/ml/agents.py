"""
PRD 03 — Specialist Agents: autonomous agents that receive tasks,
execute tool wrappers, and return standardized findings.
"""

import abc
import logging
import time
import sys
import os
from typing import List, Any
from datetime import datetime

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '../..')))
from schema import Task, Finding

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

class WebAgent(BaseAgent):
    """Handles web recon and exploitation (FFUF, Nikto, SQLMap)."""
    def __init__(self):
        super().__init__("WebAgent")

    def run(self, task: Task) -> list[Finding]:
        self.logger.info(f"Running WebAgent on {task.target}")
        findings = []
        try:
            time.sleep(1)
            raw_result = {"status": "success", "vuln": "SQL Injection"}

            if self.validate(raw_result):
                finding = Finding(
                    task_id=task.id,
                    surface="web",
                    title="SQL Injection found",
                    description="SQL injection payload triggered a database error.",
                    severity="High",
                    evidence="Error: syntax near ''",
                    remediation="Use parameterized queries.",
                    source_tool="SQLMap"
                )
                findings.append(self.publish(finding))
        except Exception as e:
            self.logger.error(f"Execution failed: {e}")

        return findings


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
        self.logger.info(f"Running NetworkAgent on {task.target}")
        findings = []
        try:
            time.sleep(1)
            raw_result = {"status": "success", "open_ports": [445, 3389]}

            if self.validate(raw_result):
                finding = Finding(
                    task_id=task.id,
                    surface=task.type if task.type in ["network", "ad"] else "network",
                    title="Open SMB Port",
                    description="Port 445 is open and accessible.",
                    severity="Low",
                    evidence="Port 445/tcp open",
                    remediation="Restrict access to trusted IP ranges.",
                    source_tool="Nmap"
                )
                findings.append(self.publish(finding))
        except Exception as e:
            self.logger.error(f"Execution failed: {e}")

        return findings


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
        pass

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
