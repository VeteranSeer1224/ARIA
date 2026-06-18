import chromadb
from datetime import datetime
import argparse

DUMMY_FINDINGS = [
    {
        "id": "F001",
        "task_id": "T001",
        "surface": "web",
        "title": "SQL Injection in /login endpoint",
        "description": "The username parameter is not sanitised. An attacker can inject SQL commands to extract all database records or bypass authentication.",
        "cvss_score": 9.8,
        "evidence": "SQLmap successfully extracted 847 rows from the users table including plaintext passwords.",
        "remediation": "Use parameterised queries to separate data from SQL commands.",
        "timestamp": "2026-06-15T10:00:00Z"
    },
    {
        "id": "F002",
        "task_id": "T002",
        "surface": "network",
        "title": "SMB Vulnerability on 192.168.10.12",
        "description": "Host is running an unpatched SMB service vulnerable to remote code execution.",
        "cvss_score": 9.8,
        "evidence": "Metasploit successfully gained command execution on 192.168.10.12 via SMB exploit.",
        "remediation": "Apply latest Windows security patches immediately. Disable SMBv1.",
        "timestamp": "2026-06-15T10:05:00Z"
    },
    {
        "id": "F003",
        "task_id": "T003",
        "surface": "web",
        "title": "Directory Listing Enabled on /backup",
        "description": "The web server exposes a /backup directory with sensitive files publicly accessible.",
        "cvss_score": 5.3,
        "evidence": "FFUF discovered /backup/db.sql containing database dump.",
        "remediation": "Disable directory listing in Apache config. Remove sensitive files from web root.",
        "timestamp": "2026-06-15T10:10:00Z"
    },
    {
        "id": "F004",
        "task_id": "T004",
        "surface": "ad",
        "title": "Weak credentials valid across domain",
        "description": "Credential admin:hunter2 extracted from web database works on 14 machines in the domain.",
        "cvss_score": 8.1,
        "evidence": "CrackMapExec confirmed credential valid on 14 domain machines.",
        "remediation": "Enforce strong password policy. Enable multi-factor authentication.",
        "timestamp": "2026-06-15T10:15:00Z"
    }
]


def get_severity_label(score):
    if score >= 9.0:
        return "CRITICAL"
    elif score >= 7.0:
        return "HIGH"
    elif score >= 4.0:
        return "MEDIUM"
    else:
        return "LOW"


def seed_dummy_data(collection):
    """Only used for testing. Loads fake findings into ChromaDB."""
    for f in DUMMY_FINDINGS:
        collection.add(
            documents=[f["description"]],
            metadatas=[{
                "id": f["id"],
                "title": f["title"],
                "surface": f["surface"],
                "cvss_score": str(f["cvss_score"]),
                "severity_label": get_severity_label(f["cvss_score"]),
                "evidence": f["evidence"],
                "remediation": f["remediation"],
                "timestamp": f["timestamp"]
            }],
            ids=[f["id"]]
        )
    print(f"[*] Seeded {len(DUMMY_FINDINGS)} dummy findings into ChromaDB")


def deduplicate(findings):
    seen = set()
    unique = []
    for f in findings:
        if f["id"] not in seen:
            seen.add(f["id"])
            unique.append(f)
    return unique


def generate_report(findings):
    findings = deduplicate(findings)

    critical = [f for f in findings if get_severity_label(f["cvss_score"]) == "CRITICAL"]
    high     = [f for f in findings if get_severity_label(f["cvss_score"]) == "HIGH"]
    medium   = [f for f in findings if get_severity_label(f["cvss_score"]) == "MEDIUM"]
    low      = [f for f in findings if get_severity_label(f["cvss_score"]) == "LOW"]

    report = f"""# ARIA Penetration Test Report
Generated: {datetime.now().strftime("%Y-%m-%d %H:%M:%S")}

---

## Executive Summary

This report presents the findings of an automated penetration test conducted by ARIA.

| Severity | Count |
|----------|-------|
| Critical | {len(critical)} |
| High     | {len(high)} |
| Medium   | {len(medium)} |
| Low      | {len(low)} |
| **Total**| **{len(findings)}** |

---

## Findings by Severity
"""

    for label, group in [("CRITICAL", critical), ("HIGH", high), ("MEDIUM", medium), ("LOW", low)]:
        if group:
            report += f"\n### {label} Findings\n"
            for f in group:
                report += f"""
#### [{f['id']}] {f['title']}
- **Surface:** {f['surface'].upper()}
- **CVSS Score:** {f['cvss_score']} ({label})
- **Description:** {f['description']}
- **Evidence:** {f['evidence']}
- **Remediation:** {f['remediation']}
- **Timestamp:** {f['timestamp']}
"""

    if not findings:
        report += "\nNo findings were present in ChromaDB at the time this report was generated.\n"

    report += """
---

## Remediation Recommendations

Review each finding above for specific remediation guidance. General priorities:
1. Patch critical and high severity issues first.
2. Re-scan after remediation to confirm fixes.

---
*Report generated automatically by ARIA Reporting Agent v1*
"""
    return report


class ReportingAgent:
    def __init__(self):
        self.client = chromadb.Client()
        self.collection = self.client.get_or_create_collection("aria_findings")

    def read_real_findings(self):
        """Reads whatever findings actually exist in ChromaDB right now."""
        results = self.collection.get(include=["documents", "metadatas"])
        metadatas = results.get("metadatas", [])
        documents = results.get("documents", [])

        findings = []
        for meta, doc in zip(metadatas, documents):
            findings.append({
                "id": meta.get("id", "UNKNOWN"),
                "title": meta.get("title", "Untitled finding"),
                "surface": meta.get("surface", "unknown"),
                "cvss_score": float(meta.get("cvss_score", 0.0)),
                "evidence": meta.get("evidence", ""),
                "remediation": meta.get("remediation", ""),
                "timestamp": meta.get("timestamp", ""),
                "description": doc
            })
        return findings

    def run(self, use_dummy=False):
        print("[*] Reporting Agent v1 started...")

        if use_dummy:
            seed_dummy_data(self.collection)

        findings = self.read_real_findings()
        print(f"[*] Retrieved {len(findings)} real findings from ChromaDB")

        report = generate_report(findings)

        with open("aria_report.md", "w") as f:
            f.write(report)

        print("[*] Report saved to aria_report.md")
        print("[*] Done!")


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--seed", action="store_true", help="Seed dummy findings before generating report")
    args = parser.parse_args()

    agent = ReportingAgent()
    agent.run(use_dummy=args.seed)
