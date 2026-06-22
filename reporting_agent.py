import os
import argparse
from datetime import datetime
from cvss import CVSS3
from db import collection


def get_severity_label(meta):
    """
    Computes the real CVSS 3.1 base score from the severity vector string
    using the official formula (via the cvss library), instead of guessing
    from keywords. Falls back to UNKNOWN if the vector is missing or invalid.
    """
    severity_str = meta.get("severity", "")
    try:
        c = CVSS3(severity_str)
        score = float(c.base_score)
        label = c.severities()[0].upper()
        return label, score
    except Exception:
        return "UNKNOWN", None


def seed_dummy_data():
    """Only used for testing. Upserts so re-running --seed never crashes."""
    dummy = [
        {
            "id": "F001", "task_id": "T001", "surface": "web",
            "title": "SQL Injection in /login endpoint",
            "description": "The username parameter is not sanitised, allowing SQL injection.",
            "severity": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
            "evidence": "SQLmap extracted 847 rows from the users table.",
            "remediation": "Use parameterised queries.",
        },
        {
            "id": "F002", "task_id": "T002", "surface": "network",
            "title": "SMB Vulnerability on 192.168.10.12",
            "description": "Unpatched SMB service vulnerable to RCE.",
            "severity": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
            "evidence": "Metasploit gained command execution via SMB exploit.",
            "remediation": "Patch SMB. Disable SMBv1.",
        },
        {
            "id": "F003", "task_id": "T003", "surface": "web",
            "title": "Directory Listing Enabled on /backup",
            "description": "The /backup directory is publicly browsable.",
            "severity": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N",
            "evidence": "FFUF discovered /backup/db.sql.",
            "remediation": "Disable directory listing.",
        },
        {
            "id": "F004", "task_id": "T004", "surface": "ad",
            "title": "Weak credentials valid across domain",
            "description": "Credential admin:hunter2 works on 14 domain machines.",
            "severity": "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N",
            "evidence": "CrackMapExec confirmed credential valid on 14 machines.",
            "remediation": "Enforce strong password policy and MFA.",
        },
    ]
    for f in dummy:
        collection.upsert(
            documents=[f["description"]],
            metadatas=[{
                "id": f["id"],
                "task_id": f["task_id"],
                "surface": f["surface"],
                "title": f["title"],
                "severity": f["severity"],
                "evidence": f["evidence"],
                "remediation": f["remediation"],
            }],
            ids=[f["id"]]
        )
    print(f"[*] Seeded {len(dummy)} dummy findings into ChromaDB (upsert, safe to re-run)")


def read_real_findings():
    results = collection.get(include=["documents", "metadatas"])
    metadatas = results.get("metadatas", [])
    documents = results.get("documents", [])

    findings = []
    for meta, doc in zip(metadatas, documents):
        label, score = get_severity_label(meta)
        findings.append({
            "id": meta.get("id", "UNKNOWN"),
            "title": meta.get("title", "Untitled finding"),
            "surface": meta.get("surface", "unknown"),
            "severity_label": label,
            "cvss_score": score,
            "severity_raw": meta.get("severity", ""),
            "evidence": meta.get("evidence", "Not recorded"),
            "remediation": meta.get("remediation", "Not recorded"),
            "description": doc
        })
    return findings


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

    groups = {"CRITICAL": [], "HIGH": [], "MEDIUM": [], "LOW": [], "UNKNOWN": []}
    for f in findings:
        groups[f["severity_label"]].append(f)

    report = f"""# ARIA Penetration Test Report
Generated: {datetime.now().strftime("%Y-%m-%d %H:%M:%S")}

---

## Executive Summary

| Severity | Count |
|----------|-------|
| Critical | {len(groups['CRITICAL'])} |
| High     | {len(groups['HIGH'])} |
| Medium   | {len(groups['MEDIUM'])} |
| Low      | {len(groups['LOW'])} |
| Unknown  | {len(groups['UNKNOWN'])} |
| **Total**| **{len(findings)}** |

---

## Findings by Severity
"""

    for label in ["CRITICAL", "HIGH", "MEDIUM", "LOW", "UNKNOWN"]:
        group = groups[label]
        if group:
            report += f"\n### {label} Findings\n"
            for f in group:
                score_display = f["cvss_score"] if f["cvss_score"] is not None else "N/A"
                report += f"""
#### [{f['id']}] {f['title']}
- **Surface:** {f['surface'].upper()}
- **CVSS Score:** {score_display} ({label})
- **Vector:** {f['severity_raw']}
- **Description:** {f['description']}
- **Evidence:** {f['evidence']}
- **Remediation:** {f['remediation']}
"""

    if not findings:
        report += "\nNo findings were present in ChromaDB at the time this report was generated.\n"

    report += """
---

## Remediation Recommendations

Review each finding above for specific remediation guidance. Patch critical and high
severity issues first, then re-scan to confirm fixes.

---
*Report generated automatically by ARIA Reporting Agent v1*
"""
    return report


def run(use_dummy=False):
    print("[*] Reporting Agent v1 started...")

    if use_dummy:
        seed_dummy_data()

    findings = read_real_findings()
    print(f"[*] Retrieved {len(findings)} findings from ChromaDB")

    report = generate_report(findings)

    script_dir = os.path.dirname(os.path.abspath(__file__))
    output_path = os.path.join(script_dir, "aria_report.md")

    try:
        with open(output_path, "w") as f:
            f.write(report)
        print(f"[*] Report saved to {output_path}")
    except OSError as e:
        print(f"[!] Failed to write report: {e}")

    print("[*] Done!")


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--seed", action="store_true", help="Seed dummy findings before generating report")
    args = parser.parse_args()
    run(use_dummy=args.seed)
